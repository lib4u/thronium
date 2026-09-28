//go:build linux

package tunsession

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"ThroneCore/gen"
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

type journal struct {
	DNSMode       string `json:",omitempty"`
	DNSIndex      int32  `json:",omitempty"`
	DNSToken      string `json:",omitempty"`
	Bridge        bool
	Forwarding    map[string]string
	Redirect      bool
	FirewallToken string
	Version       int
	Table         int
	IPv4CIDR      string
	IPv6CIDR      string
	IPv6          bool
	Strict        bool
	WorkerPID     int
	WorkerStart   uint64
}
type owner struct {
	path   string
	lease  net.Listener
	active *journal
}

func newOwner() (*owner, error) {
	lease, err := net.Listen("unix", "\x00thronium-tun-18900")
	if err != nil {
		return nil, fmt.Errorf("tun_conflict")
	}
	fail := func(err error) (*owner, error) { lease.Close(); return nil, err }
	const directory = "/run/thronium-tun"
	if err = os.Mkdir(directory, 0700); err != nil && !os.IsExist(err) {
		return fail(err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return fail(err)
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
		return fail(fmt.Errorf("tun_journal_untrusted"))
	}
	var ns unix.Stat_t
	if err = unix.Stat("/proc/self/ns/net", &ns); err != nil {
		return fail(err)
	}
	o := &owner{path: filepath.Join(directory, fmt.Sprintf("net-%d.json", ns.Ino)), lease: lease}
	fd, err := unix.Open(o.path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return o, nil
	}
	if err != nil {
		return fail(err)
	}
	f := os.NewFile(uintptr(fd), o.path)
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return fail(err)
	}
	if !info.Mode().IsRegular() || info.Size() > 65536 || info.Mode().Perm()&0077 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
		return fail(fmt.Errorf("tun_journal_untrusted"))
	}
	var j journal
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&j) != nil || j.Version != 1 || j.Table < 100000 || j.Table > 2000000000 || j.IPv4CIDR != "" && !validInterfaceCIDR(j.IPv4CIDR, false) || j.IPv6CIDR != "" && !validInterfaceCIDR(j.IPv6CIDR, true) {
		return fail(fmt.Errorf("tun_journal_untrusted"))
	}
	if j.Redirect || j.Bridge {
		if len(j.FirewallToken) != 32 {
			return fail(fmt.Errorf("tun_journal_untrusted"))
		}
		for _, c := range j.FirewallToken {
			if !strings.ContainsRune("0123456789abcdef", c) {
				return fail(fmt.Errorf("tun_journal_untrusted"))
			}
		}
	}
	if !j.validDNS() || !validForwarding(j.Forwarding) {
		return fail(fmt.Errorf("tun_journal_untrusted"))
	}
	o.active = &j
	if err = j.reap(); err != nil {
		return fail(err)
	}
	if err = o.cleanup(); err != nil {
		return fail(err)
	}
	return o, nil
}

// A pidfd pins the process before checking its recorded start time, so PID
// reuse cannot cause recovery to signal an unrelated process.
func processStart(pid int) (uint64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	end := strings.LastIndexByte(string(b), ')')
	if end < 0 {
		return 0, fmt.Errorf("invalid process stat")
	}
	fields := strings.Fields(string(b[end+1:]))
	if len(fields) < 20 {
		return 0, fmt.Errorf("invalid process stat")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

func (j *journal) reap() error {
	if j.WorkerPID == 0 && j.WorkerStart == 0 {
		return nil
	}
	if j.WorkerPID <= 1 || j.WorkerStart == 0 {
		return fmt.Errorf("tun_journal_untrusted")
	}
	fd, err := unix.PidfdOpen(j.WorkerPID, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	start, err := processStart(j.WorkerPID)
	if os.IsNotExist(err) || err == nil && start != j.WorkerStart {
		return nil
	}
	if err != nil {
		return err
	}
	var own, child unix.Stat_t
	if err = unix.Stat("/proc/self/ns/net", &own); err != nil {
		return err
	}
	if err = unix.Stat(fmt.Sprintf("/proc/%d/ns/net", j.WorkerPID), &child); os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if own.Ino != child.Ino {
		return fmt.Errorf("tun_journal_untrusted")
	}
	if err = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		return err
	}
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	if n, err := unix.Poll(poll, 2000); err != nil {
		return err
	} else if n == 0 {
		return fmt.Errorf("tun_cleanup_pending")
	}
	return nil
}

func (o *owner) write(j *journal) error {
	f, err := os.CreateTemp(filepath.Dir(o.path), ".pending-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = json.NewEncoder(f).Encode(j); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), o.path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(o.path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (o *owner) prepare(payload []byte) ([]byte, error) {
	if o.active != nil {
		return nil, fmt.Errorf("tun_session_active")
	}
	var request gen.LoadConfigReq
	if proto.Unmarshal(payload, &request) != nil || request.GetNeedExtraProcess() {
		return nil, fmt.Errorf("tun_incompatible")
	}
	// Xray sockets are bound to the monitored physical interface by xrayPreparer.
	// Only sing-box may own a TUN: the journal cannot recover a second interface.
	xrayConfigs := append([]string{}, request.GetXrayFullConfigs()...)
	if request.GetNeedXray() {
		xrayConfigs = append(xrayConfigs, request.GetXrayConfig())
	}
	for _, text := range xrayConfigs {
		var config struct {
			Inbounds []struct {
				Protocol string `json:"protocol"`
			} `json:"inbounds"`
		}
		if json.Unmarshal([]byte(text), &config) != nil {
			return nil, fmt.Errorf("tun_incompatible")
		}
		for _, inbound := range config.Inbounds {
			if inbound.Protocol == "tun" {
				return nil, fmt.Errorf("tun_incompatible")
			}
		}
	}
	var config map[string]json.RawMessage
	if json.Unmarshal([]byte(request.GetCoreConfig()), &config) != nil {
		return nil, fmt.Errorf("invalid_configuration")
	}
	if !validDNSRequest(request.GetManagedTunDnsMode(), config) {
		return nil, fmt.Errorf("invalid_tun_system_dns")
	}
	var inbounds []map[string]json.RawMessage
	if json.Unmarshal(config["inbounds"], &inbounds) != nil {
		return nil, fmt.Errorf("tun_incompatible")
	}
	var target map[string]json.RawMessage
	for _, inbound := range inbounds {
		var kind string
		_ = json.Unmarshal(inbound["type"], &kind)
		if kind == "tun" {
			if target != nil {
				return nil, fmt.Errorf("tun_incompatible")
			}
			target = inbound
		}
	}
	if target == nil {
		return nil, fmt.Errorf("tun_incompatible")
	}
	allowed := map[string]bool{"type": true, "tag": true, "interface_name": true, "address": true, "mtu": true, "stack": true, "auto_route": true, "auto_redirect": true, "iproute2_rule_index": true, "dns_mode": true, "strict_route": true, "route_exclude_address": true}
	for key := range target {
		if !allowed[key] {
			return nil, fmt.Errorf("tun_incompatible")
		}
	}
	var name, tag, dns string
	var auto, redirect, strict bool
	var priority int
	var addresses []string
	_ = json.Unmarshal(target["interface_name"], &name)
	_ = json.Unmarshal(target["tag"], &tag)
	_ = json.Unmarshal(target["dns_mode"], &dns)
	_ = json.Unmarshal(target["auto_route"], &auto)
	_ = json.Unmarshal(target["auto_redirect"], &redirect)
	_ = json.Unmarshal(target["strict_route"], &strict)
	_ = json.Unmarshal(target["iproute2_rule_index"], &priority)
	_ = json.Unmarshal(target["address"], &addresses)
	if name != Interface || tag != Interface || dns != "disabled" || !auto || priority != Priority || len(addresses) < 1 || len(addresses) > 2 || !validInterfaceCIDR(addresses[0], false) || len(addresses) == 2 && !validInterfaceCIDR(addresses[1], true) {
		return nil, fmt.Errorf("tun_incompatible")
	}
	if _, err := netlink.LinkByName(Interface); err == nil {
		return nil, fmt.Errorf("tun_conflict")
	}
	// Repeat the address check in the supervisor: automatic retries can occur
	// after the GUI's preflight and after another program has changed the network.
	assigned, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	for _, text := range addresses {
		_, owned, err := net.ParseCIDR(text)
		if err != nil {
			return nil, fmt.Errorf("tun_incompatible")
		}
		for _, address := range assigned {
			if address.IPNet != nil && (owned.Contains(address.IP) || address.Contains(owned.IP)) {
				return nil, fmt.Errorf("tun_conflict")
			}
		}
	}
	rules, err := routingRules()
	if err != nil {
		return nil, err
	}
	for _, rule := range rules {
		s, err := ruleSignature(rule)
		if err != nil {
			return nil, err
		}
		if s.Priority >= Priority && s.Priority <= Priority+10 || redirect && s.Priority == fallbackPriority {
			return nil, fmt.Errorf("tun_conflict")
		}
	}
	var seed [4]byte
	if _, err = rand.Read(seed[:]); err != nil {
		return nil, err
	}
	table := 100000 + int(binary.LittleEndian.Uint32(seed[:])%1900000000)
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err != nil || len(routes) > 0 {
		return nil, fmt.Errorf("tun_conflict")
	}
	if redirect {
		existing, err := firewallState()
		if err != nil {
			return nil, err
		}
		if existing != nil {
			return nil, fmt.Errorf("tun_conflict")
		}
	}
	if redirect {
		extra, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: table + 3}, netlink.RT_FILTER_TABLE)
		if err != nil || len(extra) > 0 {
			return nil, fmt.Errorf("tun_conflict")
		}
		for _, body := range rules {
			sig, err := ruleSignature(body)
			if err != nil {
				return nil, err
			}
			if sig.Table == uint32(table) || sig.Table == uint32(table+3) || sig.Attrs[10] == integer(uint32(table)) || sig.Attrs[10] == integer(uint32(table+1)) {
				return nil, fmt.Errorf("tun_conflict")
			}
		}
	}
	bridge, err := prepareBridge(config, rules)
	if err != nil {
		return nil, err
	}
	j := &journal{Version: 1, DNSMode: request.GetManagedTunDnsMode(), Bridge: bridge, Table: table, IPv6: len(addresses) == 2, Strict: strict, Redirect: redirect, IPv4CIDR: addresses[0]}
	if len(addresses) == 2 {
		j.IPv6CIDR = addresses[1]
	}
	if bridge {
		j.Forwarding, err = captureForwarding()
		if err != nil {
			return nil, err
		}
	}
	if redirect || bridge {
		var token [16]byte
		if _, err = rand.Read(token[:]); err != nil {
			return nil, err
		}
		j.FirewallToken = fmt.Sprintf("%x", token[:])
	}
	if err = o.write(j); err != nil {
		return nil, fmt.Errorf("tun_journal_failed: %w", err)
	}
	o.active = j
	if err = j.createFirewall(); err != nil {
		return nil, err
	}
	if bridge {
		if err = j.enableForwarding(); err != nil {
			return nil, err
		}
	}
	if redirect {
		target["auto_redirect_input_mark"], _ = json.Marshal(table)
		target["auto_redirect_output_mark"], _ = json.Marshal(table + 1)
		target["auto_redirect_reset_mark"], _ = json.Marshal(table + 2)
		target["auto_redirect_iproute2_fallback_rule_index"], _ = json.Marshal(fallbackPriority)
	}
	target["iproute2_table_index"], _ = json.Marshal(table)
	config["inbounds"], _ = json.Marshal(inbounds)
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	request.CoreConfig = proto.String(string(encoded))
	return proto.Marshal(&request)
}

func (o *owner) cleanup() error {
	if o.active == nil {
		return nil
	}
	if err := o.active.clearDNS(); err != nil {
		return err
	}
	// Reaping the worker removes its non-persistent interface and table routes.
	// Never remove a link by name: it may already belong to another program.
	if _, err := netlink.LinkByName(Interface); err == nil {
		return fmt.Errorf("tun_cleanup_pending")
	}
	if o.active.Bridge {
		if _, err := netlink.LinkByName(bridgeInterface); err == nil {
			return fmt.Errorf("tun_cleanup_pending")
		}
	}
	rules, err := routingRules()
	if err != nil {
		return err
	}
	if err = o.active.clearRedirectRoutes(); err != nil {
		return err
	}
	expected := o.active.expected()
	for _, body := range rules {
		s, err := ruleSignature(body)
		if err != nil {
			return err
		}
		if expected[s.key()] {
			if err = deleteRule(body); err != nil {
				return err
			}
		}
	}
	// Retain the journal if any of our exact rules could not be removed.
	rules, err = routingRules()
	if err != nil {
		return err
	}
	for _, body := range rules {
		s, err := ruleSignature(body)
		if err != nil {
			return err
		}
		if expected[s.key()] || s.Table == uint32(o.active.Table) {
			return fmt.Errorf("tun_cleanup_pending")
		}
	}
	if err = o.active.clearFirewall(); err != nil {
		return err
	}
	if err = o.active.restoreForwarding(); err != nil {
		return err
	}
	if err = os.Remove(o.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	o.active = nil
	return nil
}

func validInterfaceCIDR(text string, v6 bool) bool {
	ip, network, err := net.ParseCIDR(text)
	if err != nil || !ip.IsPrivate() {
		return false
	}
	ones, bits := network.Mask.Size()
	return v6 && bits == 128 && ones >= 8 && ones <= 126 || !v6 && bits == 32 && ones >= 8 && ones <= 30
}
