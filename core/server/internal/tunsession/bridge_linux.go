//go:build linux

package tunsession

import (
	"encoding/json"
	"fmt"
	"github.com/sagernet/netlink"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const bridgeInterface = "thronium-br0"
const bridgeFirewall = "sing-box-thronium-br0"
const bridgePriority = 18890
const bridgeIPv4 = "198.19.255.2"
const bridgeIPv6 = "fdfe:dcba:9877::2"

func prepareBridge(config map[string]json.RawMessage, rules [][]byte) (bool, error) {
	var outbounds []map[string]json.RawMessage
	if json.Unmarshal(config["outbounds"], &outbounds) != nil {
		return false, fmt.Errorf("tun_incompatible")
	}
	found := false
	for _, out := range outbounds {
		var kind, tag, name string
		var priority int
		_ = json.Unmarshal(out["type"], &kind)
		if kind != "bridge" {
			continue
		}
		_ = json.Unmarshal(out["tag"], &tag)
		_ = json.Unmarshal(out["bridge_name"], &name)
		_ = json.Unmarshal(out["iproute2_rule_index"], &priority)
		if found || tag != "settings-l3-direct" || name != "thronium-br" || priority != bridgePriority || len(out) != 4 {
			return false, fmt.Errorf("tun_incompatible")
		}
		found = true
	}
	if !found {
		return false, nil
	}
	if _, err := netlink.LinkByName(bridgeInterface); err == nil {
		return false, fmt.Errorf("tun_conflict")
	}
	for _, body := range rules {
		s, err := ruleSignature(body)
		if err != nil {
			return false, err
		}
		if s.Priority == bridgePriority || s.Priority == bridgePriority+1 {
			return false, fmt.Errorf("tun_conflict")
		}
	}
	state, err := firewallState(bridgeFirewall)
	if err != nil {
		return false, err
	}
	if state != nil {
		return false, fmt.Errorf("tun_conflict")
	}
	addresses, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return false, err
	}
	for _, a := range addresses {
		if a.IP.String() == bridgeIPv4 || a.IP.String() == bridgeIPv6 {
			return false, fmt.Errorf("tun_conflict")
		}
	}
	return true, nil
}

func validForwarding(values map[string]string) bool {
	if len(values) > 400 {
		return false
	}
	for path, value := range values {
		if value != "0" && value != "1" && value != "2" {
			return false
		}
		if path == "/proc/sys/net/ipv4/ip_forward" {
			continue
		}
		suffix, ok := strings.CutPrefix(path, "/proc/sys/net/ipv6/conf/")
		if !ok {
			return false
		}
		parts := strings.Split(suffix, "/")
		if len(parts) != 2 || parts[0] == "" || parts[0] == "." || parts[0] == ".." || strings.ContainsAny(parts[0], "\\\x00") || (parts[1] != "forwarding" && parts[1] != "accept_ra") {
			return false
		}
	}
	return true
}
func captureForwarding() (map[string]string, error) {
	paths := []string{"/proc/sys/net/ipv4/ip_forward"}
	entries, err := os.ReadDir("/proc/sys/net/ipv6/conf")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		for _, key := range []string{"forwarding", "accept_ra"} {
			paths = append(paths, filepath.Join("/proc/sys/net/ipv6/conf", entry.Name(), key))
		}
	}
	out := map[string]string{}
	for _, path := range paths {
		bytes, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		out[path] = strings.TrimSpace(string(bytes))
	}
	if !validForwarding(out) {
		return nil, fmt.Errorf("tun_conflict")
	}
	return out, nil
}
func forwardingValue(path, old string) string {
	if strings.HasSuffix(path, "/accept_ra") {
		if old == "1" {
			return "2"
		}
		return old
	}
	return "1"
}
func orderedForwarding(values map[string]string) []string {
	paths := make([]string, 0, len(values))
	for path := range values {
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool {
		rank := func(s string) int {
			if strings.Contains(s, "/all/") || s == "/proc/sys/net/ipv4/ip_forward" {
				return 0
			}
			return 1
		}
		if rank(paths[i]) != rank(paths[j]) {
			return rank(paths[i]) < rank(paths[j])
		}
		return paths[i] < paths[j]
	})
	return paths
}
func (j *journal) enableForwarding() error {
	for _, path := range orderedForwarding(j.Forwarding) {
		if err := os.WriteFile(path, []byte(forwardingValue(path, j.Forwarding[path])), 0644); err != nil {
			return fmt.Errorf("tun_forwarding_failed")
		}
	}
	return nil
}
func (j *journal) restoreForwarding() error {
	if !j.Bridge {
		return nil
	}
	// Decide ownership before restoring conf/all, which propagates into per-link values.
	restore := map[string]string{}
	for path, old := range j.Forwarding {
		current, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(current)) == forwardingValue(path, old) {
			restore[path] = old
		}
	}
	for _, path := range orderedForwarding(restore) {
		if err := os.WriteFile(path, []byte(restore[path]), 0644); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("tun_cleanup_pending")
		}
	}
	return nil
}
