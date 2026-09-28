//go:build linux

package tunsession

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	"github.com/sagernet/nftables"
	"golang.org/x/sys/unix"
)

func TestKernelRuleNormalization(t *testing.T) {
	// Actual Linux dump: invert dport 53 lookup main suppress_prefixlen 0,
	// including the full single-port mask emitted by newer kernels.
	body, _ := hex.DecodeString("02000000fe0000010200000008000f00fe00000008000e0000000000050015000000000008000600d6490000080018003500350006001d00ffff0000")
	s, err := ruleSignature(body)
	if err != nil {
		t.Fatal(err)
	}
	r := netlink.NewRule()
	r.Family = unix.AF_INET
	r.Priority = 18902
	r.Invert = true
	r.Table = unix.RT_TABLE_MAIN
	r.SuppressPrefixlen = 0
	r.Dport = netlink.NewRulePortRange(53, 53)
	if s.key() != expectedSignature(r) {
		t.Fatalf("mask normalization: %s", s.key())
	}
	body[len(body)-4] = 0xf0
	s, err = ruleSignature(body)
	if err != nil || s.key() == expectedSignature(r) {
		t.Fatal("a different port mask must be preserved")
	}
	body, _ = hex.DecodeString("02000000000000020c00000008000600d6490000110003007468726f6e69756d2d74756e0000000008000400de490000")
	s, err = ruleSignature(body)
	if err != nil {
		t.Fatal(err)
	}
	r = netlink.NewRule()
	r.Family = unix.AF_INET
	r.Priority = 18902
	r.IifName = Interface
	r.Goto = 18910
	if s.key() != expectedSignature(r) {
		t.Fatalf("detached interface normalization: %s", s.key())
	}
}

func TestRuleRejectsMalformedAndPreservesUnknownAttributes(t *testing.T) {
	for _, body := range [][]byte{nil, make([]byte, 11), make([]byte, 13), append(make([]byte, 12), 9, 0, 1, 0)} {
		if _, err := ruleSignature(body); err == nil {
			t.Fatalf("accepted malformed %x", body)
		}
	}
	a := signature{Attrs: map[uint16]string{42: "\xff"}}
	b := signature{Attrs: map[uint16]string{42: "\xfe"}}
	if a.key() == b.key() {
		t.Fatal("binary attribute signatures collided")
	}
}

func TestReadFrameRejectsOversizedPayloadBeforeAllocation(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	go func() {
		defer client.Close()
		b := make([]byte, 11)
		binary.LittleEndian.PutUint16(b[4:], 1)
		b[6] = 'X'
		binary.LittleEndian.PutUint32(b[7:], maxFrame+1)
		client.Write(b)
	}()
	if _, err := readFrame(server); err == nil {
		t.Fatal("oversized payload accepted")
	}
}

func TestJournalNeverSignalsReusedPID(t *testing.T) {
	// No signal is sent when the recorded identity differs, even for a live PID.
	start, err := processStart(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err = (&journal{WorkerPID: os.Getpid(), WorkerStart: start + 1}).reap(); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerDroppedCredentials(t *testing.T) {
	core := os.Getenv("THRONIUM_TEST_CORE")
	if core == "" {
		t.Skip("run desktop/scripts/test_tun.py for isolated credential test")
	}
	original := os.Getenv("THRONIUM_TEST_ORIGINAL_NETNS")
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil || original == "" || current == original || os.Geteuid() != 0 {
		t.Fatal("isolated root user/network namespace required")
	}
	dir, err := os.MkdirTemp("", "tun-credentials-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err = os.Chown(dir, 1000, 1000); err != nil {
		t.Fatal(err)
	}
	w, err := startWorkerExecutable(core, &unix.Ucred{Uid: 1000, Gid: 1000}, dir, make(chan struct{}))
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", w.cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "Uid:", "Gid:":
			for _, id := range fields[1:] {
				if id != "1000" {
					t.Fatalf("worker retained root: %s", line)
				}
			}
		case "CapEff:", "CapPrm:", "CapAmb:":
			caps, err := strconv.ParseUint(fields[1], 16, 64)
			if err != nil || caps != (1<<unix.CAP_NET_ADMIN|1<<unix.CAP_NET_RAW) {
				t.Fatalf("unexpected capabilities: %s", line)
			}
		}
	}
	// Leave enough time for the worker's liveness check of its privileged parent.
	time.Sleep(10200 * time.Millisecond)
	select {
	case <-w.exited:
		t.Fatal("dropped worker rejected live root parent")
	default:
	}
	t.Log("worker UID/GID 1000, only CAP_NET_ADMIN + CAP_NET_RAW; authenticated root parent remains alive")
}

func TestJournalRefusesUnsafeRecoveryFiles(t *testing.T) {
	if os.Getenv("THRONIUM_TEST_CORE") == "" {
		t.Skip("requires isolated /run")
	}
	current, _ := os.Readlink("/proc/self/ns/mnt")
	if original := os.Getenv("THRONIUM_TEST_ORIGINAL_MNTNS"); original == "" || original == current {
		t.Fatal("private mount namespace required")
	}
	o, err := newOwner()
	if err != nil {
		t.Fatal(err)
	}
	path := o.path
	o.lease.Close()
	target := path + ".foreign"
	if err = os.WriteFile(target, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(target)
	for _, symlink := range []bool{false, true} {
		if symlink {
			err = os.Symlink(target, path)
		} else {
			err = os.WriteFile(path, []byte("corrupt"), 0600)
		}
		if err != nil {
			t.Fatal(err)
		}
		if o, err := newOwner(); err == nil {
			o.lease.Close()
			t.Fatal("unsafe journal accepted")
		}
		os.Remove(path)
	}
	data, _ := os.ReadFile(target)
	if string(data) != "foreign" {
		t.Fatal("foreign file modified")
	}
	// Verify that journal identity cannot kill a different live process.
	child := exec.Command("sleep", "10")
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { child.Process.Kill(); child.Wait() }()
	start, err := processStart(child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if err = (&journal{WorkerPID: child.Process.Pid, WorkerStart: start + 1}).reap(); err != nil {
		t.Fatal(err)
	}
	if err = child.Process.Signal(unix.Signal(0)); err != nil {
		t.Fatal("wrong process signalled")
	}
}

func TestConfiguredPrefixesAndFirewallOwnership(t *testing.T) {
	if !validInterfaceCIDR("10.71.0.1/30", false) || validInterfaceCIDR("127.0.0.1/8", false) || validInterfaceCIDR("::1/128", true) {
		t.Fatal("interface validation")
	}
	j := &journal{Version: 1, Table: 157321, IPv4CIDR: "10.71.0.1/30", IPv6CIDR: "fd72::1/126", IPv6: true, Redirect: true, FirewallToken: "0123456789abcdef0123456789abcdef"}
	if len(j.expected()) != 10 {
		t.Fatal("redirect rule count")
	}
	// Privileged assertions run only in the runner's isolated network namespace.
	if os.Getenv("THRONIUM_TEST_ORIGINAL_NETNS") == "" {
		return
	}
	current, _ := os.Readlink("/proc/self/ns/net")
	if current == os.Getenv("THRONIUM_TEST_ORIGINAL_NETNS") {
		t.Fatal("host namespace")
	}
	if err := j.createFirewall(); err != nil {
		t.Fatal(err)
	}
	table, err := firewallState()
	if err != nil || table == nil || table.Comment != "thronium:"+j.FirewallToken {
		t.Fatal("ownership marker", err)
	}
	nftconn, _ := nftables.New()
	nftconn.AddTable(&nftables.Table{Name: firewallTable, Family: nftables.TableFamilyINet})
	if err = nftconn.Flush(); err != nil {
		t.Fatal(err)
	}
	nftconn.CloseLasting()
	table, err = firewallState()
	if err != nil || table == nil || table.Comment != "thronium:"+j.FirewallToken {
		t.Fatal("core overwrote ownership marker")
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		r := netlink.NewRule()
		r.Family = family
		r.Priority = Priority
		r.Mark = uint32(j.Table + 1)
		r.MarkSet = true
		r.Goto = Priority + 2
		if err = netlink.RuleAdd(r); err != nil {
			t.Fatal(err)
		}
		raw, err := routingRules()
		if err != nil {
			t.Fatal(err)
		}
		matched := false
		for _, body := range raw {
			signature, err := ruleSignature(body)
			if err != nil {
				t.Fatal(err)
			}
			if signature.Priority == uint32(Priority) && signature.Family == byte(family) {
				if signature.key() != expectedSignature(r) {
					t.Fatalf("marked rule mismatch: %s != %s", signature.key(), expectedSignature(r))
				}
				matched = true
			}
		}
		if !matched {
			t.Fatal("marked rule missing")
		}
		if err = netlink.RuleDel(r); err != nil {
			t.Fatal(err)
		}
	}
	// A different journal must leave this table alone.
	foreign := *j
	foreign.FirewallToken = "ffffffffffffffffffffffffffffffff"
	if err = foreign.clearFirewall(); err != nil {
		t.Fatal(err)
	}
	table, err = firewallState()
	if err != nil || table == nil {
		t.Fatal("foreign table removed")
	}
	if err = j.clearFirewall(); err != nil {
		t.Fatal(err)
	}
	table, err = firewallState()
	if err != nil || table != nil {
		t.Fatal("owned firewall not removed")
	}
}
