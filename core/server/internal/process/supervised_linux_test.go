//go:build linux

package process

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	if GuardianMain() {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type fixtureReport struct {
	PID        int
	PGID       int
	ConfigPath string
	Config     string
	Mode       uint32
	UID        int
	CWD        string
	Args       []string
	ControlEnv bool
	ProxyEnv   bool
}

func fixtureArgs() []string {
	for i, s := range os.Args {
		if s == "--" {
			return os.Args[i+1:]
		}
	}
	return nil
}

// Executed only as a real child. Normal aggregate runs exclude this fixture.
func TestSupervisedFixture(t *testing.T) {
	a := fixtureArgs()
	if len(a) < 4 {
		t.Skip("subprocess fixture")
	}
	mode, port, configPath, marker := a[0], a[1], a[2], a[3]
	config, _ := os.ReadFile(configPath)
	stat, _ := os.Stat(configPath)
	var perms uint32
	if stat != nil {
		perms = uint32(stat.Mode().Perm())
	}
	cwd, _ := os.Getwd()
	pgid, _ := unix.Getpgid(os.Getpid())
	report := fixtureReport{PID: os.Getpid(), PGID: pgid, ConfigPath: configPath, Config: string(config), Mode: perms, UID: os.Getuid(), CWD: cwd, Args: a[4:], ControlEnv: os.Getenv("THRONE_EXTRA_TEST") != "" || os.Getenv("THRONIUM_EXTRA_TEST") != "", ProxyEnv: os.Getenv("HTTP_PROXY") != "" || os.Getenv("all_proxy") != ""}
	b, _ := json.Marshal(report)
	_ = os.WriteFile(marker, b, 0600)
	if mode == "exit" {
		os.Exit(23)
	}
	if mode == "delay" {
		time.Sleep(150 * time.Millisecond)
	}
	if mode == "no-listen" {
		select {}
	}
	if mode == "flood" {
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), 2*1024*1024))
		_, _ = os.Stderr.Write(bytes.Repeat([]byte("y"), 2*1024*1024))
	}
	if mode == "tree" {
		child := exec.Command(os.Args[0], "-test.run=^TestSupervisedFixture$", "--", "stubborn", port, configPath, marker+".child")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if child.Start() != nil {
			os.Exit(24)
		}
		select {}
	}
	if mode == "stubborn" {
		signal.Ignore(syscall.SIGTERM)
	}
	if mode == "comm" {
		_ = os.WriteFile("/proc/self/comm", []byte("odd) fixture"), 0600)
	}
	if mode == "detached-sleeper" {
		signal.Ignore(syscall.SIGTERM)
		select {}
	}
	if mode == "detached" {
		child := exec.Command(os.Args[0], "-test.run=^TestSupervisedFixture$", "--", "detached-sleeper", port, configPath, marker+".child")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if child.Start() != nil {
			os.Exit(26)
		}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:"+port)
	if err != nil {
		os.Exit(25)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go fixtureSOCKS(conn, mode == "wrong")
	}
}

func fixtureSOCKS(conn net.Conn, wrong bool) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var greeting [3]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return
	}
	if wrong {
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n"))
		return
	}
	if greeting != [3]byte{5, 1, 0} {
		return
	}
	_, _ = conn.Write([]byte{5, 0})
	var request [10]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		return
	}
	if request[0] != 5 || request[1] != 1 || request[3] != 1 {
		return
	}
	address := net.IP(request[4:8]).String()
	if address != "127.0.0.1" {
		return
	}
	upstream, err := net.DialTimeout("tcp4", net.JoinHostPort(address, strconv.Itoa(int(binary.BigEndian.Uint16(request[8:])))), time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
	go func() { _, _ = io.Copy(upstream, conn) }()
	_, _ = io.Copy(conn, upstream)
}

func availablePort(t *testing.T) uint32 {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := uint32(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()
	return p
}
func supported(t *testing.T) {
	t.Helper()
	if !SupervisionSupported() {
		t.Skip("requires unprivileged Linux and -ldflags=-X=ThroneCore/parentcheck.expectedParentName=Thronium")
	}
}
func specFor(t *testing.T, mode string) (Spec, string) {
	t.Helper()
	exe, _ := os.Executable()
	marker := filepath.Join(t.TempDir(), "marker.json")
	port := availablePort(t)
	s, err := ParseSpec(exe, fmt.Sprintf("-test.run=^TestSupervisedFixture$ -- %s %d %%s %q", mode, port, marker), "synthetic-config\nDNS=exact\r\n", true, 1, "127.0.0.1", port, 10000)
	if err != nil {
		t.Fatal(err)
	}
	return s, marker
}
func readReport(t *testing.T, path string) fixtureReport {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var r fixtureReport
	if json.Unmarshal(b, &r) != nil {
		t.Fatal("bad fixture report")
	}
	return r
}
func waitUntil(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition timed out")
}
func gone(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	return err != nil || strings.Contains(string(b), ") Z ")
}

func TestSupervisedParseSpecIsLiteralAndBounded(t *testing.T) {
	s, marker := specFor(t, "socks")
	s.Args = append(s.Args, "$HOME", "`echo x`", "100%", "%d", "two words")
	if err := s.validate(); err != nil {
		t.Fatal(err)
	}
	args := s.arguments("/tmp/with spaces/config")
	if args[4] != "/tmp/with spaces/config" || args[len(args)-1] != "two words" || args[len(args)-3] != "100%" {
		t.Fatal(args)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("parse launched fixture")
	}
	for _, mutate := range []func(*Spec){func(s *Spec) { s.Path = "relative" }, func(s *Spec) { s.Port = 80 }, func(s *Spec) { s.Address = "::1" }, func(s *Spec) { s.Args = []string{"%s%s"} }, func(s *Spec) { s.Args = nil }, func(s *Spec) { s.Args = []string{"bad\x00"} }, func(s *Spec) { s.Config = strings.Repeat("a", 1024*1024+1) }, func(s *Spec) { s.TimeoutMS = 9999 }} {
		bad := s
		mutate(&bad)
		if bad.validate() == nil {
			t.Fatal("accepted invalid spec")
		}
	}
}

func TestSupervisedPrivateFramesRejectMalformedInputs(t *testing.T) {
	for _, payload := range [][]byte{{0, 0, 0, 0}, {255, 255, 255, 255}, {3, 0, 0, 0, '{', '}'}, append([]byte{13, 0, 0, 0}, []byte(`{"unknown":1}`)...)} {
		var s Spec
		if readFrame(bytes.NewReader(payload), &s) == nil {
			t.Fatal("accepted malformed frame")
		}
	}
	var b bytes.Buffer
	original := Status{State: "failed", Reason: "external_core_exited"}
	if writeFrame(&b, original) != nil {
		t.Fatal("write")
	}
	var result Status
	if readFrame(&b, &result) != nil || result.State != original.State {
		t.Fatal("round trip")
	}
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(b []byte) (int, error) {
	if len(b) > 3 {
		b = b[:3]
	}
	return w.Buffer.Write(b)
}

type emptyWriter struct{}

func (emptyWriter) Write([]byte) (int, error) { return 0, nil }

func TestSupervisedMaxEscapedConfigFitsPrivateFrame(t *testing.T) {
	s, _ := specFor(t, "socks")
	s.Config = strings.Repeat("\x01", 1024*1024)
	if err := s.validate(); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := writeFrame(&b, s); err != nil {
		t.Fatal(err)
	}
	var round Spec
	if err := readFrame(&b, &round); err != nil || round.Config != s.Config {
		t.Fatal("escaped config changed", err)
	}
	w := &shortWriter{}
	if err := writeFrame(w, Status{State: "ready"}); err != nil {
		t.Fatal(err)
	}
	var status Status
	if readFrame(&w.Buffer, &status) != nil || status.State != "ready" {
		t.Fatal("partial writer")
	}
	if writeFrame(emptyWriter{}, status) != io.ErrShortWrite {
		t.Fatal("empty writer")
	}
}

func TestSupervisedStartReadyTrafficAndExactInput(t *testing.T) {
	supported(t)
	t.Setenv("THRONE_EXTRA_TEST", "private")
	t.Setenv("THRONIUM_EXTRA_TEST", "private")
	t.Setenv("HTTP_PROXY", "http://invalid.local")
	t.Setenv("all_proxy", "socks5://invalid.local")
	s, marker := specFor(t, "delay")
	s.Args = append(s.Args, "two words", "$HOME", "%d")
	p := NewSupervised(s)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	status := p.Status()
	if status.State != "ready" || len(status.Instance) != 32 {
		t.Fatal(status)
	}
	r := readReport(t, marker)
	cwd, _ := os.Getwd()
	if r.Config != s.Config || r.Mode != 0600 || r.UID != os.Getuid() || r.CWD != cwd || r.ControlEnv || r.ProxyEnv || r.Args[0] != "two words" || r.Args[1] != "$HOME" || r.Args[2] != "%d" {
		t.Fatal("input/env/config changed")
	}
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		c, e := echo.Accept()
		if e == nil {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}
	}()
	c, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", s.Port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte{5, 1, 0})
	var greeting [2]byte
	_, err = io.ReadFull(c, greeting[:])
	if err != nil || greeting != [2]byte{5, 0} {
		t.Fatal("SOCKS greeting")
	}
	port := echo.Addr().(*net.TCPAddr).Port
	_, _ = c.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)})
	var response [10]byte
	if _, err = io.ReadFull(c, response[:]); err != nil || response[1] != 0 {
		t.Fatal("SOCKS connect")
	}
	_, _ = c.Write([]byte("owned-echo"))
	buf := make([]byte, len("owned-echo"))
	if _, err = io.ReadFull(c, buf); err != nil || string(buf) != "owned-echo" {
		t.Fatal("traffic")
	}
	if err = p.Stop(); err != nil {
		t.Fatal(err)
	}
	if err = p.Stop(); err != nil {
		t.Fatal(err)
	}
	if !gone(r.PID) {
		t.Fatal("child remains")
	}
	if _, err = os.Stat(r.ConfigPath); !os.IsNotExist(err) {
		t.Fatal("config remains")
	}
}

func TestSupervisedExistingForeignListenerIsNeverReady(t *testing.T) {
	supported(t)
	s, marker := specFor(t, "socks")
	l, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", s.Port))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	p := NewSupervised(s)
	if err = p.Start(); err == nil || err.Error() != "external_core_port_busy" {
		t.Fatal(err)
	}
	if _, err = os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("started despite occupied endpoint")
	}
	if !ownsListener(s, syscall.Getpgrp()) {
		t.Fatal("fixture listener disappeared")
	}
}

func TestSupervisedImmediateExitAndTempCleanup(t *testing.T) {
	supported(t)
	s, marker := specFor(t, "exit")
	p := NewSupervised(s)
	if err := p.Start(); err == nil || err.Error() != "external_core_exited" {
		t.Fatal(err)
	}
	r := readReport(t, marker)
	status := p.Status()
	if status.ExitCode == nil || *status.ExitCode != 23 {
		t.Fatal(status)
	}
	if _, err := os.Stat(r.ConfigPath); !os.IsNotExist(err) {
		t.Fatal("temp remains")
	}
}

func TestSupervisedWrongProtocolTimesOut(t *testing.T) {
	supported(t)
	s, marker := specFor(t, "wrong")
	p := NewSupervised(s)
	if err := p.Start(); err == nil || err.Error() != "external_core_start_timeout" {
		t.Fatal(err)
	}
	r := readReport(t, marker)
	if !gone(r.PID) {
		t.Fatal("wrong protocol child remains")
	}
	if _, err := os.Stat(r.ConfigPath); !os.IsNotExist(err) {
		t.Fatal("temp remains")
	}
}

func TestSupervisedStopReapsStubbornDescendants(t *testing.T) {
	supported(t)
	s, marker := specFor(t, "tree")
	p := NewSupervised(s)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	parent := readReport(t, marker)
	child := readReport(t, marker+".child")
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	if !gone(parent.PID) || !gone(child.PID) {
		t.Fatal("descendant leaked")
	}
	if _, err := os.Stat(parent.ConfigPath); !os.IsNotExist(err) {
		t.Fatal("config leaked")
	}
}

func TestSupervisedUnexpectedExitReportsFailure(t *testing.T) {
	supported(t)
	s, marker := specFor(t, "socks")
	p := NewSupervised(s)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	r := readReport(t, marker)
	_ = unix.Kill(r.PID, unix.SIGKILL)
	waitUntil(t, func() bool { return p.Status().State == "failed" })
	if p.Status().Reason != "external_core_exited" {
		t.Fatal(p.Status())
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestSupervisedDisabledOutputDrainsFlood(t *testing.T) {
	supported(t)
	s, _ := specFor(t, "flood")
	p := NewSupervised(s)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestSupervisedProcessCommMayContainClosingParenthesis(t *testing.T) {
	supported(t)
	s, marker := specFor(t, "comm")
	p := NewSupervised(s)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	r := readReport(t, marker)
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", r.PID))
	if err != nil || strings.TrimSpace(string(b)) != "odd) fixture" {
		t.Fatal("comm fixture not applied")
	}
	if err = p.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestSupervisedDetachedChildReportsBoundedCleanupFailure(t *testing.T) {
	supported(t)
	if unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != nil {
		t.Fatal("subreaper")
	}
	defer unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0)
	s, marker := specFor(t, "detached")
	p := NewSupervised(s)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, func() bool { _, err := os.Stat(marker + ".child"); return err == nil })
	child := readReport(t, marker+".child")
	defer func() {
		_ = unix.Kill(child.PID, unix.SIGKILL)
		var status unix.WaitStatus
		_, _ = unix.Wait4(child.PID, &status, 0, nil)
	}()
	before := time.Now()
	if err := p.Stop(); err == nil || err.Error() != "external_core_cleanup_failed" {
		t.Fatal(err)
	}
	if time.Since(before) > 4*time.Second {
		t.Fatal("cleanup hung on detached child")
	}
	if gone(child.PID) {
		t.Fatal("guardian killed unsupported unrelated group")
	}
	if !gone(p.cmd.Process.Pid) {
		t.Fatal("guardian itself remained")
	}
}

// A subprocess owning a real guardian, so killing this process tests pipe EOF.
func TestSupervisedWorkerFixture(t *testing.T) {
	a := fixtureArgs()
	if len(a) != 3 {
		t.Skip("worker subprocess fixture")
	}
	port, _ := strconv.ParseUint(a[0], 10, 32)
	marker := a[1]
	exe, _ := os.Executable()
	s, err := ParseSpec(exe, fmt.Sprintf("-test.run=^TestSupervisedFixture$ -- tree %d %%s %q", port, marker), "parent-death-config", true, 1, "127.0.0.1", uint32(port), 10000)
	if err != nil {
		os.Exit(31)
	}
	p := NewSupervised(s)
	if p.Start() != nil {
		os.Exit(32)
	}
	_ = os.WriteFile(a[2], []byte(strconv.Itoa(p.cmd.Process.Pid)), 0600)
	select {}
}

func TestSupervisedGuardianCleansAfterWorkerSIGKILL(t *testing.T) {
	supported(t)
	if unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != nil {
		t.Fatal("subreaper")
	}
	defer unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0)
	root := t.TempDir()
	marker := filepath.Join(root, "marker")
	ready := filepath.Join(root, "ready")
	port := availablePort(t)
	worker := exec.Command(os.Args[0], "-test.run=^TestSupervisedWorkerFixture$", "--", strconv.Itoa(int(port)), marker, ready)
	if worker.Start() != nil {
		t.Fatal("worker launch")
	}
	defer worker.Process.Kill()
	waitUntil(t, func() bool { _, err := os.Stat(ready); return err == nil })
	parent := readReport(t, marker)
	child := readReport(t, marker+".child")
	b, _ := os.ReadFile(ready)
	guardian, _ := strconv.Atoi(string(b))
	_ = worker.Process.Kill()
	_ = worker.Wait()
	waitUntil(t, func() bool { return gone(parent.PID) && gone(child.PID) && gone(guardian) })
	var status unix.WaitStatus
	_, _ = unix.Wait4(guardian, &status, 0, nil)
	if _, err := os.Stat(parent.ConfigPath); !os.IsNotExist(err) {
		t.Fatal("orphan config remains")
	}
	l, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal("orphan listener remains")
	}
	_ = l.Close()
}

// A core that builds a tun holds CAP_NET_ADMIN and CAP_NET_RAW; the program the
// person runs must not inherit them. The guardian gives up every inherited
// capability on the thread it execs from.
func TestGuardianDropsInheritedCapabilitiesBeforeExec(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var before [2]unix.CapUserData
	if err := unix.Capget(&header, &before[0]); err != nil {
		t.Fatal(err)
	}
	if err := dropInheritedCapabilities(); err != nil {
		t.Fatal(err)
	}
	var after [2]unix.CapUserData
	if err := unix.Capget(&header, &after[0]); err != nil {
		t.Fatal(err)
	}
	if after[0].Inheritable != 0 || after[1].Inheritable != 0 {
		t.Fatal("inherited capabilities survived", after)
	}
	if after[0].Permitted != before[0].Permitted || after[1].Permitted != before[1].Permitted {
		t.Fatal("dropping what a child inherits must not touch what the guardian holds")
	}
	// The ambient set is what would cross exec; nothing may remain in it.
	for bit := 0; bit < 64; bit++ {
		raised, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, uintptr(bit), 0, 0, 0)
		if errno == 0 && raised != 0 {
			t.Fatal("ambient capability survived", bit)
		}
	}
}
