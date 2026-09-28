//go:build windows

package process

import (
	"ThroneCore/internal/winjob"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// These run only on Windows (acceptance group A) and need a fork build:
// -ldflags=-X=ThroneCore/parentcheck.expectedParentName=Thronium

type windowsReport struct {
	PID        int
	Config     string
	ConfigPath string
	Args       []string
}

func windowsFixtureArgs() []string {
	for i, s := range os.Args {
		if s == "--" {
			return os.Args[i+1:]
		}
	}
	return nil
}

// Executed only as a real child. Normal aggregate runs skip this fixture.
func TestSupervisedWindowsFixture(t *testing.T) {
	a := windowsFixtureArgs()
	if len(a) < 4 {
		t.Skip("subprocess fixture")
	}
	mode, port, configPath, marker := a[0], a[1], a[2], a[3]
	config, _ := os.ReadFile(configPath)
	b, _ := json.Marshal(windowsReport{PID: os.Getpid(), Config: string(config), ConfigPath: configPath, Args: a[4:]})
	_ = os.WriteFile(marker, b, 0600)
	switch mode {
	case "exit":
		os.Exit(23)
	case "owner":
		// Plays the core: supervises a child, then is killed from outside.
		exe, _ := os.Executable()
		s, err := ParseSpec(exe, fmt.Sprintf("-test.run=^TestSupervisedWindowsFixture$ -- socks %s %%s %q", port, marker+".child"), "", true, 1, "127.0.0.1", mustPort(port), 10000)
		if err != nil || NewSupervised(s).Start() != nil {
			os.Exit(26)
		}
		_ = os.WriteFile(marker+".ready", nil, 0600)
		time.Sleep(time.Hour)
	case "tree":
		// The descendant listens; only the job ties it to the supervised tree.
		child := exec.Command(os.Args[0], "-test.run=^TestSupervisedWindowsFixture$", "--", "socks", port, configPath, marker+".child")
		if child.Start() != nil {
			os.Exit(24)
		}
		// Not select{}: with nothing else running, Go ends that as a deadlock.
		time.Sleep(time.Hour)
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
		go func() {
			defer conn.Close()
			var greeting [3]byte
			if _, err := io.ReadFull(conn, greeting[:]); err == nil && greeting == [3]byte{5, 1, 0} {
				_, _ = conn.Write([]byte{5, 0})
			}
		}()
	}
}

func mustPort(text string) uint32 {
	var port uint32
	_, _ = fmt.Sscan(text, &port)
	return port
}

func windowsSpec(t *testing.T, mode string) (Spec, string) {
	t.Helper()
	if !SupervisionSupported() {
		t.Skip("requires an unelevated fork build")
	}
	exe, _ := os.Executable()
	marker := filepath.Join(t.TempDir(), "marker.json")
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint32(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()
	s, err := ParseSpec(exe, fmt.Sprintf("-test.run=^TestSupervisedWindowsFixture$ -- %s %d %%s %q 'two words'", mode, port, marker), "synthetic-config", true, 1, "127.0.0.1", port, 10000)
	if err != nil {
		t.Fatal(err)
	}
	return s, marker
}

func windowsReportFrom(t *testing.T, path string) windowsReport {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		var r windowsReport
		if b, err := os.ReadFile(path); err == nil && json.Unmarshal(b, &r) == nil {
			return r
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no fixture report")
	return windowsReport{}
}

func exitedProcess(pid int) bool {
	process, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return true
	}
	defer windows.CloseHandle(process)
	event, _ := windows.WaitForSingleObject(process, 2000)
	return event == windows.WAIT_OBJECT_0
}

func TestSupervisedWindowsDescendantListenerIsReadyAndStopEndsTheTree(t *testing.T) {
	s, marker := windowsSpec(t, "tree")
	p := NewSupervised(s)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	if status := p.Status(); status.State != "ready" || len(status.Instance) != 32 {
		t.Fatal(status)
	}
	parent := windowsReportFrom(t, marker)
	child := windowsReportFrom(t, marker+".child")
	if parent.Config != s.Config || len(parent.Args) != 1 || parent.Args[0] != "two words" {
		t.Fatal("input changed")
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	if !exitedProcess(parent.PID) || !exitedProcess(child.PID) {
		t.Fatal("descendant leaked")
	}
	if _, err := os.Stat(parent.ConfigPath); !os.IsNotExist(err) {
		t.Fatal("config leaked")
	}
}

func TestSupervisedWindowsImmediateExitReportsCode(t *testing.T) {
	s, marker := windowsSpec(t, "exit")
	p := NewSupervised(s)
	if err := p.Start(); err == nil || err.Error() != "external_core_exited" {
		t.Fatal(err)
	}
	r := windowsReportFrom(t, marker)
	if status := p.Status(); status.ExitCode == nil || *status.ExitCode != 23 {
		t.Fatal(status)
	}
	if _, err := os.Stat(r.ConfigPath); !os.IsNotExist(err) {
		t.Fatal("config leaked")
	}
}

func TestSupervisedWindowsForeignListenerIsNeverOurs(t *testing.T) {
	s, marker := windowsSpec(t, "socks")
	l, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", s.Port))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err = NewSupervised(s).Start(); err == nil || err.Error() != "external_core_port_busy" {
		t.Fatal(err)
	}
	if _, err = os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("started despite occupied endpoint")
	}
	job, err := winjob.New()
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(job)
	if len(listeners(s.Port)) == 0 || ownsListener(s, job) {
		t.Fatal("listener ownership")
	}
}

func TestSupervisedWindowsKilledChildReportsFailure(t *testing.T) {
	s, marker := windowsSpec(t, "socks")
	p := NewSupervised(s)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	r := windowsReportFrom(t, marker)
	process, err := os.FindProcess(r.PID)
	if err != nil {
		t.Fatal(err)
	}
	_ = process.Kill()
	deadline := time.Now().Add(6 * time.Second)
	for p.Status().State != "failed" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if p.Status().Reason != "external_core_exited" {
		t.Fatal(p.Status())
	}
	if err = p.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestSupervisedWindowsAcceptsOnlyProgramImages(t *testing.T) {
	for _, path := range []string{`C:\tools\core.cmd`, `C:\tools\core.bat`, `C:\tools\core`} {
		if runnable(path, nil) == nil {
			t.Fatal(path)
		}
	}
	if runnable(`C:\tools\CORE.EXE`, nil) != nil {
		t.Fatal("exe")
	}
}

func TestSupervisedWindowsTreeEndsWithItsOwner(t *testing.T) {
	s, marker := windowsSpec(t, "owner")
	exe, _ := os.Executable()
	owner := exec.Command(exe, append([]string{"-test.run=^TestSupervisedWindowsFixture$", "--"}, "owner", fmt.Sprint(s.Port), "unused", marker)...)
	if err := owner.Start(); err != nil {
		t.Fatal(err)
	}
	defer owner.Process.Kill()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker + ".ready"); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	child := windowsReportFrom(t, marker+".child")
	if exitedProcess(child.PID) {
		t.Fatal("child not running")
	}
	// No Stop, no cleanup code: only the closing job handle can end the child.
	_ = owner.Process.Kill()
	_ = owner.Wait()
	if !exitedProcess(child.PID) {
		t.Fatal("child outlived its owner")
	}
}
