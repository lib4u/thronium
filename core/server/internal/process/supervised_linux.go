//go:build linux

package process

import (
	"ThroneCore/parentcheck"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func SupervisionSupported() bool {
	if !parentcheck.ManagedAllowed() || parentcheck.ManagedWorker || os.Getuid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return false
	}
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "CapEff:") || strings.HasPrefix(line, "CapPrm:") || strings.HasPrefix(line, "CapAmb:") {
			_, value, _ := strings.Cut(line, ":")
			n, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
			if err != nil || n != 0 {
				return false
			}
		}
	}
	return true
}

// Preflight checks only local metadata/listener occupancy, never executes Spec.
func Preflight(s Spec, owned *Supervised) error {
	if !SupervisionSupported() {
		return errors.New("external_core_unavailable")
	}
	if err := s.validate(); err != nil {
		return err
	}
	if owned != nil && owned.endpoint(s) && owned.Status().State == "ready" {
		return nil
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(s.Address, strconv.Itoa(int(s.Port))))
	if err != nil {
		return errors.New("external_core_port_busy")
	}
	return listener.Close()
}

type Supervised struct {
	mu       sync.RWMutex
	status   Status
	spec     Spec
	conn     *net.UnixConn
	cmd      *exec.Cmd
	done     chan struct{}
	changed  chan struct{}
	stopOnce sync.Once
}

func (p *Supervised) endpoint(s Spec) bool {
	return p.spec.Address == s.Address && p.spec.Port == s.Port
}
func (p *Supervised) Status() Status {
	p.mu.RLock()
	defer p.mu.RUnlock()
	s := p.status
	if s.ExitCode != nil {
		n := *s.ExitCode
		s.ExitCode = &n
	}
	return s
}
func (p *Supervised) publish(s Status) {
	p.mu.Lock()
	s.Instance = p.status.Instance
	p.status = s
	p.mu.Unlock()
	select {
	case p.changed <- struct{}{}:
	default:
	}
}

func NewSupervised(s Spec) *Supervised {
	var token [16]byte
	_, _ = rand.Read(token[:])
	return &Supervised{spec: s, status: Status{State: "inactive", Instance: hex.EncodeToString(token[:])}, done: make(chan struct{}), changed: make(chan struct{}, 1)}
}

func (p *Supervised) Start() error {
	if err := Preflight(p.spec, nil); err != nil {
		p.publish(Status{State: "failed", Reason: err.Error()})
		close(p.done)
		return err
	}
	p.publish(Status{State: "starting"})
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		p.publish(Status{State: "failed", Reason: "external_core_control_failed"})
		close(p.done)
		return errors.New("external_core_control_failed")
	}
	parentFile := os.NewFile(uintptr(fds[0]), "extra-parent")
	childFile := os.NewFile(uintptr(fds[1]), "extra-guardian")
	conn, err := net.FileConn(parentFile)
	_ = parentFile.Close()
	if err != nil {
		_ = childFile.Close()
		p.publish(Status{State: "failed", Reason: "external_core_control_failed"})
		close(p.done)
		return errors.New("external_core_control_failed")
	}
	p.conn = conn.(*net.UnixConn)
	exe, err := os.Executable()
	if err != nil {
		_ = childFile.Close()
		_ = p.conn.Close()
		p.publish(Status{State: "failed", Reason: "external_core_guardian_failed"})
		close(p.done)
		return errors.New("external_core_guardian_failed")
	}
	p.cmd = exec.Command(exe, GuardianArgument)
	// A detached, unsupported descendant may keep inherited output fds open even
	// after guardian reports cleanup failure. Do not wait forever on its pipes.
	p.cmd.WaitDelay = 500 * time.Millisecond
	p.cmd.ExtraFiles = []*os.File{childFile}
	p.cmd.Env = supervisedEnv()
	p.cmd.Stdout = &boundedOutput{noOut: p.spec.NoLogs}
	p.cmd.Stderr = &boundedOutput{noOut: p.spec.NoLogs}
	err = p.cmd.Start()
	_ = childFile.Close()
	if err != nil {
		_ = p.conn.Close()
		p.publish(Status{State: "failed", Reason: "external_core_guardian_failed"})
		close(p.done)
		return errors.New("external_core_guardian_failed")
	}
	go func() {
		for {
			var status Status
			if readFrame(p.conn, &status) != nil {
				break
			}
			if !validStatus(status) {
				p.publish(Status{State: "failed", Reason: "external_core_control_invalid"})
				_ = p.conn.Close()
				break
			}
			p.publish(status)
		}
		_ = p.cmd.Wait()
		_ = p.conn.Close()
		status := p.Status()
		if status.State == "ready" || status.State == "starting" || status.State == "stopping" {
			p.publish(Status{State: "failed", Reason: "external_core_guardian_exited"})
		}
		close(p.done)
	}()
	_ = p.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	err = writeFrame(p.conn, p.spec)
	_ = p.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		_ = p.Stop()
		return errors.New("external_core_control_failed")
	}
	timer := time.NewTimer(time.Duration(p.spec.TimeoutMS)*time.Millisecond + 3*time.Second)
	defer timer.Stop()
	for {
		s := p.Status()
		if s.State == "ready" {
			return nil
		}
		if s.State == "failed" {
			_ = p.Stop()
			return errors.New(s.Reason)
		}
		select {
		case <-p.changed:
		case <-p.done:
			s = p.Status()
			if s.Reason == "" {
				s.Reason = "external_core_start_failed"
			}
			return errors.New(s.Reason)
		case <-timer.C:
			_ = p.Stop()
			return errors.New("external_core_start_timeout")
		}
	}
}

func (p *Supervised) Stop() error {
	p.stopOnce.Do(func() {
		if p.conn != nil {
			_ = p.conn.CloseWrite()
		}
	})
	select {
	case <-p.done:
		if p.Status().Reason == "external_core_cleanup_failed" {
			return errors.New("external_core_cleanup_failed")
		}
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("external_core_cleanup_failed")
	}
}

func validStatus(s Status) bool {
	if s.Instance != "" || len(s.Reason) > 80 {
		return false
	}
	switch s.State {
	case "starting", "ready", "stopping", "inactive", "failed":
	default:
		return false
	}
	return s.Reason == "" || strings.HasPrefix(s.Reason, "external_core_") && strings.IndexFunc(s.Reason, func(r rune) bool { return r != '_' && (r < 'a' || r > 'z') }) < 0
}

// Only this exact internal mode bypasses normal app-parent checks, after its own
// same-executable parent and kernel socket-credential checks have succeeded.
func GuardianMain() bool {
	if len(os.Args) != 2 || os.Args[1] != GuardianArgument {
		return false
	}
	if err := runGuardian(); err != nil {
		fmt.Fprintln(os.Stderr, "external_core_guardian_failed")
		os.Exit(1)
	}
	return true
}

func guardianConnection() (*net.UnixConn, error) {
	if !SupervisionSupported() {
		return nil, errors.New("external_core_unavailable")
	}
	parent := parentcheck.ParentPID
	if parent <= 1 || os.Getppid() != parent {
		return nil, errors.New("external_core_parent_invalid")
	}
	self, err := os.Stat("/proc/self/exe")
	if err != nil {
		return nil, err
	}
	other, err := os.Stat(fmt.Sprintf("/proc/%d/exe", parent))
	if err != nil || !os.SameFile(self, other) {
		return nil, errors.New("external_core_parent_invalid")
	}
	cred, err := unix.GetsockoptUcred(3, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil || int(cred.Pid) != parent || int(cred.Uid) != os.Getuid() {
		return nil, errors.New("external_core_parent_invalid")
	}
	unix.CloseOnExec(3)
	file := os.NewFile(3, "extra-control")
	conn, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		return nil, err
	}
	return conn.(*net.UnixConn), nil
}

// A core that builds a tun carries CAP_NET_ADMIN and CAP_NET_RAW for it, and a
// child would inherit them through the ambient set. The program the person runs
// is not part of that bargain: this thread gives up every inherited capability
// before it execs, so the child starts with the plain rights of its user.
func dropInheritedCapabilities() error {
	failed := errors.New("external_core_capability_drop_failed")
	if unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != nil {
		return failed
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if unix.Capget(&header, &data[0]) != nil {
		return failed
	}
	data[0].Inheritable, data[1].Inheritable = 0, 0
	if unix.Capset(&header, &data[0]) != nil {
		return failed
	}
	return nil
}

func runGuardian() error {
	conn, err := guardianConnection()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var spec Spec
	if readFrame(conn, &spec) != nil {
		return errors.New("external_core_control_invalid")
	}
	_ = conn.SetReadDeadline(time.Time{})
	send := func(s Status) {
		_ = conn.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
		_ = writeFrame(conn, s)
	}
	if err = Preflight(spec, nil); err != nil {
		send(Status{State: "failed", Reason: err.Error()})
		return nil
	}
	if unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != nil {
		return errors.New("external_core_guardian_failed")
	}
	ownerGone := make(chan struct{})
	go func() { var b [1]byte; _, _ = conn.Read(b[:]); close(ownerGone) }()
	select {
	case <-ownerGone:
		return nil
	default:
	}
	configPath, cleanupPath := "", ""
	for _, arg := range spec.Args {
		if strings.Contains(arg, "%s") {
			configPath, cleanupPath, err = CreateExtraConfig(spec.Config)
			break
		}
	}
	if err != nil {
		send(Status{State: "failed", Reason: "external_core_config_write_failed"})
		return nil
	}
	defer func() {
		if cleanupPath != "" {
			_ = os.RemoveAll(cleanupPath)
		}
	}()
	cmd := exec.Command(spec.Path, spec.arguments(configPath)...)
	cmd.Env = supervisedEnv()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	runtime.LockOSThread()
	err = dropInheritedCapabilities()
	if err == nil {
		err = unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
	}
	if err == nil {
		err = cmd.Start()
	}
	runtime.UnlockOSThread()
	if err != nil {
		send(Status{State: "failed", Reason: "external_core_launch_failed"})
		return nil
	}
	pid := cmd.Process.Pid
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	childExited := false
	cleanup := func() bool {
		_ = unix.Kill(-pid, unix.SIGTERM)
		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) && groupAlive(pid) {
			time.Sleep(10 * time.Millisecond)
		}
		_ = unix.Kill(-pid, unix.SIGKILL)
		if !childExited {
			select {
			case <-exited:
				childExited = true
			case <-time.After(time.Second):
				return false
			}
		}
		deadline = time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			var status unix.WaitStatus
			n, e := unix.Wait4(-1, &status, unix.WNOHANG, nil)
			if e == unix.EINTR {
				continue
			}
			if e == unix.ECHILD {
				return !groupAlive(pid)
			}
			if e != nil {
				return false
			}
			if n == 0 {
				time.Sleep(10 * time.Millisecond)
			}
		}
		return false
	}
	final := Status{State: "inactive"}
	defer func() {
		if !cleanup() {
			final = Status{State: "failed", Reason: "external_core_cleanup_failed"}
		}
		if final.State == "failed" && childExited {
			code := int32(cmd.ProcessState.ExitCode())
			final.ExitCode = &code
		}
		send(final)
	}()
	deadline := time.NewTimer(time.Duration(spec.TimeoutMS) * time.Millisecond)
	defer deadline.Stop()
	tick := time.NewTicker(40 * time.Millisecond)
	defer tick.Stop()
	ready := false
	for !ready {
		select {
		case <-ownerGone:
			return nil
		case <-exited:
			childExited = true
			final = Status{State: "failed", Reason: "external_core_exited"}
			return nil
		case <-deadline.C:
			final = Status{State: "failed", Reason: "external_core_start_timeout"}
			return nil
		case <-tick.C:
			ready = socksReady(spec, pid)
		}
	}
	select {
	case <-exited:
		childExited = true
		final = Status{State: "failed", Reason: "external_core_exited"}
		return nil
	default:
	}
	send(Status{State: "ready"})
	select {
	case <-ownerGone:
		return nil
	case <-exited:
		childExited = true
		final = Status{State: "failed", Reason: "external_core_exited"}
		return nil
	}
}

func groupPIDs(pgid int) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil || len(entries) > 65536 {
		return nil
	}
	var pids []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if err != nil {
			continue
		}
		end := strings.LastIndex(string(b), ") ")
		if end < 0 {
			continue
		}
		fields := strings.Fields(string(b)[end+2:])
		if len(fields) < 3 || fields[0] == "Z" || fields[0] == "X" {
			continue
		}
		group, _ := strconv.Atoi(fields[2])
		if group == pgid {
			pids = append(pids, pid)
			if len(pids) > 128 {
				return nil
			}
		}
	}
	return pids
}

func groupAlive(pgid int) bool { return len(groupPIDs(pgid)) > 0 }

func ownsListener(spec Spec, pgid int) bool {
	b, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return false
	}
	address := fmt.Sprintf("0100007F:%04X", spec.Port)
	inodes := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 9 && fields[1] == address && fields[3] == "0A" {
			inodes["socket:["+fields[9]+"]"] = true
		}
	}
	if len(inodes) == 0 {
		return false
	}
	for _, pid := range groupPIDs(pgid) {
		root := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(root)
		if err != nil || len(fds) > 4096 {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(root, fd.Name()))
			if err == nil && inodes[target] {
				return true
			}
		}
	}
	return false
}

func socksReady(spec Spec, pgid int) bool {
	return ownsListener(spec, pgid) && socksAnswers(spec) && ownsListener(spec, pgid)
}
