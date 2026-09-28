//go:build windows

package process

import (
	"ThroneCore/internal/winjob"
	"ThroneCore/parentcheck"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows needs no guardian process. The external core and everything it
// starts run in a job object whose only handle this process holds, and the job
// kills its members when that handle closes: Stop terminates the job, and a
// core that dies takes the job, and so the whole tree, with it.

var procGetExtendedTcpTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

func SupervisionSupported() bool {
	if !parentcheck.Fork() || parentcheck.ManagedWorker {
		return false
	}
	// An elevated core would hand its administrator token to the program the
	// person runs, as root would on Linux.
	return !windows.GetCurrentProcessToken().IsElevated()
}

func GuardianMain() bool { return false }

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
	stop     chan struct{}
	done     chan struct{}
	changed  chan struct{}
	stopOnce sync.Once
}

func NewSupervised(s Spec) *Supervised {
	var token [16]byte
	_, _ = rand.Read(token[:])
	return &Supervised{spec: s, status: Status{State: "inactive", Instance: hex.EncodeToString(token[:])}, stop: make(chan struct{}), done: make(chan struct{}), changed: make(chan struct{}, 1)}
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

func (p *Supervised) Start() error {
	fail := func(reason string) error {
		p.publish(Status{State: "failed", Reason: reason})
		close(p.done)
		return errors.New(reason)
	}
	if err := Preflight(p.spec, nil); err != nil {
		return fail(err.Error())
	}
	p.publish(Status{State: "starting"})
	job, err := winjob.New()
	if err != nil {
		return fail("external_core_launch_failed")
	}
	configPath, cleanupPath := "", ""
	for _, arg := range p.spec.Args {
		if strings.Contains(arg, "%s") {
			configPath, cleanupPath, err = privateConfig(p.spec.Config)
			break
		}
	}
	if err != nil {
		_ = windows.CloseHandle(job)
		return fail("external_core_config_write_failed")
	}
	release := func() {
		_ = windows.CloseHandle(job)
		if cleanupPath != "" {
			_ = os.RemoveAll(cleanupPath)
		}
	}
	cmd := exec.Command(p.spec.Path, p.spec.arguments(configPath)...)
	cmd.Env = supervisedEnv()
	cmd.Stdout = &boundedOutput{noOut: p.spec.NoLogs}
	cmd.Stderr = &boundedOutput{noOut: p.spec.NoLogs}
	// A descendant that outlived the job's termination cannot hold the output
	// pipes open forever.
	cmd.WaitDelay = 500 * time.Millisecond
	// Suspended until it is inside the job, so not even its first child escapes.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW}
	if cmd.Start() != nil {
		release()
		return fail("external_core_launch_failed")
	}
	if winjob.Adopt(job, uint32(cmd.Process.Pid)) != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		release()
		return fail("external_core_launch_failed")
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	go p.run(cmd, job, exited, release)
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

// run owns the job from launch to cleanup and publishes the final status.
func (p *Supervised) run(cmd *exec.Cmd, job windows.Handle, exited <-chan struct{}, release func()) {
	final := Status{State: "inactive"}
	childExited := false
	defer func() {
		if !winjob.Terminate(job) {
			final = Status{State: "failed", Reason: "external_core_cleanup_failed"}
		}
		if !childExited {
			select {
			case <-exited:
			case <-time.After(time.Second):
				final = Status{State: "failed", Reason: "external_core_cleanup_failed"}
			}
		}
		release()
		if final.State == "failed" && childExited {
			code := int32(cmd.ProcessState.ExitCode())
			final.ExitCode = &code
		}
		p.publish(final)
		close(p.done)
	}()
	deadline := time.NewTimer(time.Duration(p.spec.TimeoutMS) * time.Millisecond)
	defer deadline.Stop()
	tick := time.NewTicker(40 * time.Millisecond)
	defer tick.Stop()
	for ready := false; !ready; {
		select {
		case <-p.stop:
			return
		case <-exited:
			childExited = true
			final = Status{State: "failed", Reason: "external_core_exited"}
			return
		case <-deadline.C:
			final = Status{State: "failed", Reason: "external_core_start_timeout"}
			return
		case <-tick.C:
			ready = socksReady(p.spec, job)
		}
	}
	select {
	case <-exited:
		childExited = true
		final = Status{State: "failed", Reason: "external_core_exited"}
		return
	default:
	}
	p.publish(Status{State: "ready"})
	select {
	case <-p.stop:
	case <-exited:
		childExited = true
		final = Status{State: "failed", Reason: "external_core_exited"}
	}
}

func (p *Supervised) Stop() error {
	p.stopOnce.Do(func() { close(p.stop) })
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

// The config may hold credentials. It goes into a fresh directory under the
// per-user temp folder and keeps that folder's permissions: unlike the legacy
// path, nothing grants it to other users.
func privateConfig(content string) (string, string, error) {
	directory, err := os.MkdirTemp("", "thronium-extra-*")
	if err != nil {
		return "", "", err
	}
	path := filepath.Join(directory, "config")
	if err = os.WriteFile(path, []byte(content), 0600); err != nil {
		_ = os.RemoveAll(directory)
		return "", "", err
	}
	return path, directory, nil
}

func socksReady(spec Spec, job windows.Handle) bool {
	return ownsListener(spec, job) && socksAnswers(spec) && ownsListener(spec, job)
}

// ownsListener: a member of this job listens on the endpoint. The job names
// its own members, so no process outside the tree is ever opened.
func ownsListener(spec Spec, job windows.Handle) bool {
	owners := listeners(spec.Port)
	for _, pid := range members(job) {
		if slices.Contains(owners, uint32(pid)) {
			return true
		}
	}
	return false
}

// JOBOBJECT_BASIC_PROCESS_ID_LIST with room for far more members than an
// external core starts; a larger tree simply never counts as ready.
type jobMembers struct {
	Assigned, Listed uint32
	IDs              [512]uintptr
}

func members(job windows.Handle) []uintptr {
	var list jobMembers
	if windows.QueryInformationJobObject(job, windows.JobObjectBasicProcessIdList, uintptr(unsafe.Pointer(&list)), uint32(unsafe.Sizeof(list)), nil) != nil {
		return nil
	}
	return list.IDs[:min(list.Listed, uint32(len(list.IDs)))]
}

func listeners(port uint32) []uint32 {
	const tcpTableOwnerPidListener = 3
	size := uint32(0)
	for range 4 {
		table := make([]byte, max(size, 4))
		r, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&table[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, tcpTableOwnerPidListener, 0)
		switch windows.Errno(r) {
		case 0:
			return listenerOwners(table[:min(size, uint32(len(table)))], port)
		case windows.ERROR_INSUFFICIENT_BUFFER:
			// The table can grow between the two calls.
			size += 1024
		default:
			return nil
		}
	}
	return nil
}
