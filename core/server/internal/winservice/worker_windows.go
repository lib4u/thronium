//go:build windows

package winservice

import (
	"ThroneCore/internal/winjob"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/tailscale/go-winio"
	"golang.org/x/sys/windows"
)

// Only SYSTEM may open a worker's pipe; the service checks the PID as well.
var workerPipeSecurity = "D:P(A;;GA;;;SY)"

type windowsWorker struct {
	conn     net.Conn
	listener net.Listener
	cmd      *exec.Cmd
	job      windows.Handle
	pid      uint32
	created  uint64
	done     chan struct{}
	stop     chan struct{}
}

func pipeName() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return `\\.\pipe\thronium-worker-` + hex.EncodeToString(random[:]), nil
}

// startWorker runs this same executable as a SYSTEM core in its own job, in
// a directory it gets to itself, and accepts its connection only from it.
func startWorker(executable, directory string, output io.Writer, gone <-chan struct{}) (*windowsWorker, error) {
	failed := errors.New("tun_service_worker_failed")
	if err := os.RemoveAll(directory); err != nil {
		return nil, failed
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, failed
	}
	name, err := pipeName()
	if err != nil {
		return nil, failed
	}
	listener, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: workerPipeSecurity})
	if err != nil {
		return nil, failed
	}
	job, err := winjob.New()
	if err != nil {
		listener.Close()
		return nil, failed
	}
	w := &windowsWorker{listener: listener, job: job, done: make(chan struct{}), stop: make(chan struct{})}
	cmd := exec.Command(executable, "--thronium-tun-worker")
	cmd.Dir = directory
	cmd.Env = append(os.Environ(), "THRONE_CORE_SOCKET="+name)
	cmd.Stdout, cmd.Stderr = output, output
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW}
	if err = cmd.Start(); err != nil {
		listener.Close()
		_ = windows.CloseHandle(job)
		return nil, failed
	}
	w.cmd = cmd
	w.pid = uint32(cmd.Process.Pid)
	go func() {
		_ = cmd.Wait()
		close(w.done)
	}()
	if err = winjob.Adopt(job, w.pid); err != nil {
		w.close()
		return nil, failed
	}
	w.created = processCreated(w.pid)
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- conn
	}()
	select {
	case conn, ok := <-accepted:
		if !ok {
			w.close()
			return nil, failed
		}
		w.conn = conn
	case <-time.After(8 * time.Second):
		w.close()
		return nil, failed
	case <-gone:
		w.close()
		return nil, failed
	case <-w.done:
		w.close()
		return nil, failed
	}
	if pid, err := clientPID(w.conn); err != nil || pid != w.pid {
		w.close()
		return nil, errors.New("core_peer_mismatch")
	}
	go func() {
		select {
		case <-gone:
			_ = w.conn.Close()
		case <-w.stop:
		}
	}()
	return w, nil
}

func clientPID(conn net.Conn) (uint32, error) {
	fd, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return 0, errors.New("pipe without handle")
	}
	var pid uint32
	err := windows.GetNamedPipeClientProcessId(windows.Handle(fd.Fd()), &pid)
	return pid, err
}

// processCreated is the creation time in 100 ns units; with the PID it names
// one process, never a later one that reuses the PID.
func processCreated(pid uint32) uint64 {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(process)
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(process, &created, &exited, &kernel, &user) != nil {
		return 0
	}
	return uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
}

func (w *windowsWorker) exchange(f request, timeout time.Duration) ([]byte, error) {
	if w.conn == nil {
		return nil, errors.New("worker unavailable")
	}
	if err := w.conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := w.conn.Write(encodeRequest(f)); err != nil {
		return nil, err
	}
	r, err := readResponse(w.conn)
	if err != nil {
		return nil, err
	}
	if r.id != f.id {
		return nil, errors.New("invalid worker response")
	}
	return encodeResponse(r), nil
}

func (w *windowsWorker) exited() <-chan struct{}    { return w.done }
func (w *windowsWorker) identity() (uint32, uint64) { return w.pid, w.created }

// close lets the core stop its box first, so sing-tun removes the adapter and
// its filters itself, then ends the job whatever the core did.
func (w *windowsWorker) close() {
	select {
	case <-w.stop:
		return
	default:
		close(w.stop)
	}
	if w.conn != nil {
		_, _ = w.exchange(request{method: "Stop"}, 5*time.Second)
		_ = w.conn.Close()
	}
	_ = w.listener.Close()
	select {
	case <-w.done:
	case <-time.After(2 * time.Second):
	}
	winjob.Terminate(w.job)
	_ = windows.CloseHandle(w.job)
	if w.cmd != nil {
		select {
		case <-w.done:
		case <-time.After(2 * time.Second):
		}
	}
}

// terminateLeftover ends a worker a previous service run journaled, if that
// exact process still runs. Normally its job already ended it.
func terminateLeftover(pid uint32, created uint64) {
	if pid == 0 || created == 0 || processCreated(pid) != created {
		return
	}
	process, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return
	}
	_ = windows.TerminateProcess(process, 1)
	_ = windows.CloseHandle(process)
}
