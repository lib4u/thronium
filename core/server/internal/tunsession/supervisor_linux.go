//go:build linux

package tunsession

import (
	"ThroneCore/gen"
	"ThroneCore/ipc"
	"ThroneCore/parentcheck"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

const maxFrame = 16 * 1024 * 1024

type frame struct {
	id      uint32
	method  string
	payload []byte
}

func readFrame(conn net.Conn) (frame, error) {
	var header [6]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return frame{}, err
	}
	n := int(binary.LittleEndian.Uint16(header[4:]))
	if n == 0 || n > 128 {
		return frame{}, fmt.Errorf("invalid method")
	}
	name := make([]byte, n)
	if _, err := io.ReadFull(conn, name); err != nil {
		return frame{}, err
	}
	var size [4]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return frame{}, err
	}
	length := binary.LittleEndian.Uint32(size[:])
	if length > maxFrame || (string(name) == "ManagedVPN" && length > maxManagedVPNRequest) || (string(name) == "ManagedVPNReplaceCredentials" && length > maxManagedCredentialsRequest) {
		return frame{}, fmt.Errorf("invalid frame size")
	}
	payload := make([]byte, int(length))
	_, err := io.ReadFull(conn, payload)
	return frame{binary.LittleEndian.Uint32(header[:]), string(name), payload}, err
}
func writeFrame(conn net.Conn, f frame) error {
	b := make([]byte, 10+len(f.method)+len(f.payload))
	binary.LittleEndian.PutUint32(b, f.id)
	binary.LittleEndian.PutUint16(b[4:], uint16(len(f.method)))
	copy(b[6:], f.method)
	binary.LittleEndian.PutUint32(b[6+len(f.method):], uint32(len(f.payload)))
	copy(b[10+len(f.method):], f.payload)
	_, err := conn.Write(b)
	return err
}
func reply(conn net.Conn, id uint32, message string) error {
	response := &gen.ErrorResp{}
	if message != "" {
		response.Error = proto.String(message)
	}
	data, _ := proto.Marshal(response)
	header := make([]byte, 9)
	binary.LittleEndian.PutUint32(header, id)
	binary.LittleEndian.PutUint32(header[5:], uint32(len(data)))
	_, err := conn.Write(append(header, data...))
	return err
}
func peer(conn net.Conn) (*unix.Ucred, error) {
	raw, err := conn.(*net.UnixConn).SyscallConn()
	if err != nil {
		return nil, err
	}
	var credentials *unix.Ucred
	var inner error
	err = raw.Control(func(fd uintptr) {
		credentials, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil {
		return nil, err
	}
	return credentials, inner
}

// The supervised worker is intentionally allowed to have a privileged parent
// whose /proc/exe it cannot read. The kernel must identify that exact parent as root.
func VerifyWorkerParent(conn net.Conn) error {
	credentials, err := peer(conn)
	if err != nil {
		return err
	}
	if credentials.Uid != 0 || int(credentials.Pid) != parentcheck.ParentPID {
		return fmt.Errorf("invalid managed parent")
	}
	return nil
}

type workerProcess struct {
	conn      net.Conn
	cmd       *exec.Cmd
	exited    chan struct{}
	stopWatch chan struct{}
	directory string
}

func startWorker(credentials *unix.Ucred, directory string, guiGone <-chan struct{}) (*workerProcess, error) {
	return startWorkerExecutable("/proc/self/exe", credentials, directory, guiGone)
}

func startWorkerExecutable(executable string, credentials *unix.Ucred, directory string, guiGone <-chan struct{}) (*workerProcess, error) {
	return startWorkerExecutableUntil(executable, credentials, directory, guiGone, time.Now().Add(8*time.Second))
}

func startWorkerExecutableUntil(executable string, credentials *unix.Ucred, directory string, guiGone <-chan struct{}, deadline time.Time, pinResolver ...bool) (*workerProcess, error) {
	available := func() bool {
		select {
		case <-guiGone:
			return false
		default:
		}
		return time.Now().Before(deadline)
	}
	if !available() {
		return nil, fmt.Errorf("core_start_cancelled")
	}
	private, err := workerSocketDirectory(os.TempDir())
	if err != nil {
		return nil, err
	}
	w := &workerProcess{directory: private, exited: make(chan struct{}), stopWatch: make(chan struct{})}
	fail := func(err error) (*workerProcess, error) { os.RemoveAll(private); return nil, err }
	if err = os.Chown(private, int(credentials.Uid), int(credentials.Gid)); err != nil {
		return fail(err)
	}
	path := filepath.Join(private, workerSocketName)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return fail(err)
	}
	defer listener.Close()
	if err = os.Chown(path, int(credentials.Uid), int(credentials.Gid)); err != nil {
		return fail(err)
	}
	if err = os.Chmod(path, 0600); err != nil {
		return fail(err)
	}
	w.cmd = exec.Command(executable, "--thronium-tun-worker")
	w.cmd.Dir = directory
	w.cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "THRONE_CORE_SOCKET=" + path, "XRAY_LOCATION_ASSET=" + filepath.Join(directory, "xray-assets")}
	w.cmd.Stdout = os.Stdout
	w.cmd.Stderr = os.Stderr
	w.cmd.SysProcAttr = &syscall.SysProcAttr{AmbientCaps: []uintptr{unix.CAP_NET_ADMIN, unix.CAP_NET_RAW}}
	if credentials.Uid != 0 {
		w.cmd.SysProcAttr.Credential = &syscall.Credential{Uid: credentials.Uid, Gid: credentials.Gid, Groups: []uint32{credentials.Gid}}
	}
	if !available() {
		return fail(fmt.Errorf("core_start_cancelled"))
	}
	if len(pinResolver) == 1 && pinResolver[0] {
		err = startWithResolverView(w.cmd)
	} else {
		err = w.cmd.Start()
	}
	if err != nil {
		return fail(err)
	}
	go func() { _ = w.cmd.Wait(); close(w.exited) }()
	acceptDeadline := time.Now().Add(8 * time.Second)
	if deadline.Before(acceptDeadline) {
		acceptDeadline = deadline
	}
	_ = listener.SetDeadline(acceptDeadline)
	acceptDone := make(chan struct{})
	defer close(acceptDone)
	go func() {
		select {
		case <-guiGone:
			_ = listener.Close()
		case <-acceptDone:
		}
	}()
	accepted, err := listener.AcceptUnix()
	if err != nil {
		w.close()
		return nil, err
	}
	w.conn = accepted
	if !available() {
		w.close()
		return nil, fmt.Errorf("core_start_cancelled")
	}
	child, err := peer(w.conn)
	if err != nil || int(child.Pid) != w.cmd.Process.Pid {
		w.close()
		return nil, fmt.Errorf("core_peer_mismatch")
	}
	go func() {
		select {
		case <-guiGone:
			_ = w.conn.Close()
		case <-w.stopWatch:
		}
	}()
	return w, nil
}
func (w *workerProcess) close() {
	close(w.stopWatch)
	// The supervisor owns policy cleanup. Reap every TUN fd without letting
	// sing-tun's broad priority-range cleanup remove rules added by other software.
	_ = w.cmd.Process.Kill()
	if w.conn != nil {
		_ = w.conn.Close()
	}
	select {
	case <-w.exited:
	case <-time.After(2 * time.Second):
		_ = w.cmd.Process.Kill()
		<-w.exited
	}
	os.RemoveAll(w.directory)
}
func cleanup(o *owner) error {
	if o == nil {
		return nil
	}
	defer o.lease.Close()
	return cleanNetwork(o)
}
func cleanNetwork(o *owner) error {
	if o == nil {
		return nil
	}
	var err error
	for i := 0; i < 100; i++ {
		if err = o.cleanup(); err == nil {
			return nil
		}
		if dnsCleanupError(err) {
			return err
		}
		time.Sleep(20 * time.Millisecond)
	}
	return err
}
func Run(socket, directory string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("tun_permission_required")
	}
	gui, err := ipc.ConnectIPC(socket, parentcheck.ParentPID)
	if err != nil {
		return err
	}
	defer gui.Close()
	credentials, err := peer(gui)
	if err != nil {
		return err
	}
	return (&session{gui: gui, credentials: credentials, directory: directory,
		enabled: true, phase: "idle"}).run()
}
