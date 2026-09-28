//go:build windows

package winservice

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tailscale/go-winio"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const (
	// Name is the service the installer registers.
	Name = "ThroniumService"
	// Pipe is where the application reaches it.
	Pipe = `\\.\pipe\thronium-service`
	// SYSTEM and administrators in full, interactive users may connect.
	// go-winio refuses remote clients.
	pipeSecurity = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"
	maxLogSize   = 4 << 20
)

type service struct {
	executable string
	directory  string
	output     io.Writer
	listener   net.Listener
	busy       atomic.Bool
	mu         sync.Mutex
	active     net.Conn
	finished   chan struct{}
	dns        func() error
}

// Run serves as ThroniumService under the service control manager.
// restoreDNS puts back every interface DNS list a core changed.
func Run(restoreDNS func() error) error {
	return svc.Run(Name, &handler{restoreDNS})
}

type handler struct{ restoreDNS func() error }

func (h *handler) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	s, err := open(h.restoreDNS)
	if err != nil {
		log.Print("Thronium service could not start: ", err)
		return true, 1
	}
	go s.serve()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for request := range requests {
		switch request.Cmd {
		case svc.Interrogate:
			changes <- request.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending, WaitHint: 15000}
			s.close()
			return false, 0
		}
	}
	return false, 0
}

// directory is SYSTEM's own local application data: no one else can create
// or replace anything there, unlike a folder under ProgramData.
func directory() (string, error) {
	base, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "Thronium", "tun"), nil
}

func open(restoreDNS func() error) (*service, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	dir, err := directory()
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	logPath := filepath.Join(dir, "service.log")
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if info, err := os.Stat(logPath); err == nil && info.Size() > maxLogSize {
		flags |= os.O_TRUNC
	}
	output, err := os.OpenFile(logPath, flags, 0o600)
	if err != nil {
		return nil, err
	}
	log.SetOutput(output)
	s := &service{executable: executable, directory: dir, output: output, dns: restoreDNS}
	s.recover()
	s.listener, err = winio.ListenPipe(Pipe, &winio.PipeConfig{SecurityDescriptor: pipeSecurity})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// recover undoes what a previous run left when it, or the machine, stopped
// without a clean Stop. The worker died with that run's job; the DNS lists
// it changed did not.
func (s *service) recover() {
	path := s.journalPath()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	j, err := decodeJournal(data)
	if err == nil {
		terminateLeftover(j.WorkerPID, j.WorkerCreated)
	}
	// An unreadable journal may have been written just before a DNS change.
	if err != nil || j.SystemDNS {
		if err := s.dns(); err != nil {
			log.Print("Thronium service could not restore system DNS: ", err)
			return
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Print("Thronium service could not remove its journal: ", err)
		return
	}
	log.Print("Thronium service restored the network after an unclean stop")
}

func (s *service) journalPath() string { return filepath.Join(s.directory, "journal.json") }

func (s *service) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		if err = s.verifyClient(conn); err != nil {
			log.Print("Thronium service refused a client: ", err)
			go refuse(conn, "tun_service_client_refused")
			continue
		}
		if !s.busy.CompareAndSwap(false, true) {
			go refuse(conn, "tun_service_busy")
			continue
		}
		s.mu.Lock()
		s.active = conn
		s.finished = make(chan struct{})
		finished := s.finished
		s.mu.Unlock()
		go func() {
			defer close(finished)
			defer s.busy.Store(false)
			defer conn.Close()
			if err := newSession(conn, s).run(); err != nil {
				log.Print("Thronium service session ended: ", err)
			}
		}()
	}
}

// refuse answers the first request with the reason and closes.
func refuse(conn net.Conn, reason string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	f, err := readRequest(conn)
	if err != nil {
		return
	}
	_, _ = conn.Write(encodeResponse(response{f.id, 1, []byte(reason)}))
}

// verifyClient accepts only the application installed beside this service,
// running in a person's session.
func (s *service) verifyClient(conn net.Conn) error {
	pid, err := clientPID(conn)
	if err != nil {
		return err
	}
	var session uint32
	if err = windows.ProcessIdToSessionId(pid, &session); err != nil || session == 0 {
		return fmt.Errorf("client %d is not in an interactive session", pid)
	}
	image, err := processImage(pid)
	if err != nil {
		return err
	}
	expected := filepath.Join(filepath.Dir(s.executable), "Thronium.exe")
	if !strings.EqualFold(image, expected) {
		return fmt.Errorf("client %q is not %q", image, expected)
	}
	service, serviceErr := publisher(s.executable)
	client, clientErr := publisher(image)
	return samePublisher(service, serviceErr, client, clientErr)
}

func processImage(pid uint32) (string, error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(process)
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buffer))
	if err = windows.QueryFullProcessImageName(process, 0, &buffer[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buffer[:size]), nil
}

func (s *service) close() {
	_ = s.listener.Close()
	s.mu.Lock()
	active, finished := s.active, s.finished
	s.mu.Unlock()
	if active == nil {
		return
	}
	_ = active.Close()
	select {
	case <-finished:
	case <-time.After(12 * time.Second):
		log.Print("Thronium service stopped before its session finished")
	}
}

// host

func (s *service) startWorker(gone <-chan struct{}) (worker, error) {
	w, err := startWorker(s.executable, filepath.Join(s.directory, "worker"), s.output, gone)
	if err != nil {
		return nil, err
	}
	return w, nil
}

func (s *service) writeJournal(j *journal) error {
	path := s.journalPath()
	if j == nil {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	data, err := encodeJournal(j)
	if err != nil {
		return err
	}
	temporary := path + ".new"
	if err = os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func (s *service) restoreDNS() error { return s.dns() }

// VerifyWorkerParent is the worker's check that the process it connected to
// is this service: the same executable, running as SYSTEM.
func VerifyWorkerParent(parent int) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	image, err := processImage(uint32(parent))
	if err != nil {
		return err
	}
	if !strings.EqualFold(image, self) {
		return fmt.Errorf("invalid managed parent %q", image)
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(parent))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err = windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	if !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return errors.New("managed parent is not SYSTEM")
	}
	return nil
}
