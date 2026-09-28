//go:build linux

package tunsession

import (
	"ThroneCore/gen"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

func credentialsNamespace(t *testing.T) {
	t.Helper()
	if os.Getenv("THRONIUM_CREDENTIALS_NAMESPACE") != "1" {
		t.Skip("private credentials namespace required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("namespace root required")
	}
	for _, kind := range []string{"net", "mnt", "user"} {
		current, err := os.Readlink("/proc/self/ns/" + kind)
		if err != nil || current == os.Getenv("THRONIUM_HOST_"+strings.ToUpper(kind)) {
			t.Fatal("host namespace forbidden")
		}
	}
	var st unix.Statfs_t
	if unix.Statfs("/run", &st) != nil || st.Type != unix.TMPFS_MAGIC {
		t.Fatal("private tmpfs /run required")
	}
}
func readyCredentialsSession(t *testing.T, s *session) string {
	t.Helper()
	ours, peer := net.Pipe()
	defer ours.Close()
	defer peer.Close()
	s.gui = ours
	done := make(chan error, 1)
	go func() { done <- s.request(frame{id: 9, method: "ManagedTunReady", payload: []byte{8, 1}}) }()
	var header [9]byte
	if _, err := io.ReadFull(peer, header[:]); err != nil {
		t.Fatal("Ready frame missing")
	}
	payload := make([]byte, int(binary.LittleEndian.Uint32(header[5:])))
	if _, err := io.ReadFull(peer, payload); err != nil {
		t.Fatal("Ready body missing")
	}
	if err := <-done; err != nil {
		t.Fatal("Ready failed")
	}
	var response gen.ErrorResp
	if proto.Unmarshal(payload, &response) != nil {
		t.Fatal("Ready response malformed")
	}
	return response.GetError()
}
func TestManagedCredentialsNamespaceReadyReapsJournalWithoutWorker(t *testing.T) {
	credentialsNamespace(t)
	o, err := newOwner()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/sleep", "30")
	if command.Start() != nil {
		t.Fatal("owned child failed")
	}
	done := make(chan struct{})
	go func() { _ = command.Wait(); close(done) }()
	defer func() { _ = command.Process.Kill(); <-done }()
	start, err := processStart(command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	j := &journal{Version: 1, Table: 100001, WorkerPID: command.Process.Pid, WorkerStart: start}
	if o.write(j) != nil {
		t.Fatal("journal write failed")
	}
	_ = o.lease.Close()
	s := &session{phase: "idle"}
	if code := readyCredentialsSession(t, s); code != "" {
		t.Fatal("Ready refused recoverable orphan")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Ready returned before owned reap")
	}
	if s.worker != nil || s.owner != nil || s.generation != 0 || s.desired != nil {
		t.Fatal("Ready created session")
	}
	if _, err := os.Stat(o.path); !os.IsNotExist(err) {
		t.Fatal("Ready left journal")
	}
	lease, err := net.Listen("unix", "\x00thronium-tun-18900")
	if err != nil {
		t.Fatal("Ready left lease")
	}
	lease.Close()
	t.Log("owned orphan reaped; journal removed; Ready has no worker, generation, or desired")
}
func TestManagedCredentialsNamespaceReadyFailureKeepsJournal(t *testing.T) {
	credentialsNamespace(t)
	o, err := newOwner()
	if err != nil {
		t.Fatal(err)
	}
	o.lease.Close()
	if os.WriteFile(o.path, []byte("invalid journal"), 0600) != nil {
		t.Fatal("write")
	}
	defer os.Remove(o.path)
	s := &session{phase: "idle"}
	if readyCredentialsSession(t, s) == "" {
		t.Fatal("Ready accepted untrusted journal")
	}
	raw, _ := os.ReadFile(o.path)
	if string(raw) != "invalid journal" || s.worker != nil || s.desired != nil {
		t.Fatal("Ready failure changed journal or spawned")
	}
}
func TestManagedCredentialsNamespaceStartupEOFAndDeadline(t *testing.T) {
	credentialsNamespace(t)
	for _, mode := range []string{"eof", "deadline", "already-expired", "already-gone"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			script := filepath.Join(root, "child")
			pidfile := filepath.Join(root, "owned-pid")
			source := fmt.Sprintf("#!/bin/sh\necho $$ > '%s'\nexec /bin/sleep 30\n", pidfile)
			if os.WriteFile(script, []byte(source), 0700) != nil {
				t.Fatal("script")
			}
			gone := make(chan struct{})
			deadline := time.Now().Add(time.Second)
			if mode == "deadline" {
				deadline = time.Now().Add(35 * time.Millisecond)
			}
			if mode == "already-expired" {
				deadline = time.Now().Add(-time.Second)
			}
			if mode == "already-gone" {
				close(gone)
			}
			if mode == "eof" {
				go func() { time.Sleep(35 * time.Millisecond); close(gone) }()
			}
			start := time.Now()
			worker, err := startWorkerExecutableUntil(script, &unix.Ucred{Uid: 0, Gid: 0}, root, gone, deadline)
			if err == nil || worker != nil || time.Since(start) > time.Second {
				t.Fatal("startup cancellation unbounded or accepted")
			}
			raw, readErr := os.ReadFile(pidfile)
			if strings.HasPrefix(mode, "already-") {
				if !os.IsNotExist(readErr) {
					t.Fatal("child launched past gate")
				}
				return
			}
			if readErr != nil {
				t.Fatal("child never entered accept phase")
			}
			pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
			if err != nil {
				t.Fatal("pid")
			}
			if _, err = os.Stat(fmt.Sprintf("/proc/%d", pid)); !os.IsNotExist(err) {
				t.Fatal("cancelled startup left child")
			}
		})
	}
}

// The namespace test process hosts a real session. Its re-executed worker must
// become the adjacent pinned Core, never run the Go test harness as a Core.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "--thronium-tun-worker" {
		executable, err := os.Executable()
		if err != nil {
			os.Exit(91)
		}
		core := filepath.Join(filepath.Dir(executable), "ThroniumCore")
		if unix.Exec(core, []string{core, "--thronium-tun-worker"}, os.Environ()) != nil {
			os.Exit(92)
		}
	}
	os.Exit(m.Run())
}
func credentialsNamespaceFixture(t *testing.T) json.RawMessage {
	t.Helper()
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("private fixture directory")
	}
	copyFile := func(source, name string) {
		raw, err := os.ReadFile(source)
		if err != nil {
			t.Fatal("fixture source missing")
		}
		if os.WriteFile(filepath.Join(root, name), raw, 0700) != nil {
			t.Fatal("fixture copy failed")
		}
	}
	copyFile(os.Getenv("THRONIUM_TEST_PYTHON"), "Thronium")
	if os.Link(os.Getenv("THRONIUM_TEST_CORE"), filepath.Join(root, "ThroniumCore")) != nil {
		t.Fatal("private Core link")
	}
	for _, name := range []string{"vpn_credentials_fixture.py", "vpn_otp_fixture.py", "vpn_auth_fixture.py"} {
		copyFile(filepath.Join(os.Getenv("THRONIUM_TEST_FIXTURES"), name), name)
	}
	command := exec.Command(filepath.Join(root, "Thronium"), filepath.Join(root, "vpn_credentials_fixture.py"), root)
	command.Env = append(os.Environ(), "PYTHONHOME="+os.Getenv("THRONIUM_TEST_PYTHONHOME"))
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal("fixture stdin")
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal("fixture stdout")
	}
	log, err := os.Create(filepath.Join(root, "fixture.log"))
	if err != nil {
		t.Fatal("fixture log")
	}
	command.Stderr = log
	if command.Start() != nil {
		t.Fatal("fixture start")
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		input.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error("owned fixture did not exit zero")
			}
		case <-time.After(12 * time.Second):
			command.Process.Kill()
			<-done
			t.Error("owned fixture shutdown timeout")
		}
		log.Close()
	})
	ready := make(chan map[string]json.RawMessage, 1)
	go func() {
		var result map[string]json.RawMessage
		_ = json.NewDecoder(output).Decode(&result)
		ready <- result
	}()
	select {
	case result := <-ready:
		if result["openvpn"] == nil {
			t.Fatal("fixture ready missing")
		}
		return result["openvpn"]
	case <-time.After(15 * time.Second):
		t.Fatal("fixture ready timeout")
	}
	return nil
}

type credentialsStageConn struct {
	net.Conn
	method   string
	query    int
	bytes    int
	expected int
	target   string
	gone     chan struct{}
	fired    bool
}

func (c *credentialsStageConn) Write(p []byte) (int, error) {
	if len(p) >= 6 {
		n := int(binary.LittleEndian.Uint16(p[4:6]))
		if len(p) >= 6+n {
			c.method = string(p[6 : 6+n])
			c.bytes = 0
			c.expected = 0
			if c.method == "QueryVPNStatus" {
				c.query++
			}
		}
	}
	return c.Conn.Write(p)
}
func (c *credentialsStageConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.bytes == 0 && n >= 9 {
		c.expected = 9 + int(binary.LittleEndian.Uint32(p[5:9]))
	}
	c.bytes += n
	if c.expected > 0 && c.bytes >= c.expected && !c.fired {
		hit := c.target == "after-check" && c.method == "CheckConfig" || c.target == "after-query1" && c.method == "QueryVPNStatus" && c.query == 1 || c.target == "after-query2" && c.method == "QueryVPNStatus" && c.query == 2
		if hit {
			c.fired = true
			close(c.gone)
		}
	}
	return n, err
}
func TestManagedCredentialsNamespaceActualStagesAndRollback(t *testing.T) {
	credentialsNamespace(t)
	ip := func(args ...string) {
		t.Helper()
		if exec.Command("ip", args...).Run() != nil {
			t.Fatal("namespace network setup")
		}
	}
	ip("link", "add", "credentials-phy", "type", "dummy")
	ip("address", "add", "198.18.0.1/24", "dev", "credentials-phy")
	ip("link", "set", "credentials-phy", "up")
	ip("route", "add", "default", "via", "198.18.0.254", "dev", "credentials-phy")
	defer exec.Command("ip", "link", "del", "credentials-phy").Run()
	endpoint := credentialsNamespaceFixture(t)
	for _, mode := range []string{"after-query1", "after-check", "after-query2", "after-retire", "after-candidate-start", "actual-rollback", "after-rollback-start"} {
		t.Run(mode, func(t *testing.T) {
			reserve, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal("port reservation")
			}
			address := reserve.Addr().String()
			port := reserve.Addr().(*net.TCPAddr).Port
			reserve.Close()
			config := fmt.Sprintf(`{"log":{"disabled":true},"endpoints":[%s],"inbounds":[{"type":"tun","tag":"thronium-tun","interface_name":"thronium-tun","address":["172.19.0.1/30"],"stack":"gvisor","auto_route":true,"strict_route":false,"dns_mode":"disabled","iproute2_rule_index":18900,"route_exclude_address":["127.0.0.0/8"]},{"type":"mixed","tag":"control","listen":"127.0.0.1","listen_port":%d}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`, endpoint, port)
			payload := vpnBytes(t, &gen.LoadConfigReq{CoreConfig: proto.String(config), DisableStats: proto.Bool(true), NeedXray: proto.Bool(false)})
			gone := make(chan struct{})
			s := &session{credentials: &unix.Ucred{Uid: 0, Gid: 0}, directory: t.TempDir(), gone: gone, phase: "idle", enabled: true}
			t.Cleanup(func() {
				if s.stop() != nil {
					t.Error("namespace cleanup failed")
				}
			})
			response, err := s.start(1, payload)
			if err != nil || !startSucceeded(response) {
				t.Fatal("actual initial managed Start failed")
			}
			s.desired = append([]byte(nil), payload...)
			end := time.Now().Add(12 * time.Second)
			terminal := false
			for time.Now().Before(end) {
				terminal, err = (credentialsOperation{s, end}).terminal(s.worker, 1)
				if err != nil {
					t.Fatal("actual VPN Query failed")
				}
				if terminal {
					break
				}
				time.Sleep(25 * time.Millisecond)
			}
			if !terminal {
				t.Fatal("fixture did not reach actual terminal authFailed")
			}
			oldWorker := s.worker
			oldPID := oldWorker.cmd.Process.Pid
			old := append([]byte(nil), s.desired...)
			journalPath := s.owner.path
			if strings.HasPrefix(mode, "after-query") || mode == "after-check" {
				s.worker.conn = &credentialsStageConn{Conn: s.worker.conn, target: mode, gone: gone}
			}
			starts, retired := 0, 0
			steps := credentialsSteps{retire: func() error {
				retired++
				err := s.retireCredentialsWorker()
				if mode == "after-retire" && retired == 1 {
					close(gone)
				}
				return err
			}, start: func(id uint32, payload []byte, op credentialsOperation) error {
				starts++
				var occupied net.Listener
				if strings.Contains(mode, "rollback") && starts == 1 {
					occupied, err = net.Listen("tcp", address)
					if err != nil {
						t.Fatal("could not occupy stopped old listener")
					}
				}
				result := s.startCredentialsWorker(id, payload, op)
				if occupied != nil {
					occupied.Close()
					if result == nil {
						t.Fatal("actual occupied-port candidate unexpectedly started")
					}
				}
				if mode == "after-candidate-start" && starts == 1 {
					if result != nil {
						t.Fatal("actual candidate did not Start before EOF")
					}
					close(gone)
				}
				if mode == "after-rollback-start" && starts == 2 {
					if result != nil {
						t.Fatal("actual rollback did not Start before EOF")
					}
					close(gone)
				}
				return result
			}}
			request := credentialsRequest(1)
			request.Username = proto.String(" credentials-fixture-new-user ")
			request.Password = proto.String(" credentials-fixture-new-password-31 ")
			outcome := s.replaceCredentials(1, vpnBytes(t, request), time.Now().Add(10*time.Second), steps)
			switch mode {
			case "after-query1", "after-check", "after-query2":
				credentialsSafeResponse(t, outcome, gen.ManagedVPNReplaceCredentialsOutcome_CREDENTIALS_REJECTED, 1, "managed_vpn_credentials_deadline_exceeded")
				if s.worker != oldWorker || retired != 0 || starts != 0 || !bytes.Equal(s.desired, old) {
					t.Fatal("local EOF preflight changed original worker")
				}
			case "actual-rollback":
				credentialsSafeResponse(t, outcome, gen.ManagedVPNReplaceCredentialsOutcome_CREDENTIALS_RESTORED, 3, "managed_vpn_credentials_restart_failed")
				if starts != 2 || !bytes.Equal(s.desired, old) || s.worker == nil || s.worker.cmd.Process.Pid == oldPID {
					t.Fatal("actual rollback source or worker mismatch")
				}
				end := time.Now().Add(12 * time.Second)
				terminal = false
				for time.Now().Before(end) {
					terminal, err = (credentialsOperation{s, end}).terminal(s.worker, 1)
					if err != nil {
						t.Fatal("rollback Query failed")
					}
					if terminal {
						break
					}
					time.Sleep(25 * time.Millisecond)
				}
				if !terminal {
					t.Fatal("old credentials not observed terminal after actual rollback")
				}
			default:
				generation := uint64(2)
				if mode == "after-rollback-start" {
					generation = 3
				}
				credentialsSafeResponse(t, outcome, gen.ManagedVPNReplaceCredentialsOutcome_CREDENTIALS_FAILED, generation, "managed_vpn_credentials_deadline_exceeded")
				if s.worker != nil || s.desired != nil || s.effective != nil || !s.retryAt.IsZero() {
					t.Fatal("EOF left candidate or retry")
				}
			}
			if s.stop() != nil {
				t.Fatal("final stage cleanup failed")
			}
			if _, err := os.Stat(journalPath); !os.IsNotExist(err) {
				t.Fatal("stage left journal")
			}
			lease, err := net.Listen("unix", "\x00thronium-tun-18900")
			if err != nil {
				t.Fatal("stage left lease")
			}
			lease.Close()
			if _, err := os.Stat(fmt.Sprintf("/proc/%d", oldPID)); !os.IsNotExist(err) {
				t.Fatal("stage left old owned worker")
			}
			t.Log("actual terminal fixture, real worker stage, exact owned journal/lease cleanup")
		})
	}
}

func TestManagedCredentialsNamespaceCleanupFailureCannotExitZero(t *testing.T) {
	credentialsNamespace(t)
	o, err := newOwner()
	if err != nil {
		t.Fatal("owner")
	}
	o.active = &journal{Version: 1, Table: 100001}
	if o.write(o.active) != nil {
		t.Fatal("journal")
	}
	if exec.Command("ip", "link", "add", Interface, "type", "dummy").Run() != nil {
		t.Fatal("namespace cleanup obstruction")
	}
	defer exec.Command("ip", "link", "del", Interface).Run()
	ours, peer := net.Pipe()
	defer ours.Close()
	s := &session{owner: o, gui: ours, phase: "connected"}
	go peer.Close()
	if s.run() == nil || !s.cleanupUncertain {
		t.Fatal("failed real cleanup produced clean exit")
	}
	if _, err := os.Stat(o.path); err != nil {
		t.Fatal("failed cleanup lost journal")
	}
	if s.stop() == nil {
		t.Fatal("owner nil erased cleanup uncertainty")
	}
	blocked := &session{phase: "idle"}
	if readyCredentialsSession(t, blocked) == "" || blocked.worker != nil {
		t.Fatal("Ready bypassed blocked journal")
	}
	if exec.Command("ip", "link", "del", Interface).Run() != nil {
		t.Fatal("remove owned obstruction")
	}
	recovered := &session{phase: "idle"}
	if readyCredentialsSession(t, recovered) != "" || recovered.worker != nil {
		t.Fatal("explicit Ready failed after obstruction resolved")
	}
	if _, err := os.Stat(o.path); !os.IsNotExist(err) {
		t.Fatal("recovered Ready left journal")
	}
	t.Log("actual cleanup refusal retained journal and nonzero obligation; explicit Ready recovered after resolution without worker")
}
