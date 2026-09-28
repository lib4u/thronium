package winservice

import (
	"ThroneCore/gen"
	"errors"
	"io"
	"log"
	"time"

	"google.golang.org/protobuf/proto"
)

const (
	maxRetries       = 3
	stableConnection = 30 * time.Second
	exchangeTimeout  = 25 * time.Second
	watchdogTimeout  = 3 * time.Second
	watchdogPeriod   = 5 * time.Second
)

// worker is one core the service started as SYSTEM for this session.
type worker interface {
	// exchange sends one request and returns the whole response frame.
	exchange(f request, timeout time.Duration) ([]byte, error)
	exited() <-chan struct{}
	identity() (pid uint32, created uint64)
	close()
}

// host is what a session needs from the machine: a worker, the journal and
// the system DNS reset. The Windows service and the tests provide it.
type host interface {
	startWorker(gone <-chan struct{}) (worker, error)
	// writeJournal records j; a nil j means nothing is left to undo.
	writeJournal(j *journal) error
	restoreDNS() error
}

// session serves one application connection. It answers the managed calls
// itself, keeps the connection alive across worker losses when asked to, and
// relays everything else to the worker.
type session struct {
	gui    io.ReadWriter
	host   host
	gone   <-chan struct{}
	worker worker
	// enabled is automatic reconnection, as the application last set it.
	enabled bool
	// The exact successful Start request, in memory only: it holds secrets.
	desired     []byte
	effective   []byte
	dnsDesired  bool
	dnsSet      bool
	phase       string
	failure     string
	attempts    uint32
	generation  uint64
	connectedAt time.Time
	retryAt     time.Time
	// Sticky: once the network could not be restored, no new session starts.
	cleanupUncertain bool
	now              func() time.Time
}

func newSession(gui io.ReadWriter, h host) *session {
	return &session{gui: gui, host: h, enabled: true, phase: "idle", now: time.Now}
}

func (s *session) write(id uint32, status byte, data []byte) error {
	_, err := s.gui.Write(encodeResponse(response{id, status, data}))
	return err
}

func (s *session) reply(id uint32, message string) error {
	result := &gen.ErrorResp{}
	if message != "" {
		result.Error = proto.String(message)
	}
	data, _ := proto.Marshal(result)
	return s.write(id, 0, data)
}

func succeeded(frame []byte) bool {
	if len(frame) < 9 || frame[4] != 0 {
		return false
	}
	var result gen.ErrorResp
	return proto.Unmarshal(frame[9:], &result) == nil && result.GetError() == ""
}

// stopWorker ends the worker and undoes what it changed. It reports whether
// the network is back to how it was.
func (s *session) stopWorker() bool {
	if s.worker != nil {
		s.worker.close()
		s.worker = nil
	}
	clean := true
	if s.dnsSet {
		if err := s.host.restoreDNS(); err != nil {
			log.Print("TUN service could not restore system DNS: ", err)
			clean = false
		} else {
			s.dnsSet = false
		}
	}
	if clean {
		if err := s.host.writeJournal(nil); err != nil {
			clean = false
		}
	}
	if !clean {
		s.cleanupUncertain = true
	}
	return clean
}

func (s *session) stop() error {
	// Cancel intent first: neither a late worker exit nor a timer may start
	// the session again after a disconnect or the application leaving.
	s.desired = nil
	s.effective = nil
	s.dnsDesired = false
	s.retryAt = time.Time{}
	s.attempts = 0
	s.phase = "idle"
	s.failure = ""
	if !s.stopWorker() || s.cleanupUncertain {
		return errors.New("tun_recovery_failed")
	}
	return nil
}

func (s *session) exhausted(code string) {
	s.desired = nil
	s.retryAt = time.Time{}
	s.phase = "failed"
	s.failure = code
	if s.cleanupUncertain {
		s.failure = "tun_recovery_failed"
	}
	log.Print("TUN automatic recovery stopped: ", s.failure)
}

func (s *session) workerLost() {
	s.effective = nil
	now := s.now()
	if s.phase == "connected" && now.Sub(s.connectedAt) >= stableConnection {
		s.attempts = 0
	}
	if !s.stopWorker() {
		s.exhausted("tun_recovery_failed")
		return
	}
	switch {
	case s.desired == nil:
		return
	case !s.enabled:
		s.exhausted("core_disconnected")
	case s.attempts >= maxRetries:
		s.exhausted("tun_reconnect_failed")
	default:
		s.phase = "reconnecting"
		s.failure = ""
		s.retryAt = now.Add(time.Second << s.attempts)
		log.Printf("TUN worker stopped; reconnect attempt %d scheduled", s.attempts+1)
	}
}

func (s *session) ensureWorker() error {
	if s.worker != nil {
		return nil
	}
	w, err := s.host.startWorker(s.gone)
	if err != nil {
		return err
	}
	s.worker = w
	return s.journal()
}

func (s *session) journal() error {
	if s.worker == nil {
		return s.host.writeJournal(nil)
	}
	pid, created := s.worker.identity()
	return s.host.writeJournal(&journal{Version: journalVersion, WorkerPID: pid, WorkerCreated: created, SystemDNS: s.dnsSet})
}

func (s *session) exchange(f request) ([]byte, error) {
	if err := s.ensureWorker(); err != nil {
		return nil, err
	}
	timeout := exchangeTimeout
	if f.method == "QueryConnections" {
		timeout = watchdogTimeout
	}
	return s.worker.exchange(f, timeout)
}

// setDNS asks the worker to point the default interface at its DNS server,
// or to put it back, and journals the change before it can happen.
func (s *session) setDNS(id uint32, set bool) ([]byte, error) {
	if set {
		s.dnsSet = true
		if err := s.journal(); err != nil {
			return nil, err
		}
	}
	payload, _ := proto.Marshal(&gen.SetSystemDNSRequest{Clear: proto.Bool(!set)})
	frame, err := s.exchange(request{id, "SetSystemDNS", payload})
	if err == nil && !set && len(frame) >= 9 && frame[4] == 0 {
		s.dnsSet = false
		err = s.journal()
	}
	return frame, err
}

func (s *session) start(id uint32, payload []byte) ([]byte, error) {
	if s.generation == ^uint64(0) {
		return nil, errors.New("tun_reconnect_failed")
	}
	var config gen.LoadConfigReq
	if proto.Unmarshal(payload, &config) != nil {
		return nil, errors.New("invalid_configuration")
	}
	if err := checkConfig(&config); err != nil {
		return nil, err
	}
	// The application asks for the system DNS in the request, as on Linux.
	switch config.GetManagedTunDnsMode() {
	case "":
	case "interface":
		s.dnsDesired = true
	default:
		return nil, errors.New("invalid_tun_system_dns")
	}
	response, err := s.exchange(request{id, "Start", payload})
	if err != nil || !succeeded(response) {
		return response, err
	}
	if s.dnsDesired {
		frame, err := s.setDNS(0, true)
		if err != nil || len(frame) < 9 || frame[4] != 0 {
			return nil, errors.New("tun_system_dns_failed")
		}
	}
	s.phase = "connected"
	s.failure = ""
	s.retryAt = time.Time{}
	s.generation++
	s.connectedAt = s.now()
	s.effective = append([]byte(nil), payload...)
	return response, nil
}

func (s *session) retry() {
	s.retryAt = time.Time{}
	s.attempts++
	response, err := s.start(0, s.desired)
	if err != nil || !succeeded(response) {
		s.workerLost()
		return
	}
	log.Printf("TUN connection restored on attempt %d", s.attempts)
}

func (s *session) status(id uint32) error {
	attempt := s.attempts
	if s.phase == "reconnecting" {
		attempt++
	}
	// No VPN hosts or credential exchange on Windows: their versions stay 0.
	data, _ := proto.Marshal(&gen.ManagedTunStatus{
		Phase: proto.String(s.phase), Attempt: proto.Uint32(attempt), Generation: proto.Uint64(s.generation),
		Error: proto.String(s.failure), VpnAuthVersion: proto.Uint32(0), VpnCredentialsVersion: proto.Uint32(0),
		SystemDnsVersion: proto.Uint32(SystemDNSVersion)})
	return s.write(id, 0, data)
}

// SystemDNSVersion tells the application the service sets the system DNS.
const SystemDNSVersion = 1

func (s *session) disconnected(id uint32) error {
	message := "core_disconnected"
	if s.phase == "reconnecting" {
		message = "tun_reconnecting"
	}
	return s.write(id, 1, []byte(message))
}

func (s *session) request(f request) error {
	switch f.method {
	case "ManagedTunStatus":
		return s.status(f.id)
	case "ManagedTunConfiguration":
		if s.phase != "connected" || s.effective == nil {
			return s.write(f.id, 1, []byte("active_configuration_unavailable"))
		}
		return s.write(f.id, 0, s.effective)
	case "ManagedTunReady":
		var options gen.ManagedTunOptions
		if proto.Unmarshal(f.payload, &options) != nil {
			return s.reply(f.id, "invalid_tun_settings")
		}
		s.enabled = options.GetAutoReconnect()
		if s.cleanupUncertain {
			return s.reply(f.id, "tun_recovery_failed")
		}
		return s.reply(f.id, "")
	case "ManagedVPN", "ManagedVPNReplaceCredentials":
		return s.write(f.id, 1, []byte("managed_vpn_unavailable"))
	case "Stop":
		if err := s.stop(); err != nil {
			s.phase = "failed"
			s.failure = err.Error()
			return s.reply(f.id, s.failure)
		}
		return s.reply(f.id, "")
	case "Start":
		if s.cleanupUncertain {
			return s.reply(f.id, "tun_recovery_failed")
		}
		if s.desired != nil {
			return s.reply(f.id, "tun_session_active")
		}
		s.attempts = 0
		s.failure = ""
		response, err := s.start(f.id, f.payload)
		if err != nil || !succeeded(response) {
			_ = s.stop()
			if err != nil {
				return s.reply(f.id, err.Error())
			}
		} else {
			s.desired = append([]byte(nil), f.payload...)
		}
		_, err = s.gui.Write(response)
		return err
	case "SetSystemDNS":
		var in gen.SetSystemDNSRequest
		if proto.Unmarshal(f.payload, &in) != nil || in.Clear == nil {
			return s.write(f.id, 1, []byte("invalid_tun_system_dns"))
		}
		if s.phase != "connected" {
			if in.GetClear() && !s.dnsSet {
				s.dnsDesired = false
				return s.write(f.id, 0, nil)
			}
			return s.disconnected(f.id)
		}
		s.dnsDesired = !in.GetClear()
		response, err := s.setDNS(f.id, s.dnsDesired)
		if err != nil {
			s.workerLost()
			return s.disconnected(f.id)
		}
		_, err = s.gui.Write(response)
		return err
	case "CheckConfig", "GenWgKeyPair":
		// Valid while disconnected or waiting for a retry too.
		if f.method == "CheckConfig" {
			var config gen.LoadConfigReq
			if proto.Unmarshal(f.payload, &config) != nil {
				return s.write(f.id, 1, []byte("invalid_configuration"))
			}
			if err := checkConfig(&config); err != nil {
				return s.write(f.id, 1, []byte(err.Error()))
			}
		}
	case "QueryStats", "QueryConnections", "CloseConnections", "QueryAutoSelectors", "AutoSelectorAction",
		"StartEndpointProbe", "QueryEndpointProbe", "CancelEndpointProbe":
		if s.phase != "connected" {
			return s.disconnected(f.id)
		}
	default:
		return s.write(f.id, 1, []byte("unsupported managed method"))
	}
	response, err := s.exchange(f)
	if err != nil {
		s.workerLost()
		return s.disconnected(f.id)
	}
	_, err = s.gui.Write(response)
	return err
}

// run serves the connection until the application closes it, then stops the
// session. The error says the network could not be restored.
func (s *session) run() (result error) {
	requests := make(chan request)
	gone := make(chan struct{})
	done := make(chan struct{})
	s.gone = gone
	defer close(done)
	go func() {
		defer close(gone)
		for {
			f, err := readRequest(s.gui)
			if err != nil {
				return
			}
			select {
			case requests <- f:
			case <-done:
				return
			}
		}
	}()
	defer func() {
		if err := s.stop(); err != nil {
			log.Print("TUN service kept its journal: the network was not restored")
			result = err
		}
	}()
	// Independent of the application's polling, which stops with the window.
	watchdog := time.NewTicker(watchdogPeriod)
	defer watchdog.Stop()
	for {
		var exited <-chan struct{}
		if s.worker != nil {
			exited = s.worker.exited()
		}
		var retry <-chan time.Time
		var timer *time.Timer
		if !s.retryAt.IsZero() {
			timer = time.NewTimer(s.retryAt.Sub(s.now()))
			retry = timer.C
		}
		var f request
		action := 0
		select {
		case f = <-requests:
		case <-gone:
			action = 1
		case <-exited:
			action = 2
		case <-retry:
			action = 3
		case <-watchdog.C:
			action = 4
		}
		if timer != nil {
			timer.Stop()
		}
		select {
		case <-gone:
			return nil
		default:
		}
		switch action {
		case 1:
			return nil
		case 2:
			s.workerLost()
		case 3:
			s.retry()
		case 4:
			if s.phase == "connected" {
				if _, err := s.exchange(request{method: "QueryConnections"}); err != nil {
					s.workerLost()
				}
			}
		default:
			if err := s.request(f); err != nil {
				return err
			}
		}
	}
}
