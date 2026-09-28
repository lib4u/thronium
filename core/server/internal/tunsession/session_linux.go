//go:build linux

package tunsession

import (
	"ThroneCore/gen"
	"ThroneCore/internal/tundns"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

const maxRetries = 3
const stableConnection = 30 * time.Second

type session struct {
	networkDNS  networkDNSWatch
	resolvconf  *tundns.OpenResolv
	dnsClient   *tundns.DBusClient
	dnsClose    func()
	gui         net.Conn
	credentials *unix.Ucred
	directory   string
	gone        <-chan struct{}
	worker      *workerProcess
	owner       *owner
	enabled     bool
	// Keep the exact successful request in memory only. It contains credentials.
	desired     []byte
	effective   []byte
	phase       string
	failure     string
	attempts    uint32
	generation  uint64
	connectedAt time.Time
	retryAt     time.Time
	// Sticky: a lost journal owner must never later produce a clean exit zero.
	cleanupUncertain bool
}

func wireReply(conn net.Conn, id uint32, status byte, data []byte) error {
	header := make([]byte, 9)
	binary.LittleEndian.PutUint32(header, id)
	header[4] = status
	binary.LittleEndian.PutUint32(header[5:], uint32(len(data)))
	_, err := conn.Write(append(header, data...))
	return err
}

func (s *session) stopWorker() {
	s.networkDNS = networkDNSWatch{}
	s.closeDNS()
	if s.worker != nil {
		s.worker.close()
		s.worker = nil
	}
}
func (s *session) stop() error {
	// Cancel intent before cleanup: neither a late worker exit nor a timer may
	// restart a session after an explicit disconnect or application shutdown.
	s.desired = nil
	s.effective = nil
	s.retryAt = time.Time{}
	s.attempts = 0
	s.phase = "idle"
	s.failure = ""
	s.stopWorker()
	err := cleanup(s.owner)
	s.owner = nil
	if err != nil {
		s.cleanupUncertain = true
	}
	if s.cleanupUncertain {
		return fmt.Errorf("tun_recovery_failed")
	}
	return nil
}
func (s *session) exhausted(errorCode string) {
	s.desired = nil
	s.retryAt = time.Time{}
	s.phase = "failed"
	s.failure = errorCode
	if err := cleanup(s.owner); err != nil {
		s.failure = "tun_recovery_failed"
		s.cleanupUncertain = true
	}
	s.owner = nil
	log.Print("TUN automatic recovery stopped: ", s.failure)
}
func (s *session) workerLost(now time.Time) {
	s.effective = nil
	if s.phase == "connected" && now.Sub(s.connectedAt) >= stableConnection {
		s.attempts = 0
	}
	s.stopWorker()
	// Retain the namespace lease during backoff, but remove the dead worker's
	// network rules before permitting a new Start.
	if err := cleanNetwork(s.owner); err != nil {
		s.exhausted("tun_recovery_failed")
		return
	}
	if s.desired == nil {
		return
	}
	if !s.enabled {
		s.exhausted("core_disconnected")
		return
	}
	if s.attempts >= maxRetries {
		s.exhausted("tun_reconnect_failed")
		return
	}
	s.phase = "reconnecting"
	s.failure = ""
	s.retryAt = now.Add(time.Second << s.attempts)
	log.Printf("TUN worker stopped; reconnect attempt %d scheduled", s.attempts+1)
}

func (s *session) exchange(f frame) ([]byte, error) {
	if s.worker == nil {
		var err error
		s.worker, err = startWorkerExecutableUntil("/proc/self/exe", s.credentials, s.directory, s.gone, time.Now().Add(8*time.Second), s.pinSystemResolver())
		if err != nil {
			return nil, err
		}
	}
	timeout := 25 * time.Second
	if f.method == "QueryConnections" {
		timeout = 3 * time.Second
	}
	return exchangeExisting(s.worker, f, timeout)
}

// Existing-worker transport only. This helper cannot acquire or launch a child.
func exchangeExisting(worker *workerProcess, f frame, timeout time.Duration) ([]byte, error) {
	if worker == nil || worker.conn == nil {
		return nil, fmt.Errorf("worker unavailable")
	}
	if err := worker.conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if err := writeFrame(worker.conn, f); err != nil {
		return nil, err
	}
	var header [9]byte
	if _, err := io.ReadFull(worker.conn, header[:]); err != nil {
		return nil, err
	}
	length := binary.LittleEndian.Uint32(header[5:])
	if length > maxFrame || binary.LittleEndian.Uint32(header[:]) != f.id {
		return nil, fmt.Errorf("invalid worker response")
	}
	data := make([]byte, 9+int(length))
	copy(data, header[:])
	_, err := io.ReadFull(worker.conn, data[9:])
	return data, err
}

func startSucceeded(response []byte) bool {
	if len(response) < 9 || response[4] != 0 {
		return false
	}
	var result gen.ErrorResp
	return proto.Unmarshal(response[9:], &result) == nil && result.GetError() == ""
}

func (s *session) start(id uint32, payload []byte) ([]byte, error) {
	// Refuse before any side effects; generation zero is never a wildcard.
	if s.generation == ^uint64(0) {
		return nil, fmt.Errorf("tun_reconnect_failed")
	}
	var err error
	if s.owner == nil {
		s.owner, err = newOwner()
		if err != nil {
			return nil, err
		}
	}
	prepared, err := s.owner.prepare(payload)
	if err != nil {
		return nil, err
	}
	// CheckConfig can leave an idle worker created before DNS mode was known.
	// Every openresolv Start needs a fresh pre-TUN view, including updated DHCP.
	if s.worker != nil && s.pinSystemResolver() {
		s.stopWorker()
	}
	if err = s.prepareNetworkDNS(); err != nil {
		return nil, err
	}
	if s.worker == nil {
		s.worker, err = startWorkerExecutableUntil("/proc/self/exe", s.credentials, s.directory, s.gone, time.Now().Add(8*time.Second), s.pinSystemResolver())
		if err != nil {
			return nil, err
		}
	}
	s.owner.active.WorkerPID = s.worker.cmd.Process.Pid
	s.owner.active.WorkerStart, err = processStart(s.worker.cmd.Process.Pid)
	if err != nil {
		return nil, err
	}
	if err = s.owner.write(s.owner.active); err != nil {
		return nil, err
	}
	response, err := s.exchange(frame{id, "Start", prepared})
	if err == nil && startSucceeded(response) {
		if err = s.activateDNS(); err != nil {
			return nil, err
		}
		s.phase = "connected"
		s.failure = ""
		s.retryAt = time.Time{}
		s.generation++
		s.connectedAt = time.Now()
		s.effective = append([]byte(nil), prepared...)
	}
	return response, err
}

func (s *session) retry() {
	s.retryAt = time.Time{}
	s.attempts++
	response, err := s.start(0, s.desired)
	if err != nil || !startSucceeded(response) {
		s.workerLost(time.Now())
		return
	}
	log.Printf("TUN connection restored on attempt %d", s.attempts)
}

func (s *session) status(id uint32) error {
	attempt := s.attempts
	if s.phase == "reconnecting" {
		attempt++
	}
	response := &gen.ManagedTunStatus{Phase: proto.String(s.phase), Attempt: proto.Uint32(attempt), Generation: proto.Uint64(s.generation), Error: proto.String(s.failure), VpnAuthVersion: proto.Uint32(managedVPNVersion), VpnCredentialsVersion: proto.Uint32(managedCredentialsVersion), SystemDnsVersion: proto.Uint32(systemDNSVersion)}
	data, _ := proto.Marshal(response)
	return wireReply(s.gui, id, 0, data)
}

func (s *session) request(f frame) error {
	switch f.method {
	case "ManagedVPNReplaceCredentials":
		data, _ := proto.Marshal(s.managedCredentials(f.id, f.payload))
		return wireReply(s.gui, f.id, 0, data)
	case "ManagedVPN":
		data, _ := proto.Marshal(s.managedVPN(f.id, f.payload))
		return wireReply(s.gui, f.id, 0, data)
	case "ManagedTunStatus":
		return s.status(f.id)
	case "ManagedTunConfiguration":
		// An explicit authenticated GUI request, never part of periodic status.
		if s.phase != "connected" || s.effective == nil {
			return wireReply(s.gui, f.id, 1, []byte("active_configuration_unavailable"))
		}
		return wireReply(s.gui, f.id, 0, s.effective)
	case "ManagedTunReady":
		var options gen.ManagedTunOptions
		if proto.Unmarshal(f.payload, &options) != nil {
			return reply(s.gui, f.id, "invalid_tun_settings")
		}
		s.enabled = options.GetAutoReconnect()
		if s.owner == nil {
			check, err := newOwner()
			if err != nil {
				return reply(s.gui, f.id, err.Error())
			}
			check.lease.Close()
		}
		return reply(s.gui, f.id, "")
	case "Stop":
		if err := s.stop(); err != nil {
			s.phase = "failed"
			s.failure = "tun_recovery_failed"
			return reply(s.gui, f.id, s.failure)
		}
		return reply(s.gui, f.id, "")
	case "Start":
		if s.cleanupUncertain {
			return reply(s.gui, f.id, "tun_recovery_failed")
		}
		if s.desired != nil {
			return reply(s.gui, f.id, "tun_session_active")
		}
		s.attempts = 0
		s.failure = ""
		response, err := s.start(f.id, f.payload)
		if err != nil || !startSucceeded(response) {
			_ = s.stop()
			if err != nil {
				return reply(s.gui, f.id, err.Error())
			}
		} else {
			s.desired = append([]byte(nil), f.payload...)
		}
		_, err = s.gui.Write(response)
		return err
	case "CheckConfig", "GenWgKeyPair":
		// These operations are also valid while disconnected or awaiting a retry.
	case "QueryStats", "QueryConnections", "CloseConnections", "QueryAutoSelectors", "AutoSelectorAction", "StartEndpointProbe", "QueryEndpointProbe", "CancelEndpointProbe":
		if s.phase != "connected" {
			message := "core_disconnected"
			if s.phase == "reconnecting" {
				message = "tun_reconnecting"
			}
			return wireReply(s.gui, f.id, 1, []byte(message))
		}
	default:
		return wireReply(s.gui, f.id, 1, []byte("unsupported managed method"))
	}
	response, err := s.exchange(f)
	if err != nil {
		s.workerLost(time.Now())
		message := "core_disconnected"
		if s.phase == "reconnecting" {
			message = "tun_reconnecting"
		}
		return wireReply(s.gui, f.id, 1, []byte(message))
	}
	_, err = s.gui.Write(response)
	return err
}

func (s *session) run() (result error) {
	requests := make(chan frame)
	gone := make(chan struct{})
	stop := make(chan struct{})
	s.gone = gone
	defer close(stop)
	go func() {
		defer close(gone)
		for {
			f, err := readFrame(s.gui)
			if err != nil {
				return
			}
			select {
			case requests <- f:
			case <-stop:
				return
			}
		}
	}()
	defer func() {
		if err := s.stop(); err != nil {
			log.Print("TUN recovery retained its journal")
			result = fmt.Errorf("tun_recovery_failed")
		}
	}()
	// Keep the watchdog independent of WebView polling, which can stop when
	// the window is hidden. QueryConnections is read-only and has a 3s deadline.
	watchdog := time.NewTicker(5 * time.Second)
	defer watchdog.Stop()
	for {
		var exited <-chan struct{}
		if s.worker != nil {
			exited = s.worker.exited
		}
		var retry <-chan time.Time
		var timer *time.Timer
		if !s.retryAt.IsZero() {
			timer = time.NewTimer(time.Until(s.retryAt))
			retry = timer.C
		}
		var f frame
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
		// A queued timer never takes precedence over a closed GUI connection.
		select {
		case <-gone:
			return nil
		default:
		}
		switch action {
		case 1:
			return nil
		case 2:
			s.workerLost(time.Now())
		case 3:
			s.retry()
		case 4:
			if s.phase == "connected" {
				if !s.dnsCurrent() {
					log.Print("TUN system DNS no longer matches the active request")
					s.workerLost(time.Now())
					continue
				}
				if s.networkDNSChanged(time.Now()) {
					s.workerLost(time.Now())
					continue
				}
				if _, err := s.exchange(frame{method: "QueryConnections"}); err != nil {
					s.workerLost(time.Now())
				}
			}
		default:
			if err := s.request(f); err != nil {
				return err
			}
		}
	}
}
