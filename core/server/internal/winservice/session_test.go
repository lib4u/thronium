package winservice

import (
	"ThroneCore/gen"
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

type fakeWorker struct {
	h        *fakeHost
	pid      uint32
	gone     chan struct{}
	once     sync.Once
	requests []string
}

func (w *fakeWorker) exchange(f request, _ time.Duration) ([]byte, error) {
	w.h.mu.Lock()
	defer w.h.mu.Unlock()
	select {
	case <-w.gone:
		return nil, errors.New("worker gone")
	default:
	}
	w.requests = append(w.requests, f.method)
	w.h.log = append(w.h.log, f.method)
	if f.method == "Start" && w.h.startError != "" {
		data, _ := proto.Marshal(&gen.ErrorResp{Error: proto.String(w.h.startError)})
		return encodeResponse(response{f.id, 0, data}), nil
	}
	if f.method == "SetSystemDNS" {
		var in gen.SetSystemDNSRequest
		_ = proto.Unmarshal(f.payload, &in)
		w.h.systemDNS = !in.GetClear()
	}
	data, _ := proto.Marshal(&gen.ErrorResp{})
	return encodeResponse(response{f.id, 0, data}), nil
}
func (w *fakeWorker) exited() <-chan struct{}    { return w.gone }
func (w *fakeWorker) identity() (uint32, uint64) { return w.pid, 99 }
func (w *fakeWorker) close()                     { w.once.Do(func() { close(w.gone) }) }
func (w *fakeWorker) crash()                     { w.close() }

type fakeHost struct {
	mu         sync.Mutex
	workers    []*fakeWorker
	journal    *journal
	journals   int
	systemDNS  bool
	restores   int
	startError string
	failStart  bool
	log        []string
}

func (h *fakeHost) startWorker(<-chan struct{}) (worker, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failStart {
		return nil, errors.New("tun_service_worker_failed")
	}
	w := &fakeWorker{h: h, pid: uint32(100 + len(h.workers)), gone: make(chan struct{})}
	h.workers = append(h.workers, w)
	return w, nil
}
func (h *fakeHost) writeJournal(j *journal) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.journals++
	if j != nil {
		copy := *j
		j = &copy
	}
	h.journal = j
	return nil
}
func (h *fakeHost) restoreDNS() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.restores++
	h.systemDNS = false
	return nil
}
func (h *fakeHost) state() (journal *journal, dns bool, workers int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.journal, h.systemDNS, len(h.workers)
}

type client struct {
	t    *testing.T
	conn net.Conn
	id   uint32
}

func (c *client) call(method string, message proto.Message) response {
	c.t.Helper()
	c.id++
	payload, _ := proto.Marshal(message)
	if _, err := c.conn.Write(encodeRequest(request{c.id, method, payload})); err != nil {
		c.t.Fatal(err)
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	r, err := readResponse(c.conn)
	if err != nil || r.id != c.id {
		c.t.Fatal(method, r, err)
	}
	return r
}

func (c *client) errorText(method string, message proto.Message) string {
	c.t.Helper()
	r := c.call(method, message)
	if r.status != 0 {
		return string(r.data)
	}
	var result gen.ErrorResp
	if proto.Unmarshal(r.data, &result) != nil {
		c.t.Fatal(method, r)
	}
	return result.GetError()
}

func (c *client) status() *gen.ManagedTunStatus {
	c.t.Helper()
	var status gen.ManagedTunStatus
	if r := c.call("ManagedTunStatus", &gen.EmptyReq{}); r.status != 0 || proto.Unmarshal(r.data, &status) != nil {
		c.t.Fatal(r)
	}
	return &status
}

func serve(t *testing.T, h *fakeHost) (*client, chan error) {
	app, service := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- newSession(service, h).run() }()
	t.Cleanup(func() { app.Close() })
	return &client{t: t, conn: app}, done
}

var config = &gen.LoadConfigReq{CoreConfig: proto.String(`{"inbounds":[{"type":"tun"}]}`)}

func eventually(t *testing.T, check func() bool) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if check() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

func TestServiceSessionStartsJournalsAndUndoesEverythingWhenTheApplicationLeaves(t *testing.T) {
	h := &fakeHost{}
	c, done := serve(t, h)
	if status := c.status(); status.GetPhase() != "idle" || status.GetSystemDnsVersion() != SystemDNSVersion ||
		status.GetVpnAuthVersion() != 0 || status.GetVpnCredentialsVersion() != 0 {
		t.Fatal(status)
	}
	if text := c.errorText("ManagedTunReady", &gen.ManagedTunOptions{AutoReconnect: proto.Bool(true)}); text != "" {
		t.Fatal(text)
	}
	if text := c.errorText("QueryStats", &gen.EmptyReq{}); text != "core_disconnected" {
		t.Fatal(text)
	}
	if text := c.errorText("Start", config); text != "" {
		t.Fatal(text)
	}
	if status := c.status(); status.GetPhase() != "connected" || status.GetGeneration() != 1 {
		t.Fatal(status)
	}
	if r := c.call("ManagedTunConfiguration", &gen.EmptyReq{}); r.status != 0 || !bytes.Equal(r.data, mustMarshal(config)) {
		t.Fatal(r)
	}
	if text := c.errorText("Start", config); text != "tun_session_active" {
		t.Fatal(text)
	}
	if r := c.call("SetSystemDNS", &gen.SetSystemDNSRequest{Clear: proto.Bool(false)}); r.status != 0 {
		t.Fatal(r)
	}
	j, dns, workers := h.state()
	if j == nil || !j.SystemDNS || j.WorkerPID != 100 || !dns || workers != 1 {
		t.Fatal(j, dns, workers)
	}
	if r := c.call("ManagedVPN", &gen.EmptyReq{}); r.status != 1 || string(r.data) != "managed_vpn_unavailable" {
		t.Fatal(r)
	}
	c.conn.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	j, dns, _ = h.state()
	if j != nil || dns || h.restores != 1 {
		t.Fatal(j, dns, h.restores)
	}
}

func TestServiceSessionRefusesUnsafeConfigurationsBeforeStartingAWorker(t *testing.T) {
	h := &fakeHost{}
	c, _ := serve(t, h)
	unsafe := &gen.LoadConfigReq{CoreConfig: proto.String(`{"log":{"output":"C:\\Windows\\x"}}`)}
	if text := c.errorText("Start", unsafe); text != "tun_service_write_path_unsupported" {
		t.Fatal(text)
	}
	if text := c.errorText("CheckConfig", &gen.LoadConfigReq{NeedExtraProcess: proto.Bool(true)}); text != "tun_service_external_core_unsupported" {
		t.Fatal(text)
	}
	if _, _, workers := h.state(); workers != 0 {
		t.Fatal(workers)
	}
	if text := c.errorText("Frobnicate", &gen.EmptyReq{}); text != "unsupported managed method" {
		t.Fatal(text)
	}
}

func TestServiceSessionReportsAFailedStartAndLeavesNothingBehind(t *testing.T) {
	h := &fakeHost{startError: "port in use"}
	c, _ := serve(t, h)
	if text := c.errorText("Start", config); text != "port in use" {
		t.Fatal(text)
	}
	if status := c.status(); status.GetPhase() != "idle" {
		t.Fatal(status)
	}
	if j, _, _ := h.state(); j != nil || !h.workers[0].closed() {
		t.Fatal(j)
	}
	h.failStart = true
	if text := c.errorText("Start", config); text != "tun_service_worker_failed" {
		t.Fatal(text)
	}
}

func (w *fakeWorker) closed() bool {
	select {
	case <-w.gone:
		return true
	default:
		return false
	}
}

func TestServiceSessionReconnectsALostWorkerAndSetsDNSAgain(t *testing.T) {
	h := &fakeHost{}
	c, _ := serve(t, h)
	if text := c.errorText("Start", config); text != "" {
		t.Fatal(text)
	}
	if r := c.call("SetSystemDNS", &gen.SetSystemDNSRequest{Clear: proto.Bool(false)}); r.status != 0 {
		t.Fatal(r)
	}
	h.workers[0].crash()
	eventually(t, func() bool { return c.status().GetPhase() == "reconnecting" })
	if _, dns, _ := h.state(); dns || h.restores != 1 {
		t.Fatal("DNS stayed set with the worker gone")
	}
	if text := c.errorText("QueryStats", &gen.EmptyReq{}); text != "tun_reconnecting" {
		t.Fatal(text)
	}
	eventually(t, func() bool { return c.status().GetPhase() == "connected" })
	j, dns, workers := h.state()
	if workers != 2 || !dns || j == nil || !j.SystemDNS || j.WorkerPID != 101 || c.status().GetGeneration() != 2 {
		t.Fatal(j, dns, workers)
	}
	if text := c.errorText("Stop", &gen.EmptyReq{}); text != "" {
		t.Fatal(text)
	}
	if j, dns, _ := h.state(); j != nil || dns {
		t.Fatal(j, dns)
	}
}

func TestServiceSessionWithoutReconnectionFailsOnceTheWorkerIsLost(t *testing.T) {
	h := &fakeHost{}
	c, _ := serve(t, h)
	c.errorText("ManagedTunReady", &gen.ManagedTunOptions{AutoReconnect: proto.Bool(false)})
	if text := c.errorText("Start", config); text != "" {
		t.Fatal(text)
	}
	h.workers[0].crash()
	eventually(t, func() bool { return c.status().GetPhase() == "failed" })
	if status := c.status(); status.GetError() != "core_disconnected" {
		t.Fatal(status)
	}
	if text := c.errorText("SetSystemDNS", &gen.SetSystemDNSRequest{Clear: proto.Bool(true)}); text != "" {
		t.Fatal(text)
	}
	if text := c.errorText("Start", config); text != "" {
		t.Fatal(text)
	}
}

func mustMarshal(m proto.Message) []byte {
	data, _ := proto.Marshal(m)
	return data
}

func TestServiceSessionSetsTheSystemDNSTheStartRequestAsksFor(t *testing.T) {
	h := &fakeHost{}
	c, done := serve(t, h)
	withDNS := &gen.LoadConfigReq{CoreConfig: config.CoreConfig, ManagedTunDnsMode: proto.String("interface")}
	if text := c.errorText("Start", withDNS); text != "" {
		t.Fatal(text)
	}
	if j, dns, _ := h.state(); j == nil || !j.SystemDNS || !dns {
		t.Fatal(j, dns)
	}
	c.errorText("Stop", &gen.EmptyReq{})
	if j, dns, _ := h.state(); j != nil || dns {
		t.Fatal(j, dns)
	}
	linux := &gen.LoadConfigReq{CoreConfig: config.CoreConfig, ManagedTunDnsMode: proto.String("resolved")}
	if text := c.errorText("Start", linux); text != "invalid_tun_system_dns" {
		t.Fatal(text)
	}
	c.conn.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
