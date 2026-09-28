//go:build linux

package tunsession

import (
	"ThroneCore/gen"
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"net"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func vpnBytes(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, e := proto.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func queryRequest(g uint64) *gen.ManagedVPNRequest {
	return &gen.ManagedVPNRequest{Version: proto.Uint32(1), Generation: proto.Uint64(g), Operation: &gen.ManagedVPNRequest_Query{Query: &gen.VPNStatusRequest{EndpointTags: []string{"proxy"}, TimeoutMs: proto.Int32(0)}}}
}
func actionRequest(g uint64, cancel bool) *gen.ManagedVPNRequest {
	r := queryRequest(g)
	a := &gen.SubmitVPNChallengeRequest{EndpointTag: proto.String("proxy"), ChallengeId: proto.String("1")}
	if cancel {
		r.Operation = &gen.ManagedVPNRequest_Cancel{Cancel: a}
	} else {
		r.Operation = &gen.ManagedVPNRequest_Submit{Submit: a}
	}
	return r
}
func wireVar(number protowire.Number, value uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(nil, number, protowire.VarintType), value)
}
func wireBytes(number protowire.Number, value []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(nil, number, protowire.BytesType), value)
}
func envelope(operation protowire.Number, value []byte) []byte {
	return append(append(wireVar(1, 1), wireVar(2, 7)...), wireBytes(operation, value)...)
}

type countedVPNConn struct {
	net.Conn
	writes atomic.Int32
}

func (c *countedVPNConn) Write(b []byte) (int, error) { c.writes.Add(1); return c.Conn.Write(b) }
func testVPNWorker(t *testing.T) (*workerProcess, net.Conn, *countedVPNConn) {
	t.Helper()
	ours, peer := net.Pipe()
	counted := &countedVPNConn{Conn: ours}
	command := exec.Command("/bin/sleep", "30")
	if e := command.Start(); e != nil {
		t.Fatal(e)
	}
	w := &workerProcess{conn: counted, cmd: command, exited: make(chan struct{}), stopWatch: make(chan struct{})}
	go func() { _ = command.Wait(); close(w.exited) }()
	t.Cleanup(func() {
		select {
		case <-w.stopWatch:
		default:
			w.close()
		}
		_ = peer.Close()
	})
	return w, peer, counted
}
func liveVPN(w *workerProcess, g uint64) *session {
	return &session{worker: w, enabled: true, desired: []byte("exact source request"), effective: []byte("exact effective request"), phase: "connected", generation: g, connectedAt: time.Now()}
}
func checkVPNError(t *testing.T, r *gen.ManagedVPNResponse, expected string) {
	t.Helper()
	if r.GetVersion() != 1 || r.GetErrorCode() != expected || r.Result != nil {
		t.Fatalf("safe rejection mismatch: version=%d,code=%q,result-present=%v", r.GetVersion(), r.GetErrorCode(), r.Result != nil)
	}
}

func TestManagedVPNRejectsAmbiguousWireAndInvalidRequestsWithoutSpawn(t *testing.T) {
	good := vpnBytes(t, queryRequest(7))
	plain := func(r *gen.ManagedVPNRequest) []byte { return vpnBytes(t, r) }
	cases := map[string][]byte{
		"malformed": {0xff}, "oversize": bytes.Repeat([]byte{0}, maxManagedVPNRequest+1),
		"unknown":                 append(append([]byte{}, good...), wireVar(99, 1)...),
		"duplicate-version":       append(append([]byte{}, good...), wireVar(1, 1)...),
		"duplicate-operation":     append(append([]byte{}, good...), wireBytes(3, wireBytes(1, []byte("proxy")))...),
		"second-operation":        append(append([]byte{}, good...), wireBytes(5, vpnBytes(t, actionRequest(7, true).GetCancel()))...),
		"version-overflow":        append(append(wireVar(1, 1<<32|1), wireVar(2, 7)...), wireBytes(3, wireBytes(1, []byte("proxy")))...),
		"overlong-varint":         append([]byte{8, 0x81, 0}, good[2:]...),
		"wrong-wire":              append(append(wireBytes(1, []byte{1}), wireVar(2, 7)...), wireBytes(3, wireBytes(1, []byte("proxy")))...),
		"nested-unknown":          envelope(3, append(wireBytes(1, []byte("proxy")), wireVar(99, 1)...)),
		"query-duplicate-timeout": envelope(3, append(append(wireBytes(1, []byte("proxy")), wireVar(2, 0)...), wireVar(2, 0)...)),
		"invalid-utf8":            envelope(3, wireBytes(1, []byte{0xff})),
		"timeout-overflow":        envelope(3, append(wireBytes(1, []byte("proxy")), wireVar(2, 1<<32)...)),
	}
	r := queryRequest(0)
	cases["zero-generation"] = plain(r)
	r = queryRequest(7)
	r.Operation = nil
	cases["no-operation"] = plain(r)
	for _, value := range []int32{-1, 1, 3000} {
		r = queryRequest(7)
		r.GetQuery().TimeoutMs = proto.Int32(value)
		cases["long-poll-"+time.Duration(value).String()] = plain(r)
	}
	for name, tags := range map[string][]string{"empty-tags": {}, "empty-tag": {""}, "control": {"bad\n"}, "long-tag": {strings.Repeat("x", 513)}, "duplicate-tags": {"proxy", "proxy"}, "many-tags": make([]string, 129)} {
		r = queryRequest(7)
		r.GetQuery().EndpointTags = tags
		cases[name] = plain(r)
	}
	r = actionRequest(7, true)
	r.GetCancel().Password = proto.String("must-not-forward")
	cases["cancel-with-answer"] = plain(r)
	r = actionRequest(7, false)
	r.GetSubmit().Secret = proto.String("bad\x00")
	cases["nul-answer"] = plain(r)
	r = actionRequest(7, false)
	r.GetSubmit().EndpointTag = proto.String("")
	cases["empty-action-tag"] = plain(r)
	key := append(wireBytes(1, []byte("same")), wireBytes(2, []byte("first"))...)
	action := append(wireBytes(1, []byte("proxy")), wireBytes(2, []byte("1"))...)
	action = append(action, wireBytes(6, key)...)
	action = append(action, wireBytes(6, key)...)
	cases["duplicate-map-key"] = envelope(4, action)
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			s := session{phase: "idle", generation: 7}
			checkVPNError(t, s.managedVPN(9, payload), "managed_vpn_invalid_request")
			if s.worker != nil || s.owner != nil || s.desired != nil || !s.retryAt.IsZero() {
				t.Fatal("invalid request changed lifecycle")
			}
		})
	}
	for _, v := range []uint32{0, 2, math.MaxUint32} {
		r = queryRequest(7)
		r.Version = proto.Uint32(v)
		s := session{generation: 7}
		checkVPNError(t, s.managedVPN(9, plain(r)), "managed_vpn_unsupported_version")
	}
}

func TestManagedVPNWrongGenerationAndInactiveStatesWriteNothing(t *testing.T) {
	w, _, count := testVPNWorker(t)
	s := liveVPN(w, 7)
	for _, generation := range []uint64{1, 6, 8, 1<<53 + 123, math.MaxUint64} {
		checkVPNError(t, s.managedVPN(9, vpnBytes(t, actionRequest(generation, false))), "managed_vpn_stale_generation")
	}
	for _, state := range []string{"idle", "reconnecting", "failed"} {
		s.phase = state
		checkVPNError(t, s.managedVPN(9, vpnBytes(t, queryRequest(7))), "managed_vpn_unavailable")
	}
	s.phase = "connected"
	s.desired = nil
	checkVPNError(t, s.managedVPN(9, vpnBytes(t, queryRequest(7))), "managed_vpn_unavailable")
	s.worker = nil
	s.desired = []byte("original")
	checkVPNError(t, s.managedVPN(9, vpnBytes(t, queryRequest(7))), "managed_vpn_unavailable")
	if count.writes.Load() != 0 || s.worker != nil || !s.retryAt.IsZero() {
		t.Fatal("refused auth wrote or launched a worker")
	}
	if _, err := exchangeExisting(nil, frame{}, time.Millisecond); err == nil {
		t.Fatal("nil existing worker accepted")
	}
}

func TestManagedVPNForwardsTypedOperationsAndExactPrivateValues(t *testing.T) {
	for _, operation := range []string{"query", "submit", "cancel"} {
		t.Run(operation, func(t *testing.T) {
			w, peer, count := testVPNWorker(t)
			s := liveVPN(w, 1<<53+123)
			before := append([]byte{}, s.desired...)
			effective := append([]byte{}, s.effective...)
			req := queryRequest(s.generation)
			wantMethod := "QueryVPNStatus"
			var output proto.Message = &gen.VPNStatusResponse{Results: []*gen.VPNEndpointStatus{{Tag: proto.String("proxy"), State: proto.String("auth-pending")}}}
			if operation != "query" {
				req = actionRequest(s.generation, operation == "cancel")
				wantMethod = "SubmitVPNChallenge"
				if operation == "cancel" {
					wantMethod = "CancelVPNChallenge"
				}
				output = &gen.ErrorResp{Error: proto.String("")}
			}
			if operation == "submit" {
				a := req.GetSubmit()
				a.Username = proto.String("Synthetic 日本")
				a.Password = proto.String(" exact \r\n password ")
				a.Secret = proto.String("transient-otp")
				a.FormValues = map[string]string{"key:1": "value 日本", "key:2": "two"}
			}
			observed := make(chan frame, 1)
			done := make(chan error, 1)
			go func() {
				f, e := readFrame(peer)
				if e != nil {
					done <- e
					return
				}
				observed <- f
				done <- wireReply(peer, f.id, 0, vpnBytes(t, output))
			}()
			result := s.managedVPN(42, vpnBytes(t, req))
			if result.GetErrorCode() != "" || result.GetGeneration() != s.generation || result.GetVersion() != 1 {
				t.Fatal("valid guarded request failed")
			}
			f := <-observed
			if f.method != wantMethod || f.id != 42 {
				t.Fatal("wrong worker method/id")
			}
			if operation == "query" {
				if result.GetStatus() == nil || result.GetAction() != nil {
					t.Fatal("wrong result kind")
				}
			} else {
				var actual gen.SubmitVPNChallengeRequest
				if strictVPNDecode(f.payload, &actual) != nil {
					t.Fatal("bad typed action")
				}
				want := req.GetSubmit()
				if operation == "cancel" {
					want = req.GetCancel()
				}
				if !proto.Equal(&actual, want) {
					t.Fatal("action values changed")
				}
				if result.GetAction() == nil || result.GetStatus() != nil {
					t.Fatal("wrong action kind")
				}
			}
			if e := <-done; e != nil {
				t.Fatal(e)
			}
			if count.writes.Load() != 1 || !bytes.Equal(before, s.desired) || !bytes.Equal(effective, s.effective) || s.owner != nil {
				t.Fatal("auth touched persisted/start request")
			}
		})
	}
}

func TestManagedVPNQueryThenNewGenerationRejectsOldActionsBeforeNewWorker(t *testing.T) {
	first, peer, _ := testVPNWorker(t)
	s := liveVPN(first, math.MaxUint64-1)
	go func() {
		f, e := readFrame(peer)
		if e == nil {
			_ = wireReply(peer, f.id, 0, vpnBytes(t, &gen.VPNStatusResponse{Results: []*gen.VPNEndpointStatus{{Tag: proto.String("proxy"), State: proto.String("auth-pending"), Challenge: &gen.VPNChallenge{Id: proto.String("1")}}}}))
		}
	}()
	if s.managedVPN(1, vpnBytes(t, queryRequest(s.generation))).GetStatus() == nil {
		t.Fatal("first query failed")
	}
	next, _, written := testVPNWorker(t)
	s.worker = next
	s.generation = math.MaxUint64
	for _, cancel := range []bool{false, true} {
		r := s.managedVPN(2, vpnBytes(t, actionRequest(math.MaxUint64-1, cancel)))
		checkVPNError(t, r, "managed_vpn_stale_generation")
		if r.GetGeneration() != math.MaxUint64 {
			t.Fatal("u64 generation lost")
		}
	}
	if written.writes.Load() != 0 {
		t.Fatal("old answer was forwarded to replacement")
	}
}

func TestManagedVPNAlreadyExitedWorkerCannotWinQueuedRequest(t *testing.T) {
	w, _, count := testVPNWorker(t)
	s := liveVPN(w, 7)
	_ = w.cmd.Process.Kill()
	<-w.exited
	checkVPNError(t, s.managedVPN(1, vpnBytes(t, actionRequest(7, false))), "managed_vpn_unavailable")
	if count.writes.Load() != 0 || s.worker != nil || s.phase != "reconnecting" || s.retryAt.IsZero() {
		t.Fatal("queued exit was bypassed or retried immediately")
	}
}

func TestManagedVPNBrokenExchangeSchedulesButNeverReplays(t *testing.T) {
	w, peer, count := testVPNWorker(t)
	s := liveVPN(w, 7)
	// Consume the actual action before closing, proving a lost response is not replayed.
	go func() { _, _ = readFrame(peer); _ = peer.Close() }()
	checkVPNError(t, s.managedVPN(1, vpnBytes(t, actionRequest(7, false))), "managed_vpn_exchange_failed")
	if count.writes.Load() != 1 || s.worker != nil || s.phase != "reconnecting" || s.desired == nil || s.effective != nil {
		t.Fatal("lost exchange incorrectly replayed or lost intent")
	}
	deadline := s.retryAt
	checkVPNError(t, s.managedVPN(2, vpnBytes(t, actionRequest(7, false))), "managed_vpn_unavailable")
	if !s.retryAt.Equal(deadline) || s.worker != nil {
		t.Fatal("auth forced backoff retry")
	}
	if err := s.stop(); err != nil {
		t.Fatal(err)
	}
	if s.desired != nil || !s.retryAt.IsZero() {
		t.Fatal("Stop did not cancel pending auth recovery")
	}
}

func TestManagedVPNRejectsMalformedWrongTypeOrUnmatchedWorkerReplies(t *testing.T) {
	for _, kind := range []string{"bad-id", "status-error", "malformed", "wrong-type", "unknown", "empty-query", "unexpected-tag", "duplicate-tag"} {
		t.Run(kind, func(t *testing.T) {
			w, peer, _ := testVPNWorker(t)
			s := liveVPN(w, 7)
			go func() {
				f, e := readFrame(peer)
				if e != nil {
					return
				}
				id := f.id
				status := byte(0)
				body := vpnBytes(t, &gen.VPNStatusResponse{Results: []*gen.VPNEndpointStatus{{Tag: proto.String("proxy")}}})
				switch kind {
				case "bad-id":
					id++
				case "status-error":
					status = 1
					body = []byte("secret raw transport error")
				case "malformed":
					body = []byte{0xff}
				case "wrong-type":
					body = vpnBytes(t, &gen.ErrorResp{Error: proto.String("not status")})
				case "unknown":
					body = wireVar(99, 1)
				case "empty-query":
					body = nil
				case "unexpected-tag":
					body = vpnBytes(t, &gen.VPNStatusResponse{Results: []*gen.VPNEndpointStatus{{Tag: proto.String("other")}}})
				case "duplicate-tag":
					body = vpnBytes(t, &gen.VPNStatusResponse{Results: []*gen.VPNEndpointStatus{{Tag: proto.String("proxy")}, {Tag: proto.String("proxy")}}})
				}
				_ = wireReply(peer, id, status, body)
			}()
			result := s.managedVPN(5, vpnBytes(t, queryRequest(7)))
			checkVPNError(t, result, "managed_vpn_exchange_failed")
			if bytes.Contains(vpnBytes(t, result), []byte("secret")) {
				t.Fatal("raw worker error leaked")
			}
			if s.worker != nil || s.phase != "reconnecting" {
				t.Fatal("bad worker was retained")
			}
		})
	}
}

func TestManagedVPNAnswerBoundsAndCancelDoNotForwardCredentials(t *testing.T) {
	for _, kind := range []string{"field-too-long", "answer-budget", "many-fields", "invalid-key", "cancel-map"} {
		t.Run(kind, func(t *testing.T) {
			r := actionRequest(7, false)
			a := r.GetSubmit()
			a.FormValues = map[string]string{}
			switch kind {
			case "field-too-long":
				a.Password = proto.String(strings.Repeat("x", 4097))
			case "answer-budget":
				for i := 0; i < 17; i++ {
					a.FormValues[strings.Repeat("k", i+1)] = strings.Repeat("v", 4096)
				}
			case "many-fields":
				for i := 0; i < 129; i++ {
					a.FormValues[strings.Repeat("k", i+1)] = ""
				}
			case "invalid-key":
				a.FormValues["bad\n"] = "v"
			case "cancel-map":
				r = actionRequest(7, true)
				r.GetCancel().FormValues = map[string]string{"k": "v"}
			}
			s := session{generation: 7}
			checkVPNError(t, s.managedVPN(1, vpnBytes(t, r)), "managed_vpn_invalid_request")
			if s.worker != nil {
				t.Fatal("invalid action spawned")
			}
		})
	}
}

func TestManagedVPNCapabilityAndUnguardedNames(t *testing.T) {
	for _, method := range []string{"ManagedTunStatus", "QueryVPNStatus", "SubmitVPNChallenge", "CancelVPNChallenge"} {
		t.Run(method, func(t *testing.T) {
			gui, peer := net.Pipe()
			defer gui.Close()
			defer peer.Close()
			s := session{gui: gui, phase: "idle", generation: math.MaxUint64}
			done := make(chan error, 1)
			go func() { done <- s.request(frame{77, method, nil}) }()
			var h [9]byte
			if _, e := io.ReadFull(peer, h[:]); e != nil {
				t.Fatal(e)
			}
			body := make([]byte, binary.LittleEndian.Uint32(h[5:]))
			if _, e := io.ReadFull(peer, body); e != nil {
				t.Fatal(e)
			}
			if e := <-done; e != nil {
				t.Fatal(e)
			}
			if method == "ManagedTunStatus" {
				var status gen.ManagedTunStatus
				if proto.Unmarshal(body, &status) != nil || status.GetVpnAuthVersion() != 1 || status.GetGeneration() != math.MaxUint64 {
					t.Fatal("missing capability or narrowed generation")
				}
			} else if h[4] != 1 || string(body) != "unsupported managed method" {
				t.Fatal("unguarded VPN method was allowed")
			}
			if s.worker != nil || s.owner != nil {
				t.Fatal("read-only capability acquired worker")
			}
		})
	}
}

func TestManagedVPNFrameBoundBeforeAllocationAndGenerationOverflowBeforeStart(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		b := make([]byte, 10+len("ManagedVPN"))
		binary.LittleEndian.PutUint16(b[4:], uint16(len("ManagedVPN")))
		copy(b[6:], "ManagedVPN")
		binary.LittleEndian.PutUint32(b[6+len("ManagedVPN"):], maxManagedVPNRequest+1)
		_, _ = client.Write(b)
	}()
	if _, err := readFrame(server); err == nil {
		t.Fatal("oversize header accepted")
	}
	s := session{generation: math.MaxUint64}
	if _, err := s.start(1, []byte("never parse/acquire")); err == nil {
		t.Fatal("overflow Start accepted")
	}
	if s.owner != nil || s.worker != nil || s.generation != math.MaxUint64 {
		t.Fatal("overflow caused side effects")
	}
}

func TestManagedVPNExistingExchangeDeadlineIsBounded(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		_, _, limit, ok := vpnOperation(actionRequest(7, cancel))
		if !ok || limit != 5*time.Second {
			t.Fatal("action timeout contract changed")
		}
	}
	_, _, limit, ok := vpnOperation(queryRequest(7))
	if !ok || limit != 3*time.Second {
		t.Fatal("query timeout contract changed")
	}
	worker, _, count := testVPNWorker(t)
	start := time.Now()
	if _, err := exchangeExisting(worker, frame{1, "QueryVPNStatus", nil}, 25*time.Millisecond); err == nil {
		t.Fatal("silent peer did not time out")
	}
	if elapsed := time.Since(start); elapsed > time.Second || count.writes.Load() != 1 {
		t.Fatal("existing exchange exceeded bounded deadline")
	}
}
