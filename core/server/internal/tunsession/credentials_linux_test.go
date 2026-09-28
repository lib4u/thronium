//go:build linux

package tunsession

import (
	"ThroneCore/gen"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

func credentialsRequest(g uint64) *gen.ManagedVPNReplaceCredentialsRequest {
	return &gen.ManagedVPNReplaceCredentialsRequest{Version: proto.Uint32(1), Generation: proto.Uint64(g), EndpointTag: proto.String("proxy"), Username: proto.String(" next user "), Password: proto.String(" next password ")}
}
func credentialsPayload(t *testing.T, config string) []byte {
	return vpnBytes(t, &gen.LoadConfigReq{CoreConfig: proto.String(config), DisableStats: proto.Bool(true), XrayConfig: proto.String(`{"unchanged":9007199254740993}`), TunIpv4Cidr: proto.String("172.19.0.1/30")})
}

const credentialsConfig = `{"endpoints":[{"tag":"proxy","type":"openvpn-client","username":"old user","password":"old password","unknown":{"integer":9007199254740993,"huge":18446744073709551615,"decimal":1.2300e+45}},{"tag":"other","type":"openconnect","username":"other","password":"preserved"}],"routing":{"unknown":9007199254740995}}`

func credentialsSession(t *testing.T) (*session, net.Conn, *countedVPNConn) {
	worker, peer, counted := testVPNWorker(t)
	s := liveVPN(worker, 7)
	s.owner = &owner{active: &journal{}}
	s.desired = credentialsPayload(t, credentialsConfig)
	s.effective = credentialsPayload(t, strings.Replace(credentialsConfig, `"routing":`, `"preparedMarker":true,"routing":`, 1))
	return s, peer, counted
}
func credentialsSafeResponse(t *testing.T, r *gen.ManagedVPNReplaceCredentialsResponse, outcome gen.ManagedVPNReplaceCredentialsOutcome, generation uint64, code string) {
	t.Helper()
	if r.Version == nil || r.PreviousGeneration == nil || r.Generation == nil || r.Outcome == nil || r.ErrorCode == nil || r.GetVersion() != 1 || r.GetGeneration() != generation || r.GetOutcome() != outcome || r.GetErrorCode() != code {
		t.Fatalf("outcome mismatch: version=%d, previous=%d, generation=%d, outcome=%d, safeCode=%q", r.GetVersion(), r.GetPreviousGeneration(), r.GetGeneration(), r.GetOutcome(), r.GetErrorCode())
	}
	encoded := vpnBytes(t, r)
	if len(encoded) > maxManagedCredentialsRequest || bytes.Contains(encoded, []byte("password")) || bytes.Contains(encoded, []byte("next user")) {
		t.Fatal("unsafe response")
	}
}
func TestManagedCredentialsStrictScopeBeforeWorkerWrite(t *testing.T) {
	good := vpnBytes(t, credentialsRequest(7))
	cases := map[string][]byte{"unknown": append(append([]byte{}, good...), wireVar(99, 1)...), "duplicate": append(append([]byte{}, good...), wireVar(2, 7)...), "oversize": bytes.Repeat([]byte{0}, maxManagedCredentialsRequest+1), "invalid-utf8": append(append(wireVar(1, 1), wireVar(2, 7)...), append(wireBytes(3, []byte("proxy")), append(wireBytes(4, []byte{255}), wireBytes(5, []byte("p"))...)...)...)}
	for field := 0; field < 5; field++ {
		request := credentialsRequest(7)
		switch field {
		case 0:
			request.Version = nil
		case 1:
			request.Generation = nil
		case 2:
			request.EndpointTag = nil
		case 3:
			request.Username = nil
		case 4:
			request.Password = nil
		}
		cases["missing-"+string(rune('0'+field))] = vpnBytes(t, request)
	}
	for name, mutate := range map[string]func(*gen.ManagedVPNReplaceCredentialsRequest){"empty": func(r *gen.ManagedVPNReplaceCredentialsRequest) {
		r.Username = proto.String("")
		r.Password = proto.String("")
	}, "otp": func(r *gen.ManagedVPNReplaceCredentialsRequest) { r.Password = proto.String("{otp}") }, "nul": func(r *gen.ManagedVPNReplaceCredentialsRequest) { r.Username = proto.String("a\x00b") }, "too-long": func(r *gen.ManagedVPNReplaceCredentialsRequest) {
		r.Password = proto.String(strings.Repeat("ü", 2049))
	}, "wrong-tag": func(r *gen.ManagedVPNReplaceCredentialsRequest) { r.EndpointTag = proto.String("other") }} {
		r := credentialsRequest(7)
		mutate(r)
		cases[name] = vpnBytes(t, r)
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			s, _, writes := credentialsSession(t)
			r := s.managedCredentials(1, payload)
			credentialsSafeResponse(t, r, gen.ManagedVPNReplaceCredentialsOutcome_CREDENTIALS_REJECTED, 7, "managed_vpn_credentials_invalid_request")
			if writes.writes.Load() != 0 || s.generation != 7 || s.desired == nil {
				t.Fatal("validation performed effects")
			}
		})
	}
	for _, g := range []uint64{6, ^uint64(0) - 1, ^uint64(0)} {
		t.Run("generation", func(t *testing.T) {
			s, _, writes := credentialsSession(t)
			request := credentialsRequest(g)
			code := "managed_vpn_credentials_stale"
			if g > 7 {
				s.generation = g
				code = "managed_vpn_credentials_generation_exhausted"
			}
			r := s.managedCredentials(1, vpnBytes(t, request))
			credentialsSafeResponse(t, r, gen.ManagedVPNReplaceCredentialsOutcome_CREDENTIALS_REJECTED, s.generation, code)
			if writes.writes.Load() != 0 {
				t.Fatal("generation check wrote")
			}
		})
	}
}
func TestManagedCredentialsPatchPreservesOpaqueFieldsAndNumbers(t *testing.T) {
	original := credentialsPayload(t, credentialsConfig)
	original = append(original, wireVar(90, 9007199254740993)...)
	patched, err := patchCredentials(original, " next user ", " next password ")
	if err != nil {
		t.Fatal("patch failed")
	}
	var before, after gen.LoadConfigReq
	_ = proto.Unmarshal(original, &before)
	_ = proto.Unmarshal(patched, &after)
	for _, needle := range []string{"9007199254740993", "18446744073709551615", "1.2300e+45", "9007199254740995"} {
		if !strings.Contains(after.GetCoreConfig(), needle) {
			t.Fatal("numeric lexeme lost")
		}
	}
	var parsed map[string]json.RawMessage
	_ = json.Unmarshal([]byte(after.GetCoreConfig()), &parsed)
	var endpoints []map[string]json.RawMessage
	_ = json.Unmarshal(parsed["endpoints"], &endpoints)
	if credentialsString(endpoints[0]["username"]) != " next user " || credentialsString(endpoints[0]["password"]) != " next password " || credentialsString(endpoints[1]["password"]) != "preserved" {
		t.Fatal("credential equality mismatch")
	}
	after.CoreConfig = before.CoreConfig
	if !proto.Equal(&before, &after) {
		t.Fatal("non-config fields changed")
	}
	for _, config := range []string{`{"endpoints":[{"tag":"proxy","type":"openconnect","cookie":"saved"}]}`, `{"endpoints":[{"tag":"proxy","type":"openconnect","token":"saved"}]}`, `{"endpoints":[{"tag":"proxy","type":"openconnect","form_entries":{"p":"saved"}}]}`, `{"endpoints":[{"tag":"proxy","type":"openconnect","password_authentication_disabled":true}]}`, `{"endpoints":[{"tag":"proxy","type":"socks"}]}`, `{"endpoints":[{"tag":"proxy","type":"openvpn-client"},{"tag":"proxy","type":"openvpn-client"}]}`, `{"endpoints":[{"tag":"other","tag":"proxy","type":"openvpn-client"}]}`, `{"endpoints":[],"endpoints":[]}`} {
		if _, err := patchCredentials(credentialsPayload(t, config), "u", "p"); err == nil {
			t.Fatal("unsupported config accepted")
		}
	}
}

type credentialsReply struct {
	method  string
	message proto.Message
}

func serveCredentials(t *testing.T, peer net.Conn, replies []credentialsReply) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		for _, expected := range replies {
			f, err := readFrame(peer)
			if err != nil {
				done <- errors.New("request failed")
				return
			}
			if f.method != expected.method {
				done <- errors.New("method mismatch")
				return
			}
			data, err := proto.Marshal(expected.message)
			if err != nil {
				done <- err
				return
			}
			if err = wireReply(peer, f.id, 0, data); err != nil {
				done <- errors.New("reply failed")
				return
			}
		}
		done <- nil
	}()
	return done
}
func credentialsTerminal() *gen.VPNStatusResponse {
	return &gen.VPNStatusResponse{Results: []*gen.VPNEndpointStatus{{Tag: proto.String("proxy"), State: proto.String("error"), AuthFailed: proto.Bool(true)}}}
}
func credentialsPreflight() []credentialsReply {
	return []credentialsReply{{"QueryVPNStatus", credentialsTerminal()}, {"CheckConfig", &gen.ErrorResp{}}, {"QueryVPNStatus", credentialsTerminal()}}
}
func TestManagedCredentialsCutoverOutcomesAndExactRollback(t *testing.T) {
	for _, mode := range []string{"applied", "restored", "failed", "cleanup-failed", "eof-before-candidate", "eof-after-candidate", "expired-before-candidate"} {
		t.Run(mode, func(t *testing.T) {
			s, peer, _ := credentialsSession(t)
			old := append([]byte(nil), s.desired...)
			gone := make(chan struct{})
			s.gone = gone
			done := serveCredentials(t, peer, credentialsPreflight())
			starts, retired := 0, 0
			deadline := time.Now().Add(time.Second)
			steps := credentialsSteps{retire: func() error {
				retired++
				s.effective = nil
				if retired == 1 {
					if mode == "cleanup-failed" {
						return errors.New("secret sentinel")
					}
					if mode == "eof-before-candidate" {
						close(gone)
					}
					if mode == "expired-before-candidate" {
						time.Sleep(30 * time.Millisecond)
					}
				}
				return nil
			}, start: func(_ uint32, payload []byte, op credentialsOperation) error {
				starts++
				if starts == 1 {
					if s.generation != 8 {
						t.Fatal("candidate slot wrong")
					}
					expected, _ := patchCredentials(old, " next user ", " next password ")
					if !bytes.Equal(payload, expected) {
						t.Fatal("candidate source mismatch")
					}
					if mode == "eof-after-candidate" {
						close(gone)
					}
					if mode == "restored" || mode == "failed" {
						return errors.New("secret sentinel")
					}
				} else {
					if s.generation != 9 || !bytes.Equal(payload, old) {
						t.Fatal("rollback was rebuilt")
					}
					if mode == "failed" {
						return errors.New("secret sentinel")
					}
				}
				s.effective = append([]byte(nil), payload...)
				s.phase = "connected"
				return nil
			}}
			if mode == "expired-before-candidate" {
				deadline = time.Now().Add(20 * time.Millisecond)
			}
			r := s.replaceCredentials(1, vpnBytes(t, credentialsRequest(7)), deadline, steps)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "applied":
				credentialsSafeResponse(t, r, gen.ManagedVPNReplaceCredentialsOutcome_CREDENTIALS_APPLIED, 8, "")
				if starts != 1 || s.desired == nil || s.phase != "connected" {
					t.Fatal("candidate not committed")
				}
			case "restored":
				credentialsSafeResponse(t, r, gen.ManagedVPNReplaceCredentialsOutcome_CREDENTIALS_RESTORED, 9, "managed_vpn_credentials_restart_failed")
				if starts != 2 || !bytes.Equal(s.desired, old) {
					t.Fatal("old source not restored")
				}
			default:
				code := "managed_vpn_credentials_restart_failed"
				generation := uint64(9)
				if strings.HasPrefix(mode, "eof-") || strings.HasPrefix(mode, "expired-") {
					code = "managed_vpn_credentials_deadline_exceeded"
					generation = 8
					if mode == "eof-after-candidate" {
						generation = 8
					}
				}
				if mode == "cleanup-failed" {
					code = "managed_vpn_credentials_cleanup_failed"
					generation = 8
				}
				credentialsSafeResponse(t, r, gen.ManagedVPNReplaceCredentialsOutcome_CREDENTIALS_FAILED, generation, code)
				if s.desired != nil || s.effective != nil || !s.retryAt.IsZero() || s.phase != "failed" {
					t.Fatal("failed candidate retained retry intent")
				}
				if mode == "cleanup-failed" && (!s.cleanupUncertain || s.failure != "tun_recovery_failed") {
					t.Fatal("cleanup uncertainty lost")
				}
			}
		})
	}
}
func TestManagedCredentialsPreflightRefusalDoesNotStop(t *testing.T) {
	for _, mode := range []string{"check-refusal", "became-connected", "became-challenge", "xray-refusal"} {
		t.Run(mode, func(t *testing.T) {
			s, peer, _ := credentialsSession(t)
			old := append([]byte(nil), s.desired...)
			replies := credentialsPreflight()
			if mode == "check-refusal" {
				replies = replies[:2]
				replies[1].message = &gen.ErrorResp{Error: proto.String("secret sentinel")}
			}
			if mode == "xray-refusal" {
				var effective gen.LoadConfigReq
				_ = proto.Unmarshal(s.effective, &effective)
				effective.NeedXray = proto.Bool(true)
				s.effective = vpnBytes(t, &effective)
				replies = replies[:2]
				replies = append(replies, credentialsReply{"CheckConfig", &gen.ErrorResp{Error: proto.String("secret sentinel")}})
			}
			if mode == "became-connected" {
				replies[2].message = &gen.VPNStatusResponse{Results: []*gen.VPNEndpointStatus{{Tag: proto.String("proxy"), State: proto.String("connected"), Connected: proto.Bool(true)}}}
			}
			if mode == "became-challenge" {
				status := credentialsTerminal()
				status.Results[0].Challenge = &gen.VPNChallenge{Id: proto.String("pending")}
				replies[2].message = status
			}
			done := serveCredentials(t, peer, replies)
			steps := credentialsSteps{retire: func() error { t.Fatal("preflight retired worker"); return nil }, start: func(uint32, []byte, credentialsOperation) error { t.Fatal("preflight started worker"); return nil }}
			r := s.replaceCredentials(1, vpnBytes(t, credentialsRequest(7)), time.Now().Add(time.Second), steps)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			code := "managed_vpn_credentials_unavailable"
			if strings.HasSuffix(mode, "refusal") {
				code = "managed_vpn_credentials_check_failed"
			}
			credentialsSafeResponse(t, r, gen.ManagedVPNReplaceCredentialsOutcome_CREDENTIALS_REJECTED, 7, code)
			if !bytes.Equal(s.desired, old) || s.phase != "connected" {
				t.Fatal("rejected preflight changed source")
			}
		})
	}
}
func TestManagedCredentialsExpiredBeforeQueryDoesNotWriteOrRetire(t *testing.T) {
	s, _, writes := credentialsSession(t)
	worker := s.worker
	old := append([]byte(nil), s.desired...)
	steps := credentialsSteps{retire: func() error { t.Fatal("local expiry retired worker"); return nil }, start: func(uint32, []byte, credentialsOperation) error { t.Fatal("local expiry started worker"); return nil }}
	r := s.replaceCredentials(1, vpnBytes(t, credentialsRequest(7)), time.Now().Add(-time.Second), steps)
	credentialsSafeResponse(t, r, gen.ManagedVPNReplaceCredentialsOutcome_CREDENTIALS_REJECTED, 7, "managed_vpn_credentials_deadline_exceeded")
	if writes.writes.Load() != 0 || s.worker != worker || !bytes.Equal(old, s.desired) || s.phase != "connected" || !s.retryAt.IsZero() {
		t.Fatal("expired before Query changed worker")
	}
}
func TestManagedCredentialsFrameBoundBeforeAllocation(t *testing.T) {
	ours, peer := net.Pipe()
	defer ours.Close()
	defer peer.Close()
	done := make(chan error, 1)
	go func() {
		var b bytes.Buffer
		_ = binary.Write(&b, binary.LittleEndian, uint32(1))
		name := "ManagedVPNReplaceCredentials"
		_ = binary.Write(&b, binary.LittleEndian, uint16(len(name)))
		b.WriteString(name)
		_ = binary.Write(&b, binary.LittleEndian, uint32(maxManagedCredentialsRequest+1))
		_, e := peer.Write(b.Bytes())
		done <- e
	}()
	if _, err := readFrame(ours); err == nil {
		t.Fatal("oversized frame accepted")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func TestManagedCredentialsStickyCleanupCannotBecomeExitZero(t *testing.T) {
	s := &session{cleanupUncertain: true, desired: []byte("private")}
	if s.stop() == nil || s.stop() == nil || s.desired != nil {
		t.Fatal("cleanup uncertainty lost")
	}
	ours, peer := net.Pipe()
	s.gui = ours
	go peer.Close()
	if s.run() == nil {
		t.Fatal("deferred cleanup error swallowed")
	}
	ours.Close()
}

type credentialsDelayedRead struct {
	net.Conn
	reads   int
	delayAt int
}

func (c *credentialsDelayedRead) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.reads++
	if c.reads == c.delayAt {
		time.Sleep(30 * time.Millisecond)
	}
	return n, err
}
func TestManagedCredentialsExpiryBetweenPreflightStagesDoesNotRetire(t *testing.T) {
	for _, after := range []int{1, 2} {
		t.Run(string(rune('0'+after)), func(t *testing.T) {
			s, peer, _ := credentialsSession(t)
			s.worker.conn = &credentialsDelayedRead{Conn: s.worker.conn, delayAt: after + 1}
			done := serveCredentials(t, peer, credentialsPreflight()[:after])
			worker := s.worker
			old := append([]byte(nil), s.desired...)
			steps := credentialsSteps{retire: func() error { t.Fatal("local expiry retired worker"); return nil }, start: func(uint32, []byte, credentialsOperation) error { t.Fatal("local expiry started worker"); return nil }}
			r := s.replaceCredentials(1, vpnBytes(t, credentialsRequest(7)), time.Now().Add(20*time.Millisecond), steps)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			credentialsSafeResponse(t, r, gen.ManagedVPNReplaceCredentialsOutcome_CREDENTIALS_REJECTED, 7, "managed_vpn_credentials_deadline_exceeded")
			if s.worker != worker || !bytes.Equal(old, s.desired) || s.phase != "connected" || !s.retryAt.IsZero() {
				t.Fatal("local expiry changed source")
			}
		})
	}
}
