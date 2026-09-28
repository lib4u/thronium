//go:build linux

package tunsession

import (
	"ThroneCore/gen"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
)

const managedCredentialsVersion = 1
const maxManagedCredentialsRequest = 16 * 1024
const credentialsBudget = 120 * time.Second

var credentialsUnsupported = errors.New("managed_vpn_credentials_configuration_unsupported")
var credentialsExpired = errors.New("managed_vpn_credentials_deadline_exceeded")

// RawMessage keeps every untouched nested number and extension out of float64.
// Duplicate keys at the objects whose fields we interpret are ambiguous.
func credentialsObject(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, credentialsUnsupported
	}
	result := make(map[string]json.RawMessage)
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok {
			return nil, credentialsUnsupported
		}
		if _, exists := result[name]; exists {
			return nil, credentialsUnsupported
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, credentialsUnsupported
		}
		result[name] = value
	}
	if _, err := d.Token(); err != nil {
		return nil, credentialsUnsupported
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, credentialsUnsupported
	}
	return result, nil
}
func credentialsString(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return value
}
func credentialsNonempty(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) != 0 && !bytes.Equal(raw, []byte("null")) && !bytes.Equal(raw, []byte(`""`)) && !bytes.Equal(raw, []byte("[]")) && !bytes.Equal(raw, []byte("{}"))
}
func patchCredentials(payload []byte, username, password string) ([]byte, error) {
	var request gen.LoadConfigReq
	if proto.Unmarshal(payload, &request) != nil || request.CoreConfig == nil || request.GetNeedExtraProcess() {
		return nil, credentialsUnsupported
	}
	config, err := credentialsObject([]byte(request.GetCoreConfig()))
	if err != nil {
		return nil, err
	}
	var endpoints []json.RawMessage
	if json.Unmarshal(config["endpoints"], &endpoints) != nil {
		return nil, credentialsUnsupported
	}
	found := -1
	var primary map[string]json.RawMessage
	for i, endpoint := range endpoints {
		object, err := credentialsObject(endpoint)
		if err != nil {
			return nil, err
		}
		if credentialsString(object["tag"]) == "proxy" {
			if found >= 0 {
				return nil, credentialsUnsupported
			}
			found, primary = i, object
		}
	}
	if found < 0 {
		return nil, credentialsUnsupported
	}
	switch credentialsString(primary["type"]) {
	case "openvpn-client":
	case "openconnect":
		if bytes.Equal(bytes.TrimSpace(primary["password_authentication_disabled"]), []byte("true")) {
			return nil, credentialsUnsupported
		}
		for _, key := range []string{"cookie", "token", "form_entries"} {
			if credentialsNonempty(primary[key]) {
				return nil, credentialsUnsupported
			}
		}
	default:
		return nil, credentialsUnsupported
	}
	primary["username"], _ = json.Marshal(username)
	primary["password"], _ = json.Marshal(password)
	endpoints[found], _ = json.Marshal(primary)
	config["endpoints"], _ = json.Marshal(endpoints)
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, credentialsUnsupported
	}
	request.CoreConfig = proto.String(string(encoded))
	return proto.Marshal(&request)
}

type credentialsOperation struct {
	session  *session
	deadline time.Time
}

func (op credentialsOperation) available() bool {
	select {
	case <-op.session.gone:
		return false
	default:
	}
	return time.Now().Before(op.deadline)
}
func (op credentialsOperation) timeout(cap time.Duration) (time.Duration, error) {
	if !op.available() {
		return 0, credentialsExpired
	}
	remaining := time.Until(op.deadline)
	if remaining < cap {
		return remaining, nil
	}
	return cap, nil
}
func (op credentialsOperation) exchange(worker *workerProcess, f frame, cap time.Duration) ([]byte, error) {
	timeout, err := op.timeout(cap)
	if err != nil {
		return nil, err
	}
	return exchangeExisting(worker, f, timeout)
}
func (op credentialsOperation) terminal(worker *workerProcess, id uint32) (bool, error) {
	data, _ := proto.Marshal(&gen.VPNStatusRequest{EndpointTags: []string{"proxy"}})
	response, err := op.exchange(worker, frame{id, "QueryVPNStatus", data}, 3*time.Second)
	if err != nil {
		return false, err
	}
	var status gen.VPNStatusResponse
	if len(response) < 9 || response[4] != 0 || strictVPNDecode(response[9:], &status) != nil || len(status.Results) != 1 || status.Results[0].GetTag() != "proxy" {
		return false, errors.New("managed_vpn_credentials_unavailable")
	}
	select {
	case <-worker.exited:
		return false, errors.New("managed_vpn_credentials_unavailable")
	default:
	}
	endpoint := status.Results[0]
	return endpoint.GetState() == "error" && endpoint.GetAuthFailed() && !endpoint.GetConnected() && endpoint.Challenge == nil, nil
}
func (op credentialsOperation) check(worker *workerProcess, id uint32, payload []byte) (bool, error) {
	var request gen.LoadConfigReq
	if proto.Unmarshal(payload, &request) != nil {
		return false, credentialsUnsupported
	}
	xray := request.GetNeedXray()
	request.NeedXray = proto.Bool(false)
	for step := 0; step < 2; step++ {
		if step == 1 {
			if !xray {
				break
			}
			request.NeedXray = proto.Bool(true)
		}
		data, _ := proto.Marshal(&request)
		response, err := op.exchange(worker, frame{id, "CheckConfig", data}, 25*time.Second)
		if err != nil {
			return false, err
		}
		var result gen.ErrorResp
		if len(response) < 9 || response[4] != 0 || strictVPNDecode(response[9:], &result) != nil {
			return false, errors.New("managed_vpn_credentials_check_failed")
		}
		if result.GetError() != "" {
			return false, nil
		}
	}
	return true, nil
}

// The transaction cannot delegate to exchange/start/retry: all preflight RPCs
// target the captured child, and each replacement incarnation burns its slot.
func (s *session) managedCredentials(id uint32, payload []byte) *gen.ManagedVPNReplaceCredentialsResponse {
	return s.replaceCredentials(id, payload, time.Now().Add(credentialsBudget), credentialsSteps{retire: s.retireCredentialsWorker, start: s.startCredentialsWorker})
}

type credentialsSteps struct {
	retire func() error
	start  func(uint32, []byte, credentialsOperation) error
}

func (s *session) replaceCredentials(id uint32, payload []byte, deadline time.Time, steps credentialsSteps) *gen.ManagedVPNReplaceCredentialsResponse {
	response := &gen.ManagedVPNReplaceCredentialsResponse{Version: proto.Uint32(managedCredentialsVersion), PreviousGeneration: proto.Uint64(0), Generation: proto.Uint64(s.generation), Outcome: gen.ManagedVPNReplaceCredentialsOutcome_CREDENTIALS_REJECTED.Enum(), ErrorCode: proto.String("managed_vpn_credentials_invalid_request")}
	refuse := func(code string) *gen.ManagedVPNReplaceCredentialsResponse {
		response.Generation = proto.Uint64(s.generation)
		response.ErrorCode = proto.String(code)
		return response
	}
	var request gen.ManagedVPNReplaceCredentialsRequest
	if len(payload) > maxManagedCredentialsRequest || strictVPNDecode(payload, &request) != nil {
		return response
	}
	response.PreviousGeneration = proto.Uint64(request.GetGeneration())
	if request.Version == nil || request.Generation == nil || request.EndpointTag == nil || request.Username == nil || request.Password == nil {
		return response
	}
	if request.GetVersion() != managedCredentialsVersion {
		return refuse("managed_vpn_credentials_unsupported_version")
	}
	if request.GetGeneration() == 0 || request.GetEndpointTag() != "proxy" || (!vpnText(request.GetUsername()) || !vpnText(request.GetPassword())) || strings.Contains(request.GetUsername(), "{otp}") || strings.Contains(request.GetPassword(), "{otp}") || (request.GetUsername() == "" && request.GetPassword() == "") {
		return response
	}
	if request.GetGeneration() != s.generation {
		return refuse("managed_vpn_credentials_stale")
	}
	captured := s.worker
	if s.phase != "connected" || s.desired == nil || s.effective == nil || captured == nil || s.owner == nil || s.owner.active == nil || s.cleanupUncertain {
		return refuse("managed_vpn_credentials_unavailable")
	}
	if s.generation > ^uint64(0)-2 {
		return refuse("managed_vpn_credentials_generation_exhausted")
	}
	candidateGeneration, rollbackGeneration := s.generation+1, s.generation+2
	old := append([]byte(nil), s.desired...)
	candidate, err := patchCredentials(old, request.GetUsername(), request.GetPassword())
	if err != nil {
		return refuse("managed_vpn_credentials_configuration_unsupported")
	}
	effective, err := patchCredentials(s.effective, request.GetUsername(), request.GetPassword())
	if err != nil {
		return refuse("managed_vpn_credentials_configuration_unsupported")
	}
	op := credentialsOperation{s, deadline}
	preflightFailure := func(code string, transport error) *gen.ManagedVPNReplaceCredentialsResponse {
		if transport != nil && !errors.Is(transport, credentialsExpired) {
			s.workerLost(time.Now())
		}
		if !op.available() {
			code = "managed_vpn_credentials_deadline_exceeded"
		}
		return refuse(code)
	}
	select {
	case <-captured.exited:
		return preflightFailure("managed_vpn_credentials_unavailable", errors.New("worker exited"))
	default:
	}
	terminal, err := op.terminal(captured, id)
	if err != nil || !terminal {
		return preflightFailure("managed_vpn_credentials_unavailable", err)
	}
	checked, err := op.check(captured, id, effective)
	if err != nil || !checked {
		return preflightFailure("managed_vpn_credentials_check_failed", err)
	}
	terminal, err = op.terminal(captured, id)
	if err != nil || !terminal {
		return preflightFailure("managed_vpn_credentials_unavailable", err)
	}
	if !op.available() {
		return refuse("managed_vpn_credentials_deadline_exceeded")
	}
	// Burn the candidate slot at destructive cutover, including a failed retire.
	s.generation = candidateGeneration
	// No callback into workerLost after cutover: candidate may never auto-retry.
	s.desired, s.effective = nil, nil
	s.retryAt = time.Time{}
	s.attempts = 0
	s.phase, s.failure = "failed", "core_disconnected"
	failed := func(code string) *gen.ManagedVPNReplaceCredentialsResponse {
		s.desired, s.effective = nil, nil
		s.retryAt = time.Time{}
		s.phase, s.failure = "failed", "core_disconnected"
		if err := steps.retire(); err != nil {
			code = "managed_vpn_credentials_cleanup_failed"
			s.cleanupUncertain = true
			s.failure = "tun_recovery_failed"
		}
		if s.cleanupUncertain {
			s.failure = "tun_recovery_failed"
			code = "managed_vpn_credentials_cleanup_failed"
		}
		response.Outcome = gen.ManagedVPNReplaceCredentialsOutcome_CREDENTIALS_FAILED.Enum()
		return refuse(code)
	}
	if err := steps.retire(); err != nil {
		s.cleanupUncertain = true
		return failed("managed_vpn_credentials_cleanup_failed")
	}
	if !op.available() {
		return failed("managed_vpn_credentials_deadline_exceeded")
	}
	if err := steps.start(id, candidate, op); err == nil && op.available() {
		s.desired = candidate
		response.Outcome = gen.ManagedVPNReplaceCredentialsOutcome_CREDENTIALS_APPLIED.Enum()
		return refuse("")
	}
	if err := steps.retire(); err != nil {
		s.cleanupUncertain = true
		return failed("managed_vpn_credentials_cleanup_failed")
	}
	if !op.available() {
		return failed("managed_vpn_credentials_deadline_exceeded")
	}
	s.generation = rollbackGeneration
	if err := steps.start(id, old, op); err == nil && op.available() {
		s.desired = old
		response.Outcome = gen.ManagedVPNReplaceCredentialsOutcome_CREDENTIALS_RESTORED.Enum()
		return refuse("managed_vpn_credentials_restart_failed")
	}
	code := "managed_vpn_credentials_restart_failed"
	if !op.available() {
		code = "managed_vpn_credentials_deadline_exceeded"
	}
	return failed(code)
}

// Cleanup may outlive the operation deadline. Never release the lease while a
// child still owns TUN descriptors; an unconfirmed reap cannot become exit zero.
func (s *session) retireCredentialsWorker() error {
	s.stopWorker()
	if err := cleanNetwork(s.owner); err != nil {
		s.cleanupUncertain = true
		return errors.New("managed_vpn_credentials_cleanup_failed")
	}
	s.effective = nil
	return nil
}
func (s *session) startCredentialsWorker(id uint32, payload []byte, op credentialsOperation) error {
	if !op.available() {
		return errors.New("managed_vpn_credentials_deadline_exceeded")
	}
	prepared, err := s.owner.prepare(payload)
	if err != nil {
		return errors.New("managed_vpn_credentials_restart_failed")
	}
	if !op.available() {
		return errors.New("managed_vpn_credentials_deadline_exceeded")
	}
	if err = s.prepareNetworkDNS(); err != nil {
		return errors.New("managed_vpn_credentials_restart_failed")
	}
	s.worker, err = startWorkerExecutableUntil("/proc/self/exe", s.credentials, s.directory, s.gone, op.deadline, s.pinSystemResolver())
	if err != nil {
		return errors.New("managed_vpn_credentials_restart_failed")
	}
	s.owner.active.WorkerPID = s.worker.cmd.Process.Pid
	s.owner.active.WorkerStart, err = processStart(s.worker.cmd.Process.Pid)
	if err != nil {
		return errors.New("managed_vpn_credentials_restart_failed")
	}
	if err = s.owner.write(s.owner.active); err != nil {
		return errors.New("managed_vpn_credentials_restart_failed")
	}
	response, err := op.exchange(s.worker, frame{id, "Start", prepared}, 25*time.Second)
	if err != nil || !startSucceeded(response) {
		return errors.New("managed_vpn_credentials_restart_failed")
	}
	if err = s.activateDNS(); err != nil {
		return err
	}
	s.phase, s.failure = "connected", ""
	s.retryAt = time.Time{}
	s.connectedAt = time.Now()
	s.effective = append([]byte(nil), prepared...)
	return nil
}
