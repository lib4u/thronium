//go:build linux

package tunsession

import (
	"ThroneCore/gen"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

const managedVPNVersion = 1
const maxManagedVPNRequest = 256 * 1024

var invalidManagedVPN = errors.New("invalid managed VPN protobuf")

// Unlike normal protobuf last-wins parsing, an authentication envelope must not
// accept duplicate scalar/oneof/map fields or discard unknown operations.
func strictVPNWire(data []byte, descriptor protoreflect.MessageDescriptor, depth int) error {
	if depth > 16 {
		return invalidManagedVPN
	}
	seen := make(map[protoreflect.FieldNumber]bool)
	oneofs := make(map[protoreflect.FullName]bool)
	maps := make(map[protoreflect.FieldNumber]map[string]bool)
	for len(data) > 0 {
		number, wire, n := protowire.ConsumeTag(data)
		if n < 0 || n != protowire.SizeTag(number) {
			return invalidManagedVPN
		}
		data = data[n:]
		field := descriptor.Fields().ByNumber(number)
		if field == nil || (seen[number] && !field.IsList() && !field.IsMap()) {
			return invalidManagedVPN
		}
		seen[number] = true
		if oneof := field.ContainingOneof(); oneof != nil {
			if oneofs[oneof.FullName()] {
				return invalidManagedVPN
			}
			oneofs[oneof.FullName()] = true
		}
		switch field.Kind() {
		case protoreflect.StringKind, protoreflect.MessageKind:
			if wire != protowire.BytesType {
				return invalidManagedVPN
			}
			value, n := protowire.ConsumeBytes(data)
			if n < 0 || n-len(value) != protowire.SizeVarint(uint64(len(value))) {
				return invalidManagedVPN
			}
			data = data[n:]
			if field.Kind() == protoreflect.StringKind {
				if !utf8.Valid(value) {
					return invalidManagedVPN
				}
			} else {
				if err := strictVPNWire(value, field.Message(), depth+1); err != nil {
					return err
				}
				if field.IsMap() {
					entry := dynamicpb.NewMessage(field.Message())
					if proto.Unmarshal(value, entry) != nil {
						return invalidManagedVPN
					}
					key := entry.Get(field.MapKey()).String()
					if maps[number] == nil {
						maps[number] = make(map[string]bool)
					}
					if maps[number][key] {
						return invalidManagedVPN
					}
					maps[number][key] = true
				}
			}
		case protoreflect.Uint32Kind, protoreflect.Uint64Kind, protoreflect.Int32Kind, protoreflect.Int64Kind, protoreflect.BoolKind:
			if wire != protowire.VarintType {
				return invalidManagedVPN
			}
			value, n := protowire.ConsumeVarint(data)
			if n < 0 || n != protowire.SizeVarint(value) {
				return invalidManagedVPN
			}
			data = data[n:]
			if field.Kind() == protoreflect.Uint32Kind && value > math.MaxUint32 {
				return invalidManagedVPN
			}
			if field.Kind() == protoreflect.Int32Kind && value > math.MaxInt32 && value < uint64(0xffffffff80000000) {
				return invalidManagedVPN
			}
			if field.Kind() == protoreflect.BoolKind && value > 1 {
				return invalidManagedVPN
			}
		default:
			// This private envelope schema has no packed, fixed, bytes or group fields.
			return invalidManagedVPN
		}
	}
	return nil
}

func strictVPNDecode(data []byte, message proto.Message) error {
	if err := strictVPNWire(data, message.ProtoReflect().Descriptor(), 0); err != nil {
		return err
	}
	return proto.Unmarshal(data, message)
}
func vpnIdentity(value string) bool {
	return len(value) > 0 && len(value) <= 512 && utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsControl)
}
func vpnText(value string) bool {
	return len(value) <= 4096 && utf8.ValidString(value) && !strings.ContainsRune(value, '\x00')
}
func vpnAction(request *gen.SubmitVPNChallengeRequest, cancel bool) bool {
	if request == nil || !vpnIdentity(request.GetEndpointTag()) || !vpnIdentity(request.GetChallengeId()) || len(request.FormValues) > 128 {
		return false
	}
	total := 0
	for _, value := range []string{request.GetUsername(), request.GetPassword(), request.GetSecret()} {
		if !vpnText(value) {
			return false
		}
		total += len(value)
		if cancel && value != "" {
			return false
		}
	}
	if cancel && len(request.FormValues) > 0 {
		return false
	}
	for key, value := range request.FormValues {
		if !vpnIdentity(key) || !vpnText(value) {
			return false
		}
		total += len(key) + len(value)
	}
	return total <= 65536
}
func vpnOperation(request *gen.ManagedVPNRequest) (string, proto.Message, time.Duration, bool) {
	switch operation := request.Operation.(type) {
	case *gen.ManagedVPNRequest_Query:
		query := operation.Query
		if query == nil || query.GetTimeoutMs() != 0 || len(query.EndpointTags) == 0 || len(query.EndpointTags) > 128 {
			break
		}
		seen := make(map[string]bool)
		for _, tag := range query.EndpointTags {
			if !vpnIdentity(tag) || seen[tag] {
				return "", nil, 0, false
			}
			seen[tag] = true
		}
		return "QueryVPNStatus", query, 3 * time.Second, true
	case *gen.ManagedVPNRequest_Submit:
		if vpnAction(operation.Submit, false) {
			return "SubmitVPNChallenge", operation.Submit, 5 * time.Second, true
		}
	case *gen.ManagedVPNRequest_Cancel:
		if vpnAction(operation.Cancel, true) {
			return "CancelVPNChallenge", operation.Cancel, 5 * time.Second, true
		}
	}
	return "", nil, 0, false
}

// Called only from session.run's serial request loop. Auth never uses exchange's
// ensure-worker path, never replaces desired/effective, and is never replayed.
func (s *session) managedVPN(id uint32, payload []byte) *gen.ManagedVPNResponse {
	response := &gen.ManagedVPNResponse{Version: proto.Uint32(managedVPNVersion), Generation: proto.Uint64(s.generation)}
	refuse := func(code string) *gen.ManagedVPNResponse { response.ErrorCode = proto.String(code); return response }
	var request gen.ManagedVPNRequest
	if len(payload) > maxManagedVPNRequest || strictVPNDecode(payload, &request) != nil {
		return refuse("managed_vpn_invalid_request")
	}
	if request.GetVersion() != managedVPNVersion {
		return refuse("managed_vpn_unsupported_version")
	}
	method, message, timeout, valid := vpnOperation(&request)
	if !valid || request.GetGeneration() == 0 {
		return refuse("managed_vpn_invalid_request")
	}
	if request.GetGeneration() != s.generation {
		return refuse("managed_vpn_stale_generation")
	}
	captured := s.worker
	if s.phase != "connected" || s.desired == nil || captured == nil || s.generation == 0 {
		return refuse("managed_vpn_unavailable")
	}
	select {
	case <-captured.exited:
		s.workerLost(time.Now())
		return refuse("managed_vpn_unavailable")
	default:
	}
	forwarded, err := proto.Marshal(message)
	if err != nil {
		return refuse("managed_vpn_invalid_request")
	}
	frame, err := exchangeExisting(captured, frame{id, method, forwarded}, timeout)
	if err != nil {
		s.workerLost(time.Now())
		return refuse("managed_vpn_exchange_failed")
	}
	// Do not accept a reply from a child already observed exited. The captured
	// socket can never become a new worker while this handler is executing.
	select {
	case <-captured.exited:
		s.workerLost(time.Now())
		return refuse("managed_vpn_exchange_failed")
	default:
	}
	if len(frame) < 9 || frame[4] != 0 || binary.LittleEndian.Uint32(frame[:]) != id {
		s.workerLost(time.Now())
		return refuse("managed_vpn_exchange_failed")
	}
	if method == "QueryVPNStatus" {
		var status gen.VPNStatusResponse
		if strictVPNDecode(frame[9:], &status) != nil {
			s.workerLost(time.Now())
			return refuse("managed_vpn_exchange_failed")
		}
		wanted := make(map[string]bool)
		for _, tag := range request.GetQuery().EndpointTags {
			wanted[tag] = true
		}
		if len(status.Results) != len(wanted) {
			s.workerLost(time.Now())
			return refuse("managed_vpn_exchange_failed")
		}
		for _, endpoint := range status.Results {
			if endpoint == nil || !wanted[endpoint.GetTag()] {
				s.workerLost(time.Now())
				return refuse("managed_vpn_exchange_failed")
			}
			delete(wanted, endpoint.GetTag())
		}
		response.Result = &gen.ManagedVPNResponse_Status{Status: &status}
	} else {
		var action gen.ErrorResp
		if strictVPNDecode(frame[9:], &action) != nil {
			s.workerLost(time.Now())
			return refuse("managed_vpn_exchange_failed")
		}
		response.Result = &gen.ManagedVPNResponse_Action{Action: &action}
	}
	return response
}
