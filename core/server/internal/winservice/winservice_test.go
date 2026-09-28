package winservice

import (
	"ThroneCore/gen"
	"bytes"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestFramesRoundTripAndRefuseOversizedParts(t *testing.T) {
	in := request{id: 7, method: "Start", payload: []byte("payload")}
	out, err := readRequest(bytes.NewReader(encodeRequest(in)))
	if err != nil || out.id != 7 || out.method != "Start" || string(out.payload) != "payload" {
		t.Fatal(out, err)
	}
	back, err := readResponse(bytes.NewReader(encodeResponse(response{id: 7, status: 1, data: []byte("x")})))
	if err != nil || back.id != 7 || back.status != 1 || string(back.data) != "x" {
		t.Fatal(back, err)
	}
	long := encodeRequest(request{id: 1, method: string(bytes.Repeat([]byte("m"), maxMethod+1))})
	if _, err = readRequest(bytes.NewReader(long)); err == nil {
		t.Fatal("long method accepted")
	}
	bad := encodeResponse(response{id: 1, status: 2})
	if _, err = readResponse(bytes.NewReader(bad)); err == nil {
		t.Fatal("unknown status accepted")
	}
}

func TestSystemCoreRefusesProgramsAndWritesOutsideItsSession(t *testing.T) {
	config := func(text string) *gen.LoadConfigReq { return &gen.LoadConfigReq{CoreConfig: proto.String(text)} }
	for text, wanted := range map[string]string{
		`{}`:                       "",
		`{"log":{"level":"info"}}`: "",
		`{"experimental":{"cache_file":{"enabled":true}}}`:                   "",
		`{"experimental":{"cache_file":{"enabled":true,"path":"cache.db"}}}`: "",
		`{"log":{"output":"C:\\Windows\\System32\\x.dll"}}`:                  "tun_service_write_path_unsupported",
		`{"experimental":{"cache_file":{"enabled":true,"path":"C:\\x.db"}}}`: "tun_service_write_path_unsupported",
		`{"experimental":{"cache_file":{"enabled":true,"path":"..\\x.db"}}}`: "tun_service_write_path_unsupported",
		`{"experimental":{"cache_file":{"enabled":true,"path":"../x.db"}}}`:  "tun_service_write_path_unsupported",
		`{"experimental":{"clash_api":{"external_ui":"ui"}}}`:                "tun_service_write_path_unsupported",
		`not json`: "invalid_configuration",
	} {
		err := checkConfig(config(text))
		if (err == nil && wanted != "") || (err != nil && err.Error() != wanted) {
			t.Fatal(text, err)
		}
	}
	external := &gen.LoadConfigReq{NeedExtraProcess: proto.Bool(true)}
	if err := checkConfig(external); err == nil || err.Error() != "tun_service_external_core_unsupported" {
		t.Fatal(err)
	}
}

func TestJournalIsVersionedAndBounded(t *testing.T) {
	if _, err := decodeJournal([]byte(`{"version":1,"workerPid":4,"systemDns":true}`)); err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{`{"version":2}`, `{}`, `[`, string(bytes.Repeat([]byte(" "), 5000)) + `{"version":1}`} {
		if _, err := decodeJournal([]byte(data)); err == nil {
			t.Fatal(data)
		}
	}
}

func TestASignedServiceAcceptsOnlyItsOwnPublisher(t *testing.T) {
	unsigned := errors.New("unsigned")
	if samePublisher("", unsigned, "", unsigned) != nil {
		t.Fatal("an unsigned development service must rely on the path alone")
	}
	if samePublisher("CN=Thronium", nil, "CN=Thronium", nil) != nil {
		t.Fatal("the same publisher was refused")
	}
	if samePublisher("CN=Thronium", nil, "CN=Other", nil) == nil {
		t.Fatal("another publisher was accepted")
	}
	if samePublisher("CN=Thronium", nil, "", unsigned) == nil {
		t.Fatal("an unsigned client of a signed service was accepted")
	}
}
