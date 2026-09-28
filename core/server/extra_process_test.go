//go:build linux

package main

import (
	"ThroneCore/gen"
	"ThroneCore/internal/process"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	if process.GuardianMain() {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func extraPort(t *testing.T) uint32 {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := uint32(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()
	return p
}

type extraEvent struct {
	Event    string `json:"event"`
	Identity struct {
		PID int `json:"pid"`
	} `json:"identity"`
	ConfigPath string `json:"configPath"`
}

func extraEvents(t *testing.T, marker string) []extraEvent {
	t.Helper()
	b, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	var out []extraEvent
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var e extraEvent
		if json.Unmarshal([]byte(line), &e) != nil {
			t.Fatal("bad fixture event")
		}
		out = append(out, e)
	}
	return out
}
func assertExtraClean(t *testing.T, marker string) {
	t.Helper()
	for _, e := range extraEvents(t, marker) {
		if e.Identity.PID > 0 {
			b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", e.Identity.PID))
			if err == nil && !strings.Contains(string(b), ") Z ") {
				t.Fatal("owned child remains", e.Identity.PID)
			}
		}
		if e.ConfigPath != "" {
			if _, err := os.Stat(e.ConfigPath); !os.IsNotExist(err) {
				t.Fatal("temp config remains")
			}
		}
	}
}

func extraRequest(t *testing.T) (*gen.LoadConfigReq, string) {
	t.Helper()
	if !process.SupervisionSupported() {
		t.Skip("requires unprivileged Linux fork build")
	}
	_, _ = globalServer.Stop(context.Background(), &gen.EmptyReq{})
	t.Cleanup(func() {
		reply, _ := globalServer.Stop(context.Background(), &gen.EmptyReq{})
		if reply.GetError() != "" {
			t.Error(reply.GetError())
		}
	})
	helper, err := filepath.Abs("../../desktop/tests/external_core_fixture.py")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(helper); err != nil {
		t.Fatal(err)
	}
	port, inbound := extraPort(t), extraPort(t)
	marker := filepath.Join(t.TempDir(), "launches.jsonl")
	conf, _ := json.Marshal(map[string]any{"marker": marker, "port": port, "echoPort": 1, "mode": "ready", "child": true})
	core, _ := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{map[string]any{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": inbound}}, "outbounds": []any{map[string]any{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": port, "network": "tcp"}}, "route": map[string]any{"final": "proxy"}})
	return &gen.LoadConfigReq{CoreConfig: To(string(core)), NeedExtraProcess: To(true), ExtraProcessPath: To("/usr/bin/python3"), ExtraProcessArgs: To(fmt.Sprintf("%q --config %%s", helper)), ExtraProcessConf: To(string(conf)), ExtraNoOut: To(true), NeedXray: To(false), DisableStats: To(false), ExtraProcessOptions: &gen.ExtraProcessOptions{Version: To(uint32(1)), SocksAddress: To("127.0.0.1"), SocksPort: To(port), StartupTimeoutMs: To(uint32(10000))}}, marker
}

func TestExtraCheckIsSideEffectFreeAndCapabilityExplicit(t *testing.T) {
	req, marker := extraRequest(t)
	ctx := context.Background()
	status, err := globalServer.QueryExtraProcess(ctx, &gen.EmptyReq{})
	if err != nil || !status.GetSupported() || status.GetVersion() != 1 || status.GetState() != "inactive" || status.GetInstance() != "" {
		t.Fatal(status, err)
	}
	reply, _ := globalServer.CheckConfig(ctx, req)
	if reply.GetError() != "" {
		t.Fatal(reply.GetError())
	}
	if _, err = os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("Check launched child")
	}
	req.ExtraProcessArgs = To("'unclosed")
	reply, _ = globalServer.CheckConfig(ctx, req)
	if reply.GetError() != "external_core_arguments_invalid" {
		t.Fatal(reply.GetError())
	}
	if _, err = os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("bad Check launched child")
	}
}

func TestExtraStartStopOwnPortCheckAndRepeatedStart(t *testing.T) {
	req, marker := extraRequest(t)
	ctx := context.Background()
	reply, _ := globalServer.Start(ctx, req)
	if reply.GetError() != "" {
		t.Fatal(reply.GetError())
	}
	status, _ := globalServer.QueryExtraProcess(ctx, &gen.EmptyReq{})
	if status.GetState() != "ready" || len(status.GetInstance()) != 32 {
		t.Fatal(status)
	}
	box := currentBox()
	reply, _ = globalServer.CheckConfig(ctx, req)
	if reply.GetError() != "" {
		t.Fatal("owned port rejected", reply.GetError())
	}
	reply, _ = globalServer.Start(ctx, req)
	if reply.GetError() != "instance already started" || currentBox() != box {
		t.Fatal("second Start damaged existing session", reply.GetError())
	}
	after, _ := globalServer.QueryExtraProcess(ctx, &gen.EmptyReq{})
	if after.GetInstance() != status.GetInstance() || after.GetState() != "ready" {
		t.Fatal("second Start damaged process")
	}
	reply, _ = globalServer.Stop(ctx, &gen.EmptyReq{})
	if reply.GetError() != "" {
		t.Fatal(reply.GetError())
	}
	assertExtraClean(t, marker)
	reply, _ = globalServer.Stop(ctx, &gen.EmptyReq{})
	if reply.GetError() != "" {
		t.Fatal(reply.GetError())
	}
	after, _ = globalServer.QueryExtraProcess(ctx, &gen.EmptyReq{})
	if after.GetState() != "inactive" || after.GetInstance() != "" {
		t.Fatal(after)
	}
}

func TestExtraXrayAndBoxErrorsUnwindBeforeReturning(t *testing.T) {
	for _, scenario := range []string{"xray", "box"} {
		t.Run(scenario, func(t *testing.T) {
			req, marker := extraRequest(t)
			if scenario == "xray" {
				req.NeedXray = To(true)
				req.XrayConfig = To("{invalid-json")
			} else {
				req.CoreConfig = To(`{"outbounds":[{"type":"not-real"}]}`)
			}
			reply, _ := globalServer.Start(context.Background(), req)
			if reply.GetError() == "" {
				t.Fatal("invalid core started")
			}
			assertExtraClean(t, marker)
			if currentBox() != nil || currentExtra() != nil {
				t.Fatal("failed Start retained owner")
			}
		})
	}
}

func TestExtraStopWithoutBoxCleansOwnedProcess(t *testing.T) {
	req, marker := extraRequest(t)
	spec, err := extraSpec(req)
	if err != nil {
		t.Fatal(err)
	}
	p := process.NewSupervised(spec)
	setExtra(p)
	if err = p.Start(); err != nil {
		t.Fatal(err)
	}
	if currentBox() != nil {
		t.Fatal("fixture unexpectedly has box")
	}
	reply, _ := globalServer.Stop(context.Background(), &gen.EmptyReq{})
	if reply.GetError() != "" {
		t.Fatal(reply.GetError())
	}
	assertExtraClean(t, marker)
}

func TestExtraIPCConnectionEOFDrainsGuardian(t *testing.T) {
	req, marker := extraRequest(t)
	reply, _ := globalServer.Start(context.Background(), req)
	if reply.GetError() != "" {
		t.Fatal(reply.GetError())
	}
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() { runDispatch(server); close(done) }()
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("IPC cleanup stuck")
	}
	assertExtraClean(t, marker)
	if currentBox() != nil || currentExtra() != nil {
		t.Fatal("IPC owner retained")
	}
}

func TestExtraChildExitIsStructuredWithoutConfigLeak(t *testing.T) {
	req, marker := extraRequest(t)
	reply, _ := globalServer.Start(context.Background(), req)
	if reply.GetError() != "" {
		t.Fatal(reply.GetError())
	}
	events := extraEvents(t, marker)
	_ = unix.Kill(events[0].Identity.PID, unix.SIGKILL)
	deadline := time.Now().Add(5 * time.Second)
	var status *gen.QueryExtraProcessResp
	for time.Now().Before(deadline) {
		status, _ = globalServer.QueryExtraProcess(context.Background(), &gen.EmptyReq{})
		if status.GetState() == "failed" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if status.GetState() != "failed" || status.GetReason() != "external_core_exited" || status.ExitCode == nil {
		t.Fatal(status)
	}
	data, _ := json.Marshal(status)
	if bytesContainAny(string(data), []string{marker, req.GetExtraProcessArgs(), req.GetExtraProcessConf(), req.GetExtraProcessPath()}) {
		t.Fatal("status leaked launch details")
	}
	reply, _ = globalServer.Stop(context.Background(), &gen.EmptyReq{})
	if reply.GetError() != "" {
		t.Fatal(reply.GetError())
	}
	assertExtraClean(t, marker)
}
func bytesContainAny(s string, needles []string) bool {
	for _, n := range needles {
		if n != "" && strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func TestExtraActualBoxPassesTCPThroughOwnedSOCKS(t *testing.T) {
	req, marker := extraRequest(t)
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		c, e := echo.Accept()
		if e == nil {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}
	}()
	var config map[string]any
	_ = json.Unmarshal([]byte(req.GetExtraProcessConf()), &config)
	config["echoPort"] = echo.Addr().(*net.TCPAddr).Port
	b, _ := json.Marshal(config)
	req.ExtraProcessConf = To(string(b))
	reply, _ := globalServer.Start(context.Background(), req)
	if reply.GetError() != "" {
		t.Fatal(reply.GetError())
	}
	var core struct {
		Inbounds []struct {
			Port int `json:"listen_port"`
		} `json:"inbounds"`
	}
	_ = json.Unmarshal([]byte(req.GetCoreConfig()), &core)
	c, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", core.Inbounds[0].Port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	port := echo.Addr().(*net.TCPAddr).Port
	_, _ = fmt.Fprintf(c, "CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", port, port)
	var response []byte
	one := make([]byte, 1)
	for len(response) < 4096 && !strings.HasSuffix(string(response), "\r\n\r\n") {
		if _, err = io.ReadFull(c, one); err != nil {
			t.Fatal(err)
		}
		response = append(response, one[0])
	}
	if !strings.Contains(string(response), "200") {
		t.Fatal("CONNECT failed")
	}
	_, _ = c.Write([]byte("rpc-external-echo"))
	buf := make([]byte, len("rpc-external-echo"))
	if _, err = io.ReadFull(c, buf); err != nil || string(buf) != "rpc-external-echo" {
		t.Fatal("echo", err)
	}
	reply, _ = globalServer.CheckConfig(context.Background(), req)
	if reply.GetError() != "" {
		t.Fatal(reply.GetError())
	}
	_, _ = c.Write([]byte("held"))
	buf = make([]byte, 4)
	if _, err = io.ReadFull(c, buf); err != nil || string(buf) != "held" {
		t.Fatal("Check interrupted CONNECT")
	}
	_ = c.Close()
	reply, _ = globalServer.Stop(context.Background(), &gen.EmptyReq{})
	if reply.GetError() != "" {
		t.Fatal(reply.GetError())
	}
	assertExtraClean(t, marker)
}

// The external core's own traffic must leave outside the tunnel it feeds: with
// a tun inbound the guarding rule is required, and the rule has to name the
// real file so sing-box can match the running program against it.
func TestExtraTunRequiresTheOwnTrafficGuardAndNamesTheRealFile(t *testing.T) {
	req, _ := extraRequest(t)
	directory := t.TempDir()
	real := filepath.Join(directory, "real-core")
	if err := os.WriteFile(real, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "linked-core")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	req.ExtraProcessPath = To(link)
	req.ExtraProcessArgs = To("--config %s")

	var core map[string]any
	if err := json.Unmarshal([]byte(req.GetCoreConfig()), &core); err != nil {
		t.Fatal(err)
	}
	inbounds := core["inbounds"].([]any)
	core["inbounds"] = append(inbounds, map[string]any{"type": "tun", "tag": "tun-in", "address": []any{"172.19.0.1/30"}})
	withTun, _ := json.Marshal(core)
	req.CoreConfig = To(string(withTun))
	if _, err := extraSpec(req); err == nil || err.Error() != "external_core_tun_guard_missing" {
		t.Fatal("a tun without the guarding rule was accepted:", err)
	}

	core["route"] = map[string]any{"final": "proxy", "rules": []any{
		map[string]any{"action": "route", "process_path": []any{link}, "outbound": "direct"},
	}}
	core["dns"] = map[string]any{"rules": []any{
		map[string]any{"action": "route", "process_path": []any{link}, "server": "dns-direct"},
	}}
	guarded, _ := json.Marshal(core)
	req.CoreConfig = To(string(guarded))
	if _, err := extraSpec(req); err != nil {
		t.Fatal(err)
	}
	var rewritten map[string]any
	if err := json.Unmarshal([]byte(req.GetCoreConfig()), &rewritten); err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{"route", "dns"} {
		rules := rewritten[section].(map[string]any)["rules"].([]any)
		path := rules[0].(map[string]any)["process_path"].([]any)[0]
		if path != real {
			t.Fatal(section, "keeps the symlink the person typed:", path)
		}
	}
	// Without a tun the configuration stands on its own: nothing is required.
	delete(core, "route")
	delete(core, "dns")
	core["inbounds"] = inbounds
	plain, _ := json.Marshal(core)
	req.CoreConfig = To(string(plain))
	if _, err := extraSpec(req); err != nil {
		t.Fatal(err)
	}
}
