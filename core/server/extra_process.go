package main

import (
	"ThroneCore/gen"
	"ThroneCore/internal/process"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
)

// Pointer publication uses stateMu; Process owns its own status lock. Lifecycle
// operations are serialized by lifecycleMu, never hold stateMu while waiting.
var supervisedExtra *process.Supervised

func currentExtra() *process.Supervised {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return supervisedExtra
}
func setExtra(p *process.Supervised) { stateMu.Lock(); supervisedExtra = p; stateMu.Unlock() }

func (s *server) QueryExtraProcess(context.Context, *gen.EmptyReq) (*gen.QueryExtraProcessResp, error) {
	status := process.Status{State: "inactive"}
	if p := currentExtra(); p != nil {
		status = p.Status()
	}
	return &gen.QueryExtraProcessResp{Version: To(process.ProtocolVersion), Supported: To(process.SupervisionSupported()), State: To(status.State), Instance: To(status.Instance), Reason: To(status.Reason), ExitCode: status.ExitCode}, nil
}

func extraSpec(in *gen.LoadConfigReq) (process.Spec, error) {
	options := in.GetExtraProcessOptions()
	if options == nil || !in.GetNeedExtraProcess() {
		return process.Spec{}, errors.New("external_core_options_invalid")
	}
	var core struct {
		Inbounds []struct {
			Type string `json:"type"`
			Port uint32 `json:"listen_port"`
		} `json:"inbounds"`
	}
	if json.Unmarshal([]byte(in.GetCoreConfig()), &core) != nil {
		return process.Spec{}, errors.New("external_core_options_invalid")
	}
	tun := false
	for _, entry := range core.Inbounds {
		if entry.Type == "tun" {
			tun = true
		}
		if entry.Port == options.GetSocksPort() {
			return process.Spec{}, errors.New("external_core_port_busy")
		}
	}
	spec, err := process.ParseSpec(in.GetExtraProcessPath(), in.GetExtraProcessArgs(), in.GetExtraProcessConf(), in.GetExtraNoOut(), options.GetVersion(), options.GetSocksAddress(), options.GetSocksPort(), options.GetStartupTimeoutMs())
	if err != nil {
		return process.Spec{}, err
	}
	config, err := guardedConfig(in.GetCoreConfig(), spec.Path, tun)
	if err != nil {
		return process.Spec{}, err
	}
	in.CoreConfig = &config
	return spec, nil
}

// sing-box matches process_path against the file the kernel reports for a
// running program, so a core reached through a symlink has to be named by its
// real path. The routing rules the app wrote name it as the person typed it;
// on Windows that may use forward slashes, which Clean turns around as Qt did.
func realExtraCorePath(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return filepath.Clean(path)
}

// The external core's own connections must leave outside whatever this config
// builds, or a tun would carry them back into the core that feeds it. The app
// writes that rule; here it is made to name the real file and, when a tun is
// present, its absence is refused rather than silently looped.
func guardedConfig(config, path string, tun bool) (string, error) {
	real := realExtraCorePath(path)
	decoder := json.NewDecoder(strings.NewReader(config))
	decoder.UseNumber()
	var root map[string]any
	if decoder.Decode(&root) != nil {
		return "", errors.New("external_core_options_invalid")
	}
	guarded := false
	for _, section := range []string{"route", "dns"} {
		object, _ := root[section].(map[string]any)
		rules, _ := object["rules"].([]any)
		for _, entry := range rules {
			rule, _ := entry.(map[string]any)
			paths, _ := rule["process_path"].([]any)
			named := false
			for i, value := range paths {
				if text, ok := value.(string); ok && (text == path || text == real) {
					paths[i] = real
					named = true
				}
			}
			if named && section == "route" && rule["outbound"] == "direct" {
				guarded = true
			}
		}
	}
	if tun && !guarded {
		return "", errors.New("external_core_tun_guard_missing")
	}
	out, err := json.Marshal(root)
	if err != nil {
		return "", errors.New("external_core_options_invalid")
	}
	return string(out), nil
}

func stopExtra() error {
	if p := currentExtra(); p != nil {
		if err := p.Stop(); err != nil {
			return err
		}
		setExtra(nil)
	}
	if extraProcess != nil {
		extraProcess.Stop()
		extraProcess = nil
	}
	return nil
}
