package winservice

import (
	"ThroneCore/gen"
	"encoding/json"
	"errors"
	pathpkg "path"
	"strings"
)

// checkConfig refuses what a core running as SYSTEM must not do on the
// person's behalf: start another program, or write a file where the person
// could have placed a link (logs, cache outside the session, a downloaded
// panel). Everything else in the configuration is the person's choice.
func checkConfig(in *gen.LoadConfigReq) error {
	if in.GetNeedExtraProcess() || in.GetExtraProcessPath() != "" {
		return errors.New("tun_service_external_core_unsupported")
	}
	text := in.GetCoreConfig()
	if text == "" {
		return nil
	}
	var config struct {
		Log struct {
			Output string `json:"output"`
		} `json:"log"`
		Experimental struct {
			CacheFile struct {
				Enabled bool   `json:"enabled"`
				Path    string `json:"path"`
			} `json:"cache_file"`
			ClashAPI struct {
				ExternalUI            string `json:"external_ui"`
				ExternalUIDownloadURL string `json:"external_ui_download_url"`
			} `json:"clash_api"`
		} `json:"experimental"`
	}
	if json.Unmarshal([]byte(text), &config) != nil {
		return errors.New("invalid_configuration")
	}
	if config.Log.Output != "" {
		return errors.New("tun_service_write_path_unsupported")
	}
	if cache := config.Experimental.CacheFile; cache.Enabled && !insideSession(cache.Path) {
		return errors.New("tun_service_write_path_unsupported")
	}
	if api := config.Experimental.ClashAPI; api.ExternalUI != "" || api.ExternalUIDownloadURL != "" {
		return errors.New("tun_service_write_path_unsupported")
	}
	return nil
}

// A relative name without parent steps stays inside the worker's own session
// directory, its working directory.
func insideSession(path string) bool {
	if path == "" {
		return true
	}
	// Both separators count on Windows, whatever system checks the name.
	slashed := strings.ReplaceAll(path, `\`, "/")
	clean := pathpkg.Clean(slashed)
	return !strings.HasPrefix(slashed, "/") && !strings.Contains(path, ":") &&
		clean != ".." && !strings.HasPrefix(clean, "../")
}
