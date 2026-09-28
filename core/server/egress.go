package main

import (
	"ThroneCore/internal/boxdns"
	"encoding/json"
	"runtime"
	"sync/atomic"

	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
)

func currentEgress() (iface string, mark uint32) {
	return defaultInterfaceFinder(), autoRedirectMark.Load()
}

func defaultInterfaceFinder() string {
	ifc := boxdns.DefaultInterface()
	if ifc == nil {
		return ""
	}
	return ifc.Name
}

var autoRedirectMark atomic.Uint32

func autoRedirectMarkFor(coreConfig []byte) uint32 {
	// auto_redirect, and SO_MARK itself, are Linux-only.
	if runtime.GOOS != "linux" {
		return 0
	}
	return configAutoRedirectMark(coreConfig)
}

func configAutoRedirectMark(coreConfig []byte) uint32 {
	var config struct {
		Inbounds []json.RawMessage `json:"inbounds"`
	}
	if json.Unmarshal(coreConfig, &config) != nil {
		return 0
	}
	for _, raw := range config.Inbounds {
		var inbound struct {
			Type                   string        `json:"type"`
			AutoRedirect           bool          `json:"auto_redirect"`
			AutoRedirectOutputMark option.FwMark `json:"auto_redirect_output_mark"`
		}
		if json.Unmarshal(raw, &inbound) != nil || inbound.Type != "tun" || !inbound.AutoRedirect {
			continue
		}
		if inbound.AutoRedirectOutputMark != 0 {
			return uint32(inbound.AutoRedirectOutputMark)
		}
		return tun.DefaultAutoRedirectOutputMark
	}
	return 0
}
