package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"io"
)

// The protocol this core was compiled against, byte for byte. The application
// hashes its own copy and refuses a core whose file differs, or whose stamped
// version is not its own: the two ship as one pair.
//
//go:embed gen/libcore.proto
var protocolSource []byte

type coreInfo struct {
	Version  string `json:"version"`
	Protocol string `json:"protocol"`
}

func currentCoreInfo() coreInfo {
	sum := sha256.Sum256(protocolSource)
	return coreInfo{Version: appVersion, Protocol: hex.EncodeToString(sum[:])}
}

// writeCoreInfo answers `ThroniumCore --thronium-core-info`, which needs no
// parent, socket or privileges.
func writeCoreInfo(out io.Writer) error {
	return json.NewEncoder(out).Encode(currentCoreInfo())
}
