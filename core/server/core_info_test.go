package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestCoreInfoNamesTheCompiledProtocolAndStampedVersion(t *testing.T) {
	source, err := os.ReadFile("gen/libcore.proto")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(source)
	previous := appVersion
	appVersion = "9.8.7"
	defer func() { appVersion = previous }()
	var out bytes.Buffer
	if err := writeCoreInfo(&out); err != nil {
		t.Fatal(err)
	}
	var info coreInfo
	if err := json.Unmarshal(out.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info.Protocol != hex.EncodeToString(sum[:]) || info.Version != "9.8.7" {
		t.Fatal(info)
	}
}
