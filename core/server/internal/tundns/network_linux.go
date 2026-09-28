//go:build linux

package tundns

import (
	"context"
	"crypto/sha256"
	"sort"
	"strings"
)

// NetworkFingerprint observes supplied resolver records without interpreting
// openresolv's policy or touching the active exclusive record. On a change the
// supervisor removes its record before reconnecting, so openresolv itself applies
// metrics, private/search rules and administrator configuration to the new file.
// Metric-only and resolvconf.conf changes are not exposed by this read-only API.
func (c *OpenResolv) NetworkFingerprint(parent context.Context, token string) ([32]byte, error) {
	var zero [32]byte
	if token != "" && !validToken(token) {
		return zero, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, Timeout)
	defer cancel()
	out, code, err := c.command(ctx, "", "-i")
	if err != nil || code != 0 || len(out) > 65536 {
		return zero, ErrUnavailable
	}
	keys := strings.Fields(out)
	if len(keys) > 128 {
		return zero, ErrUnavailable
	}
	sort.Strings(keys)
	args := []string{"-l"}
	for i, key := range keys {
		if !safeResolverKey(key) || i > 0 && key == keys[i-1] {
			return zero, ErrInvalid
		}
		if token != "" && key == "thronium-tun.thronium-"+token {
			continue
		}
		args = append(args, key)
	}
	if len(args) == 1 {
		return sha256.Sum256(nil), nil
	}
	// Read each record independently so moving a directive between keys cannot
	// keep the same digest. Raw headers are comments and are not trustworthy
	// delimiters inside administrator-supplied record bodies.
	var canonical strings.Builder
	total := 0
	for _, key := range args[1:] {
		out, code, err = c.command(ctx, "", "-l", key)
		total += len(out)
		if err != nil || code != 0 || total > 65536 || strings.ContainsRune(out, 0) {
			return zero, ErrUnavailable
		}
		canonical.WriteString(key)
		canonical.WriteByte('\x00')
		for _, line := range strings.Split(out, "\n") {
			line = strings.SplitN(strings.SplitN(line, "#", 2)[0], ";", 2)[0]
			if fields := strings.Fields(line); len(fields) > 0 {
				canonical.WriteString(strings.Join(fields, " "))
				canonical.WriteByte('\n')
			}
		}
		canonical.WriteByte('\x00')
	}
	return sha256.Sum256([]byte(canonical.String())), nil
}

func validToken(token string) bool {
	if len(token) != 32 {
		return false
	}
	for _, c := range token {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func safeResolverKey(key string) bool {
	if len(key) == 0 || len(key) > 256 || !(key[0] >= 'a' && key[0] <= 'z' || key[0] >= 'A' && key[0] <= 'Z' || key[0] >= '0' && key[0] <= '9') {
		return false
	}
	for _, c := range key {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == ':') {
			return false
		}
	}
	return true
}
