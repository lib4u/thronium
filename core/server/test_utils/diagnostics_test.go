package test_utils

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type ipFixtureTransport func(*http.Request) (*http.Response, error)

func (f ipFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestIPResponseValidation(t *testing.T) {
	for _, tt := range []struct {
		name, body          string
		status              int
		wantIP, wantCountry string
		bad                 bool
	}{
		{"v4", `{"ip":"203.0.113.9","country_code":"jp"}`, 200, "203.0.113.9", "JP", false},
		{"v6", `{"ip":"2001:db8::1","country_code":"DE"}`, 200, "2001:db8::1", "DE", false},
		{"unknown", `{"ip":"203.0.113.9","country_code":"-"}`, 200, "203.0.113.9", "", false},
		{"http-error", `{"ip":"203.0.113.9","country_code":"JP"}`, 429, "", "", true},
		{"provider-error", `{"error":{"message":"private-provider-error"}}`, 200, "", "", true},
		{"bad-ip", `{"ip":"private-host/path","country_code":"US"}`, 200, "", "", true},
		{"bad-country", `{"ip":"203.0.113.9","country_code":"<script>"}`, 200, "", "", true},
		{"html", `<html>private-provider-error</html>`, 200, "", "", true},
		{"oversize", strings.Repeat(" ", 65537), 200, "", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: ipFixtureTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != ipInfoAPI {
					t.Fatal("wrong endpoint")
				}
				return &http.Response{StatusCode: tt.status, Body: io.NopCloser(strings.NewReader(tt.body)), Header: make(http.Header)}, nil
			})}
			result, err := ipTest(context.Background(), client)
			if (err != nil) != tt.bad {
				t.Fatalf("success=%v, expected error=%v", err == nil, tt.bad)
			}
			if !tt.bad && (result.IP != tt.wantIP || result.CountryCode != tt.wantCountry) {
				t.Fatalf("unexpected result: %+v", result)
			}
		})
	}
}
func TestSimpleDownloadRejectsHTTPEmptyAndBrokenBodies(t *testing.T) {
	for _, mode := range []string{"ok", "http-error", "empty", "truncated", "sample-deadline"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "http-error":
					w.WriteHeader(503)
					_, _ = io.WriteString(w, "unavailable")
				case "empty":
					w.WriteHeader(200)
				case "truncated":
					w.Header().Set("Content-Length", "9999")
					_, _ = io.WriteString(w, "short")
				case "sample-deadline":
					_, _ = io.WriteString(w, strings.Repeat("x", 4096))
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				default:
					_, _ = io.WriteString(w, strings.Repeat("x", 8192))
				}
			}))
			defer server.Close()
			res := &SpeedTestResult{}
			dialer := &net.Dialer{}
			err := simpleDownloadTest(context.Background(), dialer.DialContext, res, server.URL, 150*time.Millisecond)
			success := mode == "ok" || mode == "sample-deadline"
			if (err == nil) != success {
				t.Fatalf("success=%v, expected=%v, error=%v", err == nil, success, err)
			}
			if success && (res.DlBytes <= 0 || res.DlSpeed == "") {
				t.Fatal("successful sample needs measured bytes and rate")
			}
		})
	}
}
