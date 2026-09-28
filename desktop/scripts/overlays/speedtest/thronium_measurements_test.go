package speedtest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestThroniumTimedTransfers(t *testing.T) {
	for _, direction := range []string{"download", "upload"} {
		for _, mode := range []string{"ok", "http-error", "truncated", "deadline", "empty"} {
			if direction == "upload" && mode == "empty" {
				continue
			}
			t.Run(direction+"/"+mode, func(t *testing.T) {
				var received atomic.Int64
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if mode == "http-error" {
						// In upload mode an error still matters after actual bytes were sent.
						if r.Method == http.MethodPost {
							n, _ := io.Copy(io.Discard, r.Body)
							received.Add(n)
						}
						w.WriteHeader(503)
						_, _ = io.WriteString(w, "unavailable")
						return
					}
					if r.Method == http.MethodPost {
						n, _ := io.Copy(io.Discard, r.Body)
						received.Add(n)
					}
					if mode == "empty" {
						return
					}
					if mode == "truncated" {
						w.Header().Set("Content-Length", "999999")
					}
					_, _ = io.WriteString(w, strings.Repeat("x", 8192))
					w.(http.Flusher).Flush()
					if mode == "deadline" {
						<-r.Context().Done()
					} else {
						time.Sleep(5 * time.Millisecond)
					}
				}))
				defer server.Close()
				client := New(WithUserConfig(&UserConfig{DialContextFunc: (&net.Dialer{}).DialContext, MaxConnections: 2}))
				defer client.config.T.CloseIdleConnections()
				srv, err := client.CustomServer(server.URL)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
				defer cancel()
				if direction == "download" {
					err = srv.DownloadTestContext(ctx)
				} else {
					err = srv.UploadTestContext(ctx)
				}
				wantSuccess := mode == "ok" || mode == "deadline"
				if (err == nil) != wantSuccess {
					t.Fatalf("success=%v, want=%v: %v", err == nil, wantSuccess, err)
				}
				if mode == "http-error" && (err == nil || !strings.Contains(err.Error(), "503")) {
					t.Fatalf("HTTP status lost: %v", err)
				}
				if mode == "http-error" && direction == "download" && client.GetTotalDownload() != 0 {
					t.Fatal("HTTP error body credited as download")
				}
				if direction == "upload" && (client.GetTotalUpload() <= 0 || received.Load() <= 0) {
					t.Fatal("upload fixture did not transfer actual data")
				}
				if wantSuccess && direction == "download" && client.GetTotalDownload() <= 0 {
					t.Fatal("download has no measured data")
				}
			})
		}
	}
}

func TestThroniumServerDiscovery(t *testing.T) {
	for _, mode := range []string{"ok", "api-http", "fallback-http", "null-entry", "empty-list", "invalid-json", "ping-http", "ping-truncated", "cancel-ping"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var server *httptest.Server
			var requests atomic.Int64
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if strings.HasSuffix(r.URL.Path, "latency.txt") {
					switch mode {
					case "cancel-ping":
						cancel()
						<-r.Context().Done()
						return
					case "ping-http":
						w.WriteHeader(503)
					case "ping-truncated":
						w.Header().Set("Content-Length", "999")
					}
					_, _ = io.WriteString(w, "test=test")
					return
				}
				if mode == "fallback-http" {
					if strings.Contains(r.URL.Path, "/api/") {
						w.Header().Set("Content-Length", "0")
						return
					}
					w.WriteHeader(503)
					_, _ = io.WriteString(w, `<settings><servers><server url="`+server.URL+`/speedtest/upload.php" id="1"/></servers></settings>`)
					return
				}
				switch mode {
				case "api-http":
					w.WriteHeader(503)
				case "null-entry":
					_, _ = io.WriteString(w, "[null]")
					return
				case "empty-list":
					_, _ = io.WriteString(w, "[]")
					return
				case "invalid-json":
					_, _ = io.WriteString(w, "invalid")
					return
				}
				_ = json.NewEncoder(w).Encode([]map[string]any{{"url": server.URL + "/speedtest/upload.php", "id": "1", "lat": "0", "lon": "0"}})
			}))
			defer server.Close()
			// Every URL, including the fixed discovery URL, reaches this owned TLS listener.
			dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}
			client := New(WithUserConfig(&UserConfig{DialContextFunc: dial, PingMode: HTTP, MaxConnections: 2}))
			client.config.T = server.Client().Transport.(*http.Transport).Clone()
			// httptest's CA is trusted above; validate its actual certificate name.
			client.config.T.TLSClientConfig.ServerName = "example.com"
			client.config.T.DialContext = dial
			defer client.config.T.CloseIdleConnections()
			started := time.Now()
			servers, err := client.FetchServerListContext(ctx)
			if requests.Load() == 0 {
				t.Fatalf("owned TLS fixture was not reached: %v", err)
			}
			switch mode {
			case "ok":
				if err != nil || len(servers) != 1 || servers[0].Latency <= 0 {
					t.Fatalf("bad discovery: %v", err)
				}
			case "ping-http", "ping-truncated":
				if err != nil || len(servers) != 1 || servers[0].Latency != PingTimeout {
					t.Fatalf("bad HTTP counted as latency: %v", err)
				}
			case "cancel-ping":
				if !errors.Is(err, context.Canceled) || time.Since(started) > time.Second {
					t.Fatalf("discovery did not honor parent cancellation: %v", err)
				}
			default:
				if err == nil {
					t.Fatal("invalid discovery accepted")
				}
				if (mode == "api-http" || mode == "fallback-http") && !strings.Contains(err.Error(), "503") {
					t.Fatalf("HTTP status lost: %v", err)
				}
			}
		})
	}
}
