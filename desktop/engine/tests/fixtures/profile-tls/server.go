// An owned TLS HTTP CONNECT fixture with an independent raw ClientHello SNI parser.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const name = "abcdefghijklmnopqrstuvwxyzabcdef.fixture.invalid"

type recorder struct {
	net.Conn
	mu   sync.Mutex
	data []byte
	done bool
}

func (c *recorder) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	if !c.done && len(c.data)+n <= 1024*1024 {
		c.data = append(c.data, p[:n]...)
	}
	c.mu.Unlock()
	return n, err
}
func (c *recorder) captured() ([]byte, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.done = true
	return append([]byte(nil), c.data...), len(c.data)
}

func rawSNI(records []byte) (string, error) {
	var handshake []byte
	for len(records) >= 5 {
		n := int(binary.BigEndian.Uint16(records[3:5]))
		if len(records) < 5+n {
			return "", fmt.Errorf("short record")
		}
		if records[0] == 22 {
			handshake = append(handshake, records[5:5+n]...)
		}
		records = records[5+n:]
	}
	if len(handshake) < 4 || handshake[0] != 1 {
		return "", fmt.Errorf("missing client hello")
	}
	n := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < 4+n {
		return "", fmt.Errorf("short client hello")
	}
	p := handshake[4 : 4+n]
	take := func(n int) ([]byte, error) {
		if n < 0 || len(p) < n {
			return nil, io.ErrUnexpectedEOF
		}
		v := p[:n]
		p = p[n:]
		return v, nil
	}
	if _, err := take(34); err != nil {
		return "", err
	}
	s, err := take(1)
	if err != nil {
		return "", err
	}
	if _, err = take(int(s[0])); err != nil {
		return "", err
	}
	s, err = take(2)
	if err != nil {
		return "", err
	}
	if _, err = take(int(binary.BigEndian.Uint16(s))); err != nil {
		return "", err
	}
	s, err = take(1)
	if err != nil {
		return "", err
	}
	if _, err = take(int(s[0])); err != nil {
		return "", err
	}
	s, err = take(2)
	if err != nil {
		return "", err
	}
	extensions, err := take(int(binary.BigEndian.Uint16(s)))
	if err != nil {
		return "", err
	}
	for len(extensions) >= 4 {
		typ := binary.BigEndian.Uint16(extensions[:2])
		n := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if len(extensions) < n {
			return "", io.ErrUnexpectedEOF
		}
		v := extensions[:n]
		extensions = extensions[n:]
		if typ != 0 {
			continue
		}
		if len(v) < 5 || int(binary.BigEndian.Uint16(v[:2])) != len(v)-2 || v[2] != 0 {
			return "", fmt.Errorf("invalid SNI list")
		}
		n = int(binary.BigEndian.Uint16(v[3:5]))
		if n != len(v)-5 {
			return "", fmt.Errorf("invalid SNI length")
		}
		return string(v[5:]), nil
	}
	return "", fmt.Errorf("no SNI extension")
}

func handshakeRecordSizes(records []byte) []int {
	var sizes []int
	for len(records) >= 5 {
		n := int(binary.BigEndian.Uint16(records[3:5]))
		if len(records) < 5+n {
			break
		}
		if records[0] == 22 {
			sizes = append(sizes, n)
		}
		records = records[5+n:]
	}
	return sizes
}

func certificate(directory string) (tls.Certificate, string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	now := time.Now()
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	must(err)
	identifier := sha256.Sum256(public)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Owned TLS fixture CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), SubjectKeyId: identifier[:20], AuthorityKeyId: identifier[:20], IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	must(err)
	caPath := filepath.Join(directory, "ca.pem")
	must(os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, AuthorityKeyId: identifier[:20], NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDer, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	must(err)
	return tls.Certificate{Certificate: [][]byte{leafDer, der}, PrivateKey: leafKey}, caPath
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) != 2 {
		panic("provide private output directory")
	}
	directory := os.Args[1]
	must(os.MkdirAll(directory, 0700))
	cert, ca := certificate(directory)
	events, err := os.OpenFile(filepath.Join(directory, "events.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	must(err)
	defer events.Close()
	var eventLock sync.Mutex
	emit := func(value map[string]any) {
		eventLock.Lock()
		defer eventLock.Unlock()
		must(json.NewEncoder(events).Encode(value))
		must(events.Sync())
	}
	originListener, err := net.Listen("tcp4", "127.0.0.1:0")
	must(err)
	originAddress := originListener.Addr().String()
	origin := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		emit(map[string]any{"event": "http", "path": r.URL.Path})
		body := "tls-fixture:" + r.URL.Path
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, body)
	})}
	go func() { _ = origin.Serve(originListener) }()
	proxy, err := net.Listen("tcp4", "127.0.0.1:0")
	must(err)
	var counter atomic.Uint64
	var group sync.WaitGroup
	var connectionLock sync.Mutex
	connections := map[net.Conn]bool{}
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			raw, err := proxy.Accept()
			if err != nil {
				return
			}
			connectionLock.Lock()
			connections[raw] = true
			connectionLock.Unlock()
			id := counter.Add(1)
			group.Add(1)
			go func() {
				defer group.Done()
				defer raw.Close()
				defer func() { connectionLock.Lock(); delete(connections, raw); connectionLock.Unlock() }()
				_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
				capture := &recorder{Conn: raw}
				config := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					data, size := capture.captured()
					sni, err := rawSNI(data)
					if err != nil {
						return nil, err
					}
					if sni != hello.ServerName {
						return nil, fmt.Errorf("wire SNI differs from Go callback")
					}
					emit(map[string]any{"event": "client-hello", "connection": id, "sni": hello.ServerName, "rawSni": sni, "clientHelloBytes": size, "handshakeRecordSizes": handshakeRecordSizes(data)})
					return nil, nil
				}}
				secure := tls.Server(capture, config)
				if err := secure.Handshake(); err != nil {
					emit(map[string]any{"event": "handshake-failed", "connection": id})
					return
				}
				emit(map[string]any{"event": "handshake", "connection": id, "version": secure.ConnectionState().Version, "alpn": secure.ConnectionState().NegotiatedProtocol})
				reader := bufio.NewReader(secure)
				request, err := http.ReadRequest(reader)
				if err != nil {
					emit(map[string]any{"event": "request-failed", "connection": id})
					return
				}
				if request.Method != "CONNECT" || request.Host != originAddress {
					emit(map[string]any{"event": "target-rejected", "connection": id})
					return
				}
				emit(map[string]any{"event": "connect", "connection": id, "target": request.Host})
				remote, err := net.DialTimeout("tcp4", originAddress, 3*time.Second)
				if err != nil {
					return
				}
				defer remote.Close()
				_ = remote.SetDeadline(time.Now().Add(10 * time.Second))
				_, err = io.WriteString(secure, "HTTP/1.1 200 Connection Established\r\n\r\n")
				if err != nil {
					return
				}
				forwarded := make(chan struct{})
				go func() {
					_, _ = io.Copy(remote, reader)
					if tcp, ok := remote.(*net.TCPConn); ok {
						_ = tcp.CloseWrite()
					}
					close(forwarded)
				}()
				_, _ = io.Copy(secure, remote)
				_ = secure.Close()
				<-forwarded
			}()
		}
	}()
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"proxyPort": proxy.Addr().(*net.TCPAddr).Port, "originPort": originListener.Addr().(*net.TCPAddr).Port, "serverName": name, "ca": ca, "events": filepath.Join(directory, "events.jsonl")}))
	_, _ = io.Copy(io.Discard, os.Stdin)
	_ = proxy.Close()
	<-closed
	_ = origin.Close()
	connectionLock.Lock()
	for conn := range connections {
		_ = conn.Close()
	}
	connectionLock.Unlock()
	group.Wait()
}
