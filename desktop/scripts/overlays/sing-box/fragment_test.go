package dialer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	opts "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
)

type fragmentRecorder struct {
	net.Conn
	mu    sync.Mutex
	data  []byte
	limit int
	err   error
	first chan struct{}
	once  sync.Once
}

func (r *fragmentRecorder) Write(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(b)
	if r.limit >= 0 {
		n = min(n, r.limit)
	}
	r.data = append(r.data, b[:n]...)
	if r.first != nil {
		r.once.Do(func() { close(r.first) })
	}
	return n, r.err
}
func (r *fragmentRecorder) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Clone(r.data)
}
func (r *fragmentRecorder) Close() error                     { return nil }
func (r *fragmentRecorder) SetDeadline(time.Time) error      { return nil }
func (r *fragmentRecorder) SetWriteDeadline(time.Time) error { return nil }
func newFragmentRecorder(size uint64) (*fragmentConn, *fragmentRecorder) {
	r := &fragmentRecorder{limit: -1}
	return &fragmentConn{conn: r, fragment: TLSFragment{Enabled: true, Size: opts.IntRange{Min: size, Max: size}}}, r
}
func fragmentHello(size int) []byte {
	b := make([]byte, size+5)
	copy(b, []byte{22, 3, 3, byte(size >> 8), byte(size), 1})
	for i := 6; i < len(b); i++ {
		b[i] = byte(i)
	}
	return b
}
func fragmentPayload(t *testing.T, b []byte) ([]byte, int) {
	t.Helper()
	var data []byte
	count := 0
	for len(b) > 0 {
		if len(b) < 5 || b[0] != 22 || b[1] != 3 || b[2] != 3 {
			t.Fatalf("invalid record header %x", b[:min(5, len(b))])
		}
		size := int(b[3])<<8 | int(b[4])
		if size == 0 || size > len(b)-5 {
			t.Fatalf("invalid record size %d", size)
		}
		data = append(data, b[5:5+size]...)
		b = b[5+size:]
		count++
	}
	return data, count
}
func TestFragmentShortAndUnrelatedWrites(t *testing.T) {
	for _, b := range [][]byte{nil, {22}, {22, 3, 3, 0, 10}, {22, 3, 3, 0, 0, 1}, {22, 3, 3, 0, 10, 1}, {23, 3, 3, 0, 1, 1}, {22, 3, 0, 0, 1, 1}, []byte("GET / HTTP/1.1\r\n")} {
		c, r := newFragmentRecorder(10)
		n, err := c.Write(b)
		if n != len(b) || err != nil || !bytes.Equal(r.bytes(), b) {
			t.Fatalf("passthrough %x: %d %v", b, n, err)
		}
	}
}
func TestFragmentBoundedRecordsAndInputCount(t *testing.T) {
	for _, size := range []uint64{1, 10, 500, 1019, 1020, 1500, 16384, 65535} {
		t.Run(big.NewInt(int64(size)).String(), func(t *testing.T) {
			c, r := newFragmentRecorder(size)
			b := fragmentHello(16384)
			n, err := c.Write(b)
			if n != len(b) || err != nil {
				t.Fatalf("Write=%d,%v want %d", n, err, len(b))
			}
			data, records := fragmentPayload(t, r.bytes())
			if !bytes.Equal(data, b[5:]) || records != int((16384+size-1)/size) {
				t.Fatalf("payload or record count changed: %d", records)
			}
		})
	}
}
func TestFragmentRandomRangesKeepPayload(t *testing.T) {
	c, r := newFragmentRecorder(10)
	c.fragment.Size.Max = 100
	b := fragmentHello(8192)
	n, err := c.Write(b)
	if n != len(b) || err != nil {
		t.Fatal(n, err)
	}
	data, count := fragmentPayload(t, r.bytes())
	if !bytes.Equal(data, b[5:]) || count < 82 || count > 820 {
		t.Fatal(count)
	}
}
func TestFragmentTrailingRecordsUntouched(t *testing.T) {
	c, r := newFragmentRecorder(10)
	b := fragmentHello(200)
	tail := []byte{23, 3, 3, 0, 3, 9, 8, 7}
	b = append(b, tail...)
	n, err := c.Write(b)
	wire := r.bytes()
	if n != len(b) || err != nil || !bytes.HasSuffix(wire, tail) {
		t.Fatal(n, err)
	}
	data, _ := fragmentPayload(t, wire[:len(wire)-len(tail)])
	if !bytes.Equal(data, b[5:205]) {
		t.Fatal("changed first record")
	}
}
func TestFragmentPartialWriteAccountingAndTerminalError(t *testing.T) {
	sentinel := errors.New("owned write failure")
	for _, entry := range [][2]int{{0, 0}, {2, 2}, {5, 5}, {7, 7}, {15, 15}, {17, 15}, {20, 15}, {23, 18}} {
		c, r := newFragmentRecorder(10)
		r.limit = entry[0]
		r.err = sentinel
		n, err := c.Write(fragmentHello(200))
		if n != entry[1] || !errors.Is(err, sentinel) {
			t.Fatalf("wire %d: input %d err %v", entry[0], n, err)
		}
		if n == 0 {
			continue
		} // No transformed bytes reached the stream.
		before := r.bytes()
		n, err = c.Write([]byte("must not replay"))
		if n != 0 || !errors.Is(err, sentinel) || !bytes.Equal(before, r.bytes()) {
			t.Fatal("error not terminal")
		}
	}
}
func TestFragmentShortWriteWithoutError(t *testing.T) {
	c, r := newFragmentRecorder(10)
	r.limit = 7
	n, err := c.Write(fragmentHello(100))
	if n != 7 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(n, err)
	}
}
func TestFragmentInvalidRangesFailWithoutWriting(t *testing.T) {
	for _, fragment := range []TLSFragment{
		{Size: opts.IntRange{Min: 0, Max: 0}}, {Size: opts.IntRange{Min: 0, Max: 10}}, {Size: opts.IntRange{Min: 20, Max: 10}}, {Size: opts.IntRange{Min: 1, Max: 65536}},
		{Size: opts.IntRange{Min: 10, Max: 10}, Sleep: opts.IntRange{Min: 10, Max: 2}}, {Size: opts.IntRange{Min: 10, Max: 10}, Sleep: opts.IntRange{Max: 1 << 63}},
	} {
		c, r := newFragmentRecorder(10)
		c.fragment = fragment
		n, err := c.Write(fragmentHello(100))
		if n != 0 || err == nil || len(r.bytes()) != 0 {
			t.Fatal(n, err)
		}
	}
}
func TestFragmentRangeParsing(t *testing.T) {
	for _, value := range []string{"", "0", "0-10", "10-20-30", "20-10", "-1", "65536", "1-65536", "18446744073709551615", "10-ms", " 10"} {
		if _, err := parseTLSFragmentRange(value, 1); err == nil {
			t.Fatal("accepted size", value)
		}
	}
	for _, value := range []string{"1", "10-100", "65535"} {
		if _, err := parseTLSFragmentRange(value, 1); err != nil {
			t.Fatal(value, err)
		}
	}
	for _, value := range []string{"0", "0-100", "65535"} {
		if _, err := parseTLSFragmentRange(value, 0); err != nil {
			t.Fatal(value, err)
		}
	}
}
func TestFragmentCopyCannotUnwrapWriter(t *testing.T) {
	c, r := newFragmentRecorder(10)
	b := fragmentHello(200)
	n, err := bufio.Copy(c, bytes.NewReader(b))
	if n != int64(len(b)) || err != nil {
		t.Fatal(n, err)
	}
	data, count := fragmentPayload(t, r.bytes())
	if count != 20 || !bytes.Equal(data, b[5:]) {
		t.Fatalf("copy bypassed writer: %d records", count)
	}
}
func TestFragmentCloseInterruptsPause(t *testing.T) {
	c, r := newFragmentRecorder(10)
	r.first = make(chan struct{})
	c.fragment.Sleep = opts.IntRange{Min: 65535, Max: 65535}
	result := make(chan error, 1)
	go func() { _, err := c.Write(fragmentHello(200)); result <- err }()
	<-r.first
	c.Close()
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt pause")
	}
}
func TestFragmentChangedDeadlineInterruptsPause(t *testing.T) {
	for _, all := range []bool{false, true} {
		c, r := newFragmentRecorder(10)
		r.first = make(chan struct{})
		c.fragment.Sleep = opts.IntRange{Min: 65535, Max: 65535}
		result := make(chan error, 1)
		go func() { _, err := c.Write(fragmentHello(200)); result <- err }()
		<-r.first
		if all {
			c.SetDeadline(time.Now().Add(20 * time.Millisecond))
		} else {
			c.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
		}
		select {
		case err := <-result:
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			c.Close()
			t.Fatal("deadline did not interrupt pause")
		}
		c.Close()
	}
}
func TestFragmentClearedDeadlineAllowsWrite(t *testing.T) {
	c, _ := newFragmentRecorder(10)
	c.SetWriteDeadline(time.Now().Add(-time.Second))
	c.SetWriteDeadline(time.Time{})
	n, err := c.Write(fragmentHello(200))
	if n != 205 || err != nil {
		t.Fatal(n, err)
	}
}
func TestFragmentNoDelayAfterFinalRecord(t *testing.T) {
	c, _ := newFragmentRecorder(1000)
	c.fragment.Sleep = opts.IntRange{Min: 65535, Max: 65535}
	result := make(chan error, 1)
	go func() {
		n, err := c.Write(fragmentHello(200))
		if n != 205 && err == nil {
			err = io.ErrShortWrite
		}
		result <- err
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		c.Close()
		t.Fatal("slept after final write")
	}
}
func TestFragmentConcurrentWritesStaySeparate(t *testing.T) {
	c, r := newFragmentRecorder(10)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			n, err := c.Write(fragmentHello(200))
			if n != 205 || err != nil {
				t.Error(n, err)
			}
		})
	}
	wg.Wait()
	data, count := fragmentPayload(t, r.bytes())
	want := bytes.Repeat(fragmentHello(200)[5:], 8)
	if count != 160 || !bytes.Equal(data, want) {
		t.Fatal("concurrent writes interleaved")
	}
}
func TestFragmentConcurrentCloseAndDeadlines(t *testing.T) {
	c, r := newFragmentRecorder(10)
	r.first = make(chan struct{})
	c.fragment.Sleep = opts.IntRange{Min: 65535, Max: 65535}
	result := make(chan error, 1)
	go func() { _, err := c.Write(fragmentHello(200)); result <- err }()
	<-r.first
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Go(func() { c.SetDeadline(time.Now().Add(time.Hour)); c.SetWriteDeadline(time.Now()); c.Close() })
	}
	wg.Wait()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("write succeeded after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("write leaked")
	}
}
func TestFragmentVerifiedTLSHandshakeAndData(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fragment.fixture.invalid"}, DNSNames: []string{"fragment.fixture.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	left.SetDeadline(time.Now().Add(3 * time.Second))
	right.SetDeadline(time.Now().Add(3 * time.Second))
	fragmented := &fragmentConn{conn: left, fragment: TLSFragment{Enabled: true, Size: opts.IntRange{Min: 10, Max: 100}, Sleep: opts.IntRange{Min: 0, Max: 1}}}
	client := tls.Client(fragmented, &tls.Config{ServerName: "fragment.fixture.invalid", RootCAs: roots})
	server := tls.Server(right, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	done := make(chan error, 1)
	go func() {
		if err := server.Handshake(); err != nil {
			done <- err
			return
		}
		b := make([]byte, 7)
		_, err := io.ReadFull(server, b)
		if err == nil && !bytes.Equal(b, []byte("request")) {
			err = errors.New("request corrupted")
		}
		if err == nil {
			_, err = server.Write([]byte("response"))
		}
		done <- err
	}()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if len(client.ConnectionState().VerifiedChains) != 1 {
		t.Fatal("certificate not verified")
	}
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 8)
	if _, err := io.ReadFull(client, b); err != nil || !bytes.Equal(b, []byte("response")) {
		t.Fatal(string(b), err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestFragmentExpiredDeadlineCanBeResetBeforeAnyBytes(t *testing.T) {
	c, r := newFragmentRecorder(10)
	c.SetWriteDeadline(time.Now().Add(-time.Second))
	n, err := c.Write(fragmentHello(200))
	if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) || len(r.bytes()) != 0 {
		t.Fatal(n, err)
	}
	c.SetWriteDeadline(time.Time{})
	n, err = c.Write(fragmentHello(200))
	if n != 205 || err != nil {
		t.Fatal(n, err)
	}
}
