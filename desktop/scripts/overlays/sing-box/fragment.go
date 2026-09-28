package dialer

// Thronium: bounded TLS ClientHello record fragmentation. Keep the original
// byte stream and net.Conn write/deadline semantics across inserted headers.
import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	opts "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

type TLSFragment struct {
	Enabled     bool
	Sleep, Size opts.IntRange
}

// Keep validation local: Parse2IntRange is also used by unrelated TLS tricks.
func parseTLSFragmentRange(value string, minimum uint64) (opts.IntRange, error) {
	parts := strings.Split(value, "-")
	var result opts.IntRange
	if len(parts) < 1 || len(parts) > 2 {
		return result, fmt.Errorf("expected an integer or min-max range")
	}
	values := make([]uint64, len(parts))
	for i, part := range parts {
		number, err := strconv.ParseUint(part, 10, 64)
		if err != nil || number < minimum || number > 65535 {
			return result, fmt.Errorf("TLS fragment range must be within %d..65535", minimum)
		}
		values[i] = number
	}
	result.Min, result.Max = values[0], values[len(values)-1]
	if result.Min > result.Max {
		return result, fmt.Errorf("TLS fragment range is reversed")
	}
	return result, nil
}

type fragmentConn struct {
	conn        net.Conn
	err         error
	dialer      net.Dialer
	destination M.Socksaddr
	network     string
	fragment    TLSFragment
	writeMu     sync.Mutex
	writeErr    error
	stateOnce   sync.Once
	stateMu     sync.Mutex
	done        chan struct{}
	changed     chan struct{}
	deadline    time.Time
	closed      bool
}

func (c *fragmentConn) initState() {
	c.stateOnce.Do(func() { c.done = make(chan struct{}); c.changed = make(chan struct{}) })
}

func isClientHelloPacket(b []byte) bool {
	if len(b) < 6 || b[0] != 22 || uint16(b[1])<<8|uint16(b[2]) < 0x0301 || b[5] != 1 {
		return false
	}
	size := int(b[3])<<8 | int(b[4])
	return size > 0 && size <= len(b)-5
}

// Pauses are part of Write: Close and changed write deadlines must interrupt
// them too, even while no system call is outstanding.
func (c *fragmentConn) pause(delay time.Duration) error {
	c.initState()
	end := time.Now().Add(delay)
	for {
		c.stateMu.Lock()
		closed, deadline, changed := c.closed, c.deadline, c.changed
		c.stateMu.Unlock()
		if closed {
			return net.ErrClosed
		}
		now := time.Now()
		if !deadline.IsZero() && !now.Before(deadline) {
			return os.ErrDeadlineExceeded
		}
		if !now.Before(end) {
			return nil
		}
		until := end
		if !deadline.IsZero() && deadline.Before(until) {
			until = deadline
		}
		timer := time.NewTimer(time.Until(until))
		select {
		case <-c.done:
			timer.Stop()
			return net.ErrClosed
		case <-changed:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// Count caller bytes acknowledged by a partial write of transformed records.
// Only the first record header belongs to the input; later headers are added.
func fragmentInputCount(queue []byte, written int, first bool) int {
	total := 0
	for offset := 0; offset < len(queue) && written > offset; {
		size := int(queue[offset+3])<<8 | int(queue[offset+4])
		header := min(5, written-offset)
		if first {
			total += header
			first = false
		}
		total += max(0, min(size, written-offset-5))
		offset += 5 + size
	}
	return total
}

func (c *fragmentConn) writeFragments(b []byte) (int, error) {
	if c.fragment.Size.Min < 1 || c.fragment.Size.Max > 65535 || c.fragment.Size.Max < c.fragment.Size.Min || c.fragment.Sleep.Max > 65535 || c.fragment.Sleep.Max < c.fragment.Sleep.Min {
		return 0, fmt.Errorf("invalid TLS fragment size or sleep range")
	}
	recordLen := 5 + (int(b[3])<<8 | int(b[4]))
	data := b[5:recordLen]
	// Preserve the pinned implementation's burst size (2..5 records). Appending
	// bounds memory by this one input record, without fixed 1/2 KiB buffers.
	burst := int(opts.GetRandomIntFromRange(1, 4)) + 1
	consumed := 0
	for offset := 0; offset < len(data); {
		queue := make([]byte, 0, min(recordLen+25, 5*(int(c.fragment.Size.Max)+5)))
		for i := 0; i < burst && offset < len(data); i++ {
			size := min(int(opts.GetRandomIntFromRange(c.fragment.Size.Min, c.fragment.Size.Max)), len(data)-offset)
			queue = append(queue, b[0], b[1], b[2], byte(size>>8), byte(size))
			queue = append(queue, data[offset:offset+size]...)
			offset += size
		}
		if err := c.pause(0); err != nil {
			return consumed, err
		}
		written, err := c.conn.Write(queue)
		if written < 0 || written > len(queue) {
			return consumed, io.ErrShortWrite
		}
		consumed += fragmentInputCount(queue, written, consumed == 0)
		if err != nil {
			return consumed, err
		}
		if written != len(queue) {
			return consumed, io.ErrShortWrite
		}
		// A completed Write needs no final sleep. Pause only before more data.
		if offset < len(data) || len(b) > recordLen {
			delay := time.Duration(opts.GetRandomIntFromRange(c.fragment.Sleep.Min, c.fragment.Sleep.Max)) * time.Millisecond
			if err := c.pause(delay); err != nil {
				return consumed, err
			}
		}
	}
	if len(b) > recordLen {
		n, err := c.conn.Write(b[recordLen:])
		if n < 0 || n > len(b)-recordLen {
			return consumed, io.ErrShortWrite
		}
		if err == nil && n != len(b)-recordLen {
			err = io.ErrShortWrite
		}
		return consumed + n, err
	}
	return consumed, nil
}

func (c *fragmentConn) Write(b []byte) (int, error) {
	if c.conn == nil {
		return 0, c.err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if isClientHelloPacket(b) {
		n, err := c.writeFragments(b)
		// After part of a transformed TLS record reaches the wire, retrying a
		// caller slice cannot reconstruct its framing. Retain the terminal error.
		if err != nil && n > 0 {
			c.writeErr = err
		}
		return n, err
	}
	return c.conn.Write(b)
}

func (c *fragmentConn) Read(b []byte) (int, error) {
	if c.conn == nil {
		return 0, c.err
	}
	return c.conn.Read(b)
}
func (c *fragmentConn) Close() error {
	c.initState()
	c.stateMu.Lock()
	if !c.closed {
		c.closed = true
		close(c.done)
	}
	c.stateMu.Unlock()
	return common.Close(c.conn)
}
func (c *fragmentConn) LocalAddr() net.Addr {
	if c.conn == nil {
		return M.Socksaddr{}
	}
	return c.conn.LocalAddr()
}
func (c *fragmentConn) RemoteAddr() net.Addr {
	if c.conn == nil {
		return M.Socksaddr{}
	}
	return c.conn.RemoteAddr()
}
func (c *fragmentConn) SetDeadline(t time.Time) error {
	if c.conn == nil {
		return os.ErrInvalid
	}
	// Serialize deadline publication with other setters. The delegate
	// updates deadline state without performing a read or write.
	c.initState()
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if err := c.conn.SetDeadline(t); err != nil {
		return err
	}
	c.deadline = t
	close(c.changed)
	c.changed = make(chan struct{})
	return nil
}
func (c *fragmentConn) SetReadDeadline(t time.Time) error {
	if c.conn == nil {
		return os.ErrInvalid
	}
	return c.conn.SetReadDeadline(t)
}
func (c *fragmentConn) SetWriteDeadline(t time.Time) error {
	if c.conn == nil {
		return os.ErrInvalid
	}
	c.initState()
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if err := c.conn.SetWriteDeadline(t); err != nil {
		return err
	}
	c.deadline = t
	close(c.changed)
	c.changed = make(chan struct{})
	return nil
}
func (c *fragmentConn) Upstream() any           { return c.conn }
func (c *fragmentConn) ReaderReplaceable() bool { return c.conn != nil }
func (c *fragmentConn) WriterReplaceable() bool { return false }
func (c *fragmentConn) LazyHeadroom() bool      { return c.conn == nil }
func (c *fragmentConn) NeedHandshake() bool     { return c.conn == nil }
func (c *fragmentConn) WriteTo(w io.Writer) (int64, error) {
	if c.conn == nil {
		return 0, c.err
	}
	return bufio.Copy(w, c.conn)
}
