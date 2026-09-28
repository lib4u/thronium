// Package winservice is the Thronium service on Windows: it owns TUN and
// system DNS for the person's application, which itself runs without
// elevation. The application talks to it over one pipe in the same framing
// it uses with any core; the service answers the managed calls itself and
// relays the rest to a worker core it runs as SYSTEM.
package winservice

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	maxMethod  = 128
	maxPayload = 16 * 1024 * 1024
)

var errFrame = errors.New("invalid frame")

type request struct {
	id      uint32
	method  string
	payload []byte
}

func readRequest(r io.Reader) (request, error) {
	var header [6]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return request{}, err
	}
	n := int(binary.LittleEndian.Uint16(header[4:]))
	if n == 0 || n > maxMethod {
		return request{}, errFrame
	}
	method := make([]byte, n)
	if _, err := io.ReadFull(r, method); err != nil {
		return request{}, err
	}
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return request{}, err
	}
	length := binary.LittleEndian.Uint32(size[:])
	if length > maxPayload {
		return request{}, errFrame
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return request{}, err
	}
	return request{binary.LittleEndian.Uint32(header[:]), string(method), payload}, nil
}

func encodeRequest(f request) []byte {
	b := make([]byte, 10+len(f.method)+len(f.payload))
	binary.LittleEndian.PutUint32(b, f.id)
	binary.LittleEndian.PutUint16(b[4:], uint16(len(f.method)))
	copy(b[6:], f.method)
	binary.LittleEndian.PutUint32(b[6+len(f.method):], uint32(len(f.payload)))
	copy(b[10+len(f.method):], f.payload)
	return b
}

// A response: the request id, 0 for data or 1 for an error text, and bytes.
type response struct {
	id     uint32
	status byte
	data   []byte
}

func readResponse(r io.Reader) (response, error) {
	var header [9]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return response{}, err
	}
	length := binary.LittleEndian.Uint32(header[5:])
	if length > maxPayload || header[4] > 1 {
		return response{}, errFrame
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return response{}, err
	}
	return response{binary.LittleEndian.Uint32(header[:]), header[4], data}, nil
}

func encodeResponse(f response) []byte {
	b := make([]byte, 9+len(f.data))
	binary.LittleEndian.PutUint32(b, f.id)
	b[4] = f.status
	binary.LittleEndian.PutUint32(b[5:], uint32(len(f.data)))
	copy(b[9:], f.data)
	return b
}
