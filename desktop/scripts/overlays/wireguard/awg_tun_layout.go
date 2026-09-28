// SPDX-License-Identifier: MIT
package device

import "golang.org/x/crypto/poly1305"

// A TUN Read chooses its offset before blocking. The initial IPC configuration
// can change S4 while it waits; move the returned IP payload before encryption.
func prepareTUNOutbound(elem *QueueOutboundElement, readOffset, size int, padding uint32) bool {
	if size <= 0 || readOffset < 0 || readOffset > len(elem.buffer) || size > len(elem.buffer)-readOffset {
		return false
	}
	offset64 := int64(MessageEncapsulatingTransportSize) + int64(padding) + int64(MessageTransportHeaderSize)
	if offset64 > int64(len(elem.buffer)) {
		return false
	}
	offset := int(offset64)
	if size > len(elem.buffer)-offset-poly1305.TagSize {
		return false
	}
	copy(elem.buffer[offset:offset+size], elem.buffer[readOffset:readOffset+size])
	elem.padding = padding
	elem.isKeepalive = false
	elem.packet = elem.buffer[offset : offset+size]
	return true
}
