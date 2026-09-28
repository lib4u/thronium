package process

import "encoding/binary"

// listenerOwners reads a MIB_TCPTABLE_OWNER_PID as GetExtendedTcpTable fills it
// and returns the processes listening on exactly 127.0.0.1:port. Addresses and
// ports are stored in network byte order; the rest is little-endian.
// It lives outside the Windows file so the parsing is tested everywhere.
func listenerOwners(table []byte, port uint32) []uint32 {
	const header, row, listen = 4, 24, 2
	if len(table) < header {
		return nil
	}
	count := binary.LittleEndian.Uint32(table)
	if count > 65536 || uint64(len(table)) < header+uint64(count)*row {
		return nil
	}
	var owners []uint32
	for i := range int(count) {
		entry := table[header+i*row : header+(i+1)*row]
		if binary.LittleEndian.Uint32(entry[0:]) == listen &&
			[4]byte(entry[4:8]) == [4]byte{127, 0, 0, 1} &&
			uint32(binary.BigEndian.Uint16(entry[8:10])) == port {
			owners = append(owners, binary.LittleEndian.Uint32(entry[20:]))
		}
	}
	return owners
}
