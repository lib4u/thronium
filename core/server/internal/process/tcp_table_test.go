package process

import (
	"encoding/binary"
	"slices"
	"testing"
)

func tcpRow(state uint32, address [4]byte, port uint16, pid uint32) []byte {
	row := make([]byte, 24)
	binary.LittleEndian.PutUint32(row[0:], state)
	copy(row[4:8], address[:])
	binary.BigEndian.PutUint16(row[8:10], port)
	binary.BigEndian.PutUint16(row[16:18], 443)
	binary.LittleEndian.PutUint32(row[20:], pid)
	return row
}

func tcpTable(rows ...[]byte) []byte {
	table := binary.LittleEndian.AppendUint32(nil, uint32(len(rows)))
	for _, row := range rows {
		table = append(table, row...)
	}
	return table
}

func TestListenerOwnersNamesOnlyExactLoopbackListeners(t *testing.T) {
	loopback := [4]byte{127, 0, 0, 1}
	table := tcpTable(
		tcpRow(2, loopback, 1080, 10),
		tcpRow(5, loopback, 1080, 11),            // established, not listening
		tcpRow(2, [4]byte{0, 0, 0, 0}, 1080, 12), // every address, not ours to vouch for
		tcpRow(2, [4]byte{127, 0, 0, 2}, 1080, 13),
		tcpRow(2, loopback, 1081, 14),
		tcpRow(2, loopback, 1080, 15),
	)
	if got := listenerOwners(table, 1080); !slices.Equal(got, []uint32{10, 15}) {
		t.Fatal(got)
	}
	// Byte order matters: port 0x3804 is not 0x0438 (1080).
	if got := listenerOwners(table, 0x3804); got != nil {
		t.Fatal(got)
	}
	for cut := range len(table) {
		if listenerOwners(table[:cut], 1080) != nil {
			t.Fatal(cut)
		}
	}
	lying := binary.LittleEndian.AppendUint32(nil, 1<<31)
	if listenerOwners(lying, 1080) != nil {
		t.Fatal("count beyond the buffer")
	}
}
