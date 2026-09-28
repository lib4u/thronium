//go:build linux

package tunsession

// These signatures cover exactly the desktop's restricted sing-tun 0.9.1
// auto_route configuration. Unknown rules are never deleted by recovery.
import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"syscall"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

const Interface = "thronium-tun"
const Priority = 18900

type signature struct {
	Family, Action, SrcBits, DstBits, Tos byte
	Flags, Table, Priority                uint32
	Attrs                                 map[uint16]string
}

func (s signature) key() string {
	attrs := map[uint16]string{}
	for k, v := range s.Attrs {
		attrs[k] = hex.EncodeToString([]byte(v))
	}
	s.Attrs = attrs
	b, _ := json.Marshal(s)
	return string(b)
}
func integer(n uint32) string {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, n)
	return string(b)
}

// Preserve the complete netlink payload for exact deletion, including the action
// (RuleList in the pinned netlink library drops that field).
func ruleSignature(body []byte) (signature, error) {
	if len(body) < 12 {
		return signature{}, fmt.Errorf("short routing rule")
	}
	s := signature{Family: body[0], DstBits: body[1], SrcBits: body[2], Tos: body[3], Table: uint32(body[4]), Action: body[7], Flags: binary.NativeEndian.Uint32(body[8:12]) &^ (unix.FIB_RULE_UNRESOLVED | unix.FIB_RULE_IIF_DETACHED | unix.FIB_RULE_OIF_DETACHED), Attrs: map[uint16]string{}}
	for rest := body[12:]; len(rest) > 0; {
		if len(rest) < 4 {
			return s, fmt.Errorf("short rule attribute")
		}
		n, kind := int(binary.NativeEndian.Uint16(rest)), binary.NativeEndian.Uint16(rest[2:])
		if n < 4 || n > len(rest) || (n+3)&^3 > len(rest) {
			return s, fmt.Errorf("invalid rule attribute")
		}
		value := rest[4:n]
		switch kind {
		case 6:
			if len(value) != 4 {
				return s, fmt.Errorf("priority")
			}
			s.Priority = binary.NativeEndian.Uint32(value)
		case 15:
			if len(value) != 4 {
				return s, fmt.Errorf("table")
			}
			s.Table = binary.NativeEndian.Uint32(value)
		case 13, 14:
			if len(value) != 4 || binary.NativeEndian.Uint32(value) != 0xffffffff {
				s.Attrs[kind] = string(value)
			}
		case 21:
			if len(value) != 1 || value[0] != 0 {
				s.Attrs[kind] = string(value)
			} // FRA_PROTOCOL
		default:
			s.Attrs[kind] = string(value)
		}
		rest = rest[(n+3)&^3:]
	}
	// Newer kernels add a full destination-port mask for a single-port range.
	// It is equivalent to the legacy range only when both endpoints match.
	if mask, ok := s.Attrs[29]; ok && mask == "\xff\xff" {
		if port := s.Attrs[24]; len(port) == 4 && port[:2] == port[2:] {
			delete(s.Attrs, 29)
		}
	}
	return s, nil
}

func expectedSignature(r *netlink.Rule) string {
	s := signature{Family: byte(r.Family), Priority: uint32(r.Priority), Attrs: map[uint16]string{}}
	if r.Table >= 0 {
		s.Table = uint32(r.Table)
		s.Action = unix.FR_ACT_TO_TBL
	} else if r.Goto >= 0 {
		s.Action = unix.FR_ACT_GOTO
	} else {
		s.Action = unix.FR_ACT_NOP
	}
	if r.Type != 0 {
		s.Action = r.Type
	}
	if r.Invert {
		s.Flags = 2
	}
	if r.Src.IsValid() {
		s.SrcBits = byte(r.Src.Bits())
		s.Attrs[2] = string(r.Src.Addr().AsSlice())
	}
	if r.Dst.IsValid() {
		s.DstBits = byte(r.Dst.Bits())
		s.Attrs[1] = string(r.Dst.Addr().AsSlice())
	}
	if r.MarkSet {
		s.Attrs[10] = integer(r.Mark)
		s.Attrs[16] = integer(0xffffffff)
	}
	if r.IifName != "" {
		s.Attrs[3] = r.IifName + "\x00"
	}
	if r.Goto >= 0 {
		s.Attrs[4] = integer(uint32(r.Goto))
	}
	if r.SuppressPrefixlen >= 0 {
		s.Attrs[14] = integer(uint32(r.SuppressPrefixlen))
	}
	if r.Dport != nil {
		b := make([]byte, 4)
		binary.NativeEndian.PutUint16(b, r.Dport.Start)
		binary.NativeEndian.PutUint16(b[2:], r.Dport.End)
		s.Attrs[24] = string(b)
	}
	return s.key()
}

func (j *journal) expected() map[string]bool {
	wanted := map[string]bool{}
	add := func(family, priority int, change func(*netlink.Rule)) {
		r := netlink.NewRule()
		r.Family = family
		r.Priority = priority
		change(r)
		wanted[expectedSignature(r)] = true
	}
	if j.Bridge {
		for _, f := range []int{unix.AF_INET, unix.AF_INET6} {
			add(f, bridgePriority, func(r *netlink.Rule) { r.IifName = bridgeInterface; r.Table = unix.RT_TABLE_MAIN })
			add(f, bridgePriority+1, func(r *netlink.Rule) {
				r.Table = unix.RT_TABLE_MAIN
				if f == unix.AF_INET {
					r.Dst = netip.MustParsePrefix(bridgeIPv4 + "/32")
				} else {
					r.Dst = netip.MustParsePrefix(bridgeIPv6 + "/128")
				}
			})
		}
	}
	if j.Redirect {
		for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
			if family == unix.AF_INET6 && !j.IPv6 {
				continue
			}
			add(family, Priority, func(r *netlink.Rule) { r.MarkSet = true; r.Mark = uint32(j.Table + 1); r.Goto = Priority + 2 })
			add(family, Priority+1, func(r *netlink.Rule) { r.MarkSet = true; r.Mark = uint32(j.Table); r.Table = j.Table })
			add(family, Priority+2, func(r *netlink.Rule) {})
			add(family, fallbackPriority, func(r *netlink.Rule) { r.Table = j.Table })
			add(family, 1, func(r *netlink.Rule) { r.Table = j.Table + 3 })
		}
		return wanted
	}
	v4 := netip.MustParsePrefix("172.19.0.0/30")
	v6 := netip.MustParsePrefix("fdfe:dcba:9876::/126")
	if j.IPv4CIDR != "" {
		v4 = netip.MustParsePrefix(j.IPv4CIDR).Masked()
	}
	if j.IPv6CIDR != "" {
		v6 = netip.MustParsePrefix(j.IPv6CIDR).Masked()
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		p := Priority
		if family == unix.AF_INET6 && !j.IPv6 {
			if j.Strict {
				add(family, p, func(r *netlink.Rule) { r.Type = unix.FR_ACT_UNREACHABLE })
			}
			continue
		}
		if family == unix.AF_INET {
			add(family, p, func(r *netlink.Rule) { r.Dst = v4; r.Table = j.Table })
			p++
		}
		add(family, p, func(r *netlink.Rule) { r.Table = j.Table; r.SuppressPrefixlen = 0 })
		p++
		add(family, p, func(r *netlink.Rule) {
			r.Invert = true
			r.Dport = netlink.NewRulePortRange(53, 53)
			r.Table = unix.RT_TABLE_MAIN
			r.SuppressPrefixlen = 0
		})
		add(family, p, func(r *netlink.Rule) { r.IifName = Interface; r.Goto = Priority + 10 })
		if family == unix.AF_INET {
			p++
			add(family, p, func(r *netlink.Rule) { r.Invert = true; r.IifName = "lo"; r.Table = j.Table })
			for _, source := range []netip.Prefix{netip.MustParsePrefix("0.0.0.0/32"), v4} {
				add(family, p, func(r *netlink.Rule) { r.IifName = "lo"; r.Src = source; r.Table = j.Table })
			}
		} else {
			for _, source := range []netip.Prefix{netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1")} {
				add(family, p, func(r *netlink.Rule) { r.IifName = "lo"; r.Src = source; r.Goto = Priority + 10 })
			}
			p++
			add(family, p, func(r *netlink.Rule) { r.IifName = "lo"; r.Src = v6; r.Table = j.Table })
			p++
			add(family, p, func(r *netlink.Rule) { r.Table = j.Table })
		}
		add(family, Priority+10, func(r *netlink.Rule) {})
	}
	return wanted
}

func routingRules() ([][]byte, error) {
	data, err := syscall.NetlinkRIB(unix.RTM_GETRULE, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	messages, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return nil, err
	}
	var result [][]byte
	for _, message := range messages {
		if message.Header.Type == unix.RTM_NEWRULE {
			result = append(result, message.Data)
		}
	}
	return result, nil
}

func deleteRule(body []byte) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2})
	message := make([]byte, 16+len(body))
	binary.NativeEndian.PutUint32(message, uint32(len(message)))
	binary.NativeEndian.PutUint16(message[4:], unix.RTM_DELRULE)
	binary.NativeEndian.PutUint16(message[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(message[8:], 1)
	copy(message[16:], body)
	if err = unix.Sendto(fd, message, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	answer := make([]byte, 8192)
	n, _, err := unix.Recvfrom(fd, answer, 0)
	if err != nil {
		return err
	}
	if n < 20 || binary.NativeEndian.Uint16(answer[4:]) != unix.NLMSG_ERROR {
		return fmt.Errorf("invalid netlink acknowledgement")
	}
	code := int32(binary.NativeEndian.Uint32(answer[16:]))
	if code == 0 || code == -int32(unix.ENOENT) {
		return nil
	}
	return syscall.Errno(-code)
}
