//go:build linux

package tunsession

// Reserve our own table before the worker starts. The comment survives sing-tun's
// AddTable call; a replacement table has a different handle and is never deleted.
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
	"io"
	"os/exec"
	"time"
)

const firewallTable = "thronium-auto-redirect"
const fallbackPriority = 58900

func nft(input string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/nft", args...)
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin"}
	cmd.Stdin = bytes.NewBufferString(input)
	var out limitedBuffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("tun_firewall_unavailable")
	}
	return out.Bytes(), nil
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 2*1024*1024 {
		return 0, fmt.Errorf("tun_firewall_output_limit")
	}
	return b.Buffer.Write(p)
}

type firewallRecord struct {
	Family  string `json:"family"`
	Name    string `json:"name"`
	Comment string `json:"comment"`
	Handle  uint64 `json:"handle"`
}

func firewallState(names ...string) (*firewallRecord, error) {
	name := firewallTable
	if len(names) > 0 {
		name = names[0]
	}
	b, err := nft("", "-j", "list", "tables")
	if err != nil {
		return nil, err
	}
	var data struct {
		Entries []struct {
			Table *firewallRecord `json:"table"`
		} `json:"nftables"`
	}
	if json.Unmarshal(b, &data) != nil {
		return nil, fmt.Errorf("tun_firewall_unavailable")
	}
	for _, entry := range data.Entries {
		if entry.Table != nil && entry.Table.Name == name && entry.Table.Family == "inet" {
			return entry.Table, nil
		}
	}
	return nil, nil
}
func (j *journal) firewallTables() []string {
	var names []string
	if j.Redirect {
		names = append(names, firewallTable)
	}
	if j.Bridge {
		names = append(names, bridgeFirewall)
	}
	return names
}
func (j *journal) createFirewall() error {
	for _, name := range j.firewallTables() {
		if _, err := nft(fmt.Sprintf("create table inet %s { comment \"thronium:%s\"; }", name, j.FirewallToken), "-f", "-"); err != nil {
			return err
		}
	}
	return nil
}
func (j *journal) clearFirewall() error {
	for _, name := range j.firewallTables() {
		table, err := firewallState(name)
		if err != nil {
			return err
		}
		if table == nil || table.Comment != "thronium:"+j.FirewallToken {
			continue
		}
		data, _ := json.Marshal(map[string]any{"nftables": []any{map[string]any{"delete": map[string]any{"table": map[string]any{"family": "inet", "handle": table.Handle}}}}})
		if _, err = nft(string(data), "-j", "-f", "-"); err != nil {
			return fmt.Errorf("tun_cleanup_pending")
		}
	}
	return nil
}

func (j *journal) clearRedirectRoutes() error {
	if !j.Redirect {
		return nil
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: j.Table + 3}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	for _, route := range routes {
		if route.Protocol != 253 || route.Type != unix.RTN_LOCAL || route.Dst == nil || !route.Dst.IP.IsLoopback() || (route.Scope != netlink.SCOPE_HOST && !(route.Dst.IP.To4() == nil && route.Scope == netlink.SCOPE_UNIVERSE)) {
			continue
		}
		ones, bits := route.Dst.Mask.Size()
		if ones != bits {
			continue
		}
		if err = netlink.RouteDel(&route); err != nil {
			return err
		}
	}
	return nil
}
