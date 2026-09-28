package boxdns

import (
	"ThroneCore/internal/boxdns/winipcfg"
	"encoding/binary"
	"errors"
	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/windnsapi"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"log"
	"net"
	"strings"
)

const nameServerRegistryKey = "NameServer"

var dnsIsSet bool

func (d *DnsManager) HandleSystemDNS(ifc *control.Interface, flag int) {
	if d == nil {
		log.Println("No DnsManager, you may need to restart Throne")
		return
	}
	if ifc == nil {
		return
	}
	var err error
	if !dnsIsSet {
		err = d.restoreSystemDNS(*ifc)
	} else {
		err = d.setSystemDNS(*ifc)
	}
	if err != nil {
		log.Println("[HandleSystemDNS]", ifc.Name, err)
	}
	if d.lastIfc != nil && d.lastIfc.Index != ifc.Index {
		if err = d.restoreSystemDNS(*d.lastIfc); err != nil {
			log.Println("[HandleSystemDNS]", d.lastIfc.Name, err)
		}
	}
	// The setting moved with the default interface; the next move must take
	// it from here, not from the interface it started on.
	if dnsIsSet {
		d.lastIfc = ifc
	}
}

func (d *DnsManager) getInterfaceGuid(ifc control.Interface) (string, error) {
	if d.Monitor == nil {
		return "", E.New("No Dns Manager, you may need to restart Throne")
	}
	index := ifc.Index
	u, err := ifcIdxtoUUID(index)
	if err != nil {
		return "", err
	}
	guidStr := "{" + u.String() + "}"

	return guidStr, nil
}

func ifcIdxtoUUID(index int) (*uuid.UUID, error) {
	luid, err := winipcfg.LUIDFromIndex(uint32(index))
	if err != nil {
		log.Println("Could not get luid from index")
		return nil, err
	}
	guid, err := luid.GUID()
	if err != nil {
		log.Println("Could not get guid from luid")
		return nil, err
	}
	data1 := make([]byte, 4)
	data2 := make([]byte, 2)
	data3 := make([]byte, 2)
	binary.LittleEndian.PutUint32(data1, guid.Data1)
	binary.LittleEndian.PutUint16(data2, guid.Data2)
	binary.LittleEndian.PutUint16(data3, guid.Data3)
	u, _ := uuid.FromBytes([]byte{
		data1[3], data1[2], data1[1], data1[0],
		data2[1], data2[0],
		data3[1], data3[0],
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7],
	})
	return &u, nil
}

func (d *DnsManager) isIfcDNSDhcp(ifc control.Interface) (dhcp bool, err error) {
	if d == nil {
		log.Println("No DnsManager, you may need to restart Throne")
		return false, E.New("No Dns Manager, you may need to restart Throne")
	}

	luid, err := winipcfg.LUIDFromIndex(uint32(ifc.Index))
	if err != nil {
		log.Println("[isIfcDNSDhcp] failed to get luid from index:", err)
		return
	}

	dnsServers, err := luid.DNS()
	if err != nil {
		log.Println("[isIfcDNSDhcp] failed to get luid dns servers:", err)
		return
	}
	for _, server := range dnsServers {
		if server.String() == dhcpMarkAddr {
			return true, nil
		}
	}

	guidStr, err := d.getInterfaceGuid(ifc)
	if err != nil {
		return false, err
	}

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`+guidStr, registry.QUERY_VALUE)
	if err != nil {
		log.Println("getNameServersForInterface OpenKey:", err)
		return false, err
	}
	defer key.Close()

	if manualNSs, _, err := key.GetStringValue(nameServerRegistryKey); err == nil {
		if len(strings.TrimSpace(manualNSs)) > 0 {
			return false, nil
		}
	}

	return true, nil
}

func (d *DnsManager) restoreSystemDNS(ifx control.Interface) error {
	return restoreInterface(ifx.Index, ifx.Name)
}

func restoreInterface(index int, name string) error {
	luid, err := winipcfg.LUIDFromIndex(uint32(index))
	if err != nil {
		return E.Cause(err, "interface luid")
	}
	current, err := luid.DNS()
	if err != nil {
		return E.Cause(err, "read dns servers")
	}
	servers, dhcp, owned := originalList(current)
	if !owned {
		return nil
	}
	if dhcp {
		servers = nil
	}
	if err = luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET), servers, nil); err != nil {
		return E.Cause(err, "restore dns servers")
	}
	_ = windnsapi.FlushResolverCache()
	log.Println("[restoreSystemDNS] Local DNS Server removed for:", name)
	return nil
}

// RestoreAllMarked puts back every interface whose DNS list carries the
// mark, whichever core set it: after a crash the default interface may have
// changed, and the core that knew which one it used is gone. Interfaces
// without the mark are left alone.
func RestoreAllMarked() error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	var failed error
	for _, ifc := range interfaces {
		luid, err := winipcfg.LUIDFromIndex(uint32(ifc.Index))
		if err != nil {
			continue
		}
		current, err := luid.DNS()
		if err != nil {
			continue
		}
		if _, _, owned := originalList(current); owned {
			failed = errors.Join(failed, restoreInterface(ifc.Index, ifc.Name))
		}
	}
	return failed
}

func (d *DnsManager) setSystemDNS(ifx control.Interface) error {
	luid, err := winipcfg.LUIDFromIndex(uint32(ifx.Index))
	if err != nil {
		return E.Cause(err, "interface luid")
	}
	current, err := luid.DNS()
	if err != nil {
		return E.Cause(err, "read dns servers")
	}
	// Without knowing where the servers came from, a later restore would pin a
	// DHCP interface to today's servers; leave the interface untouched instead.
	dhcp, err := d.isIfcDNSDhcp(ifx)
	if err != nil {
		return E.Cause(err, "dns origin")
	}
	if err = luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET), ownedList(current, dhcp), nil); err != nil {
		return E.Cause(err, "set dns servers")
	}
	_ = windnsapi.FlushResolverCache()
	log.Println("[setSystemDNS] Local DNS Server added for:", ifx.Name)
	return nil
}

func (d *DnsManager) SetSystemDNS(ifc *control.Interface, clear bool) error {
	if d == nil {
		log.Println("No DnsManager, you may need to restart Throne")
		return E.New("No dns Manager, you may need to restart Throne")
	}

	if ifc == nil {
		if d.Monitor == nil {
			return E.New("No interface monitor, you may need to restart Throne")
		}
		ifc = d.Monitor.DefaultInterface()
		if ifc == nil {
			log.Println("Default interface is nil!")
			return E.New("Default interface is nil!")
		}
	}
	log.Println("[SetSystemDNS] Setting system dns for", ifc.Name, "clear is", clear)

	if clear {
		dnsIsSet = false
		return d.restoreSystemDNS(*ifc)
	}
	if err := d.setSystemDNS(*ifc); err != nil {
		return err
	}
	dnsIsSet = true
	d.lastIfc = ifc
	return nil
}
