//go:build linux

package tundns

import (
	"bufio"
	"context"
	"errors"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/prop"
)

const testLinkPath = dbus.ObjectPath("/org/freedesktop/resolve1/link/_9")

type fixtureManager struct {
	mu         sync.Mutex
	memory     memoryClient
	properties *prop.Properties
}

func (f *fixtureManager) GetLink(index int32) (dbus.ObjectPath, *dbus.Error) {
	if index != 9 {
		return "", dbus.NewError("org.freedesktop.resolve1.NoSuchLink", []any{"fixture index"})
	}
	return testLinkPath, nil
}
func (f *fixtureManager) change(name string, index int32, value any) *dbus.Error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if index != 9 {
		return dbus.NewError("org.freedesktop.resolve1.NoSuchLink", nil)
	}
	if f.memory.Call(context.Background(), name, index, value) != nil {
		return dbus.NewError("org.freedesktop.DBus.Error.Failed", []any{"fixture refusal"})
	}
	for key, value := range map[string]any{"DNS": f.memory.dns, "Domains": f.memory.domains, "DefaultRoute": f.memory.route, "DNSOverTLS": f.memory.tls, "DNSSEC": f.memory.dnssec} {
		f.properties.SetMust(linkInterface, key, value)
	}
	return nil
}
func (f *fixtureManager) SetLinkDNS(i int32, v []DNS) *dbus.Error {
	return f.change("SetLinkDNS", i, v)
}
func (f *fixtureManager) SetLinkDomains(i int32, v []Domain) *dbus.Error {
	return f.change("SetLinkDomains", i, v)
}
func (f *fixtureManager) SetLinkDefaultRoute(i int32, v bool) *dbus.Error {
	return f.change("SetLinkDefaultRoute", i, v)
}
func (f *fixtureManager) SetLinkDNSOverTLS(i int32, v string) *dbus.Error {
	return f.change("SetLinkDNSOverTLS", i, v)
}
func (f *fixtureManager) SetLinkDNSSEC(i int32, v string) *dbus.Error {
	return f.change("SetLinkDNSSEC", i, v)
}
func (f *fixtureManager) RevertLink(i int32) *dbus.Error { return f.change("RevertLink", i, nil) }
func privateBus(t *testing.T) func() *dbus.Conn {
	t.Helper()
	life, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(life, "dbus-daemon", "--session", "--nofork", "--nopidfile", "--print-address=1")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	address := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(out)
		if scanner.Scan() {
			address <- scanner.Text()
		} else {
			address <- ""
		}
	}()
	var endpoint string
	select {
	case endpoint = <-address:
	case <-time.After(3 * time.Second):
		t.Fatal("private bus did not publish an address")
	}
	if endpoint == "" {
		t.Fatal("private bus failed")
	}
	return func() *dbus.Conn {
		c, err := dbus.Connect(endpoint, dbus.WithContext(life))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
}
func publish(t *testing.T, conn *dbus.Conn) *fixtureManager {
	t.Helper()
	f := &fixtureManager{}
	properties := map[string]*prop.Prop{}
	for key, value := range map[string]any{"DNS": []DNS{}, "Domains": []Domain{}, "DefaultRoute": false, "DNSOverTLS": "", "DNSSEC": ""} {
		properties[key] = &prop.Prop{Value: value, Writable: false, Emit: prop.EmitTrue}
	}
	var err error
	f.properties, err = prop.Export(conn, testLinkPath, map[string]map[string]*prop.Prop{linkInterface: properties})
	if err != nil {
		t.Fatal(err)
	}
	if err = conn.Export(f, managerPath, managerInterface); err != nil {
		t.Fatal(err)
	}
	result, err := conn.RequestName(serviceName, dbus.NameFlagDoNotQueue)
	if err != nil || result != dbus.RequestNameReplyPrimaryOwner {
		t.Fatal("private resolver name unavailable", result, err)
	}
	return f
}
func TestPrivateDBusWireRoundTripAndServiceReplacement(t *testing.T) {
	dial := privateBus(t)
	service := dial()
	first := publish(t, service)
	clientBus := dial()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := ForConnection(ctx, clientBus)
	if err != nil {
		t.Fatal(err)
	}
	if err = Apply(ctx, client, own, testSpec()); err != nil {
		t.Fatal(err)
	}
	if !Matches(ctx, client, own, testSpec()) {
		t.Fatal("wire readback differs")
	}
	first.mu.Lock()
	before := len(first.memory.calls)
	first.mu.Unlock()
	if _, err = service.ReleaseName(serviceName); err != nil {
		t.Fatal(err)
	}
	second := publish(t, dial())
	if !errors.Is(client.Call(ctx, "RevertLink", int32(9)), ErrUnavailable) {
		t.Fatal("old client reached another service owner")
	}
	first.mu.Lock()
	unchanged := len(first.memory.calls) == before
	first.mu.Unlock()
	second.mu.Lock()
	empty := len(second.memory.calls) == 0
	second.mu.Unlock()
	if !unchanged || !empty {
		t.Fatal("stale service client mutated resolver")
	}
	fresh, err := ForConnection(ctx, clientBus)
	if err != nil {
		t.Fatal(err)
	}
	if err = Apply(ctx, fresh, own, testSpec()); err != nil {
		t.Fatal(err)
	}
	if err = Revert(ctx, fresh, own, testSpec()); err != nil {
		t.Fatal(err)
	}
	second.mu.Lock()
	defer second.mu.Unlock()
	if len(second.memory.dns) != 0 || len(second.memory.domains) != 0 || second.memory.route {
		t.Fatal("new service policy not cleaned up")
	}
}
func TestPrivateDBusPartialFailureReverts(t *testing.T) {
	dial := privateBus(t)
	f := publish(t, dial())
	f.mu.Lock()
	f.memory.fail = "SetLinkDomains"
	f.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := ForConnection(ctx, dial())
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(Apply(ctx, client, own, testSpec()), ErrApply) {
		t.Fatal("wire mutation failure accepted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.memory.dns) > 0 || f.memory.route || f.memory.calls[len(f.memory.calls)-1] != "RevertLink" {
		t.Fatal("partial wire policy retained")
	}
}
