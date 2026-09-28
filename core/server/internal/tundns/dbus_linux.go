//go:build linux

package tundns

import (
	"context"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

const serviceName = "org.freedesktop.resolve1"
const managerPath = dbus.ObjectPath("/org/freedesktop/resolve1")
const managerInterface = serviceName + ".Manager"
const linkInterface = serviceName + ".Link"

type DBusClient struct {
	connection *dbus.Conn
	owner      string
}

// Open owns a private system-bus connection for the lifetime of parent. The
// initial connection/authentication and service lookup are independently bounded.
func Open(parent context.Context) (*DBusClient, func(), error) {
	life, cancel := context.WithCancel(parent)
	timer := time.AfterFunc(Timeout, cancel)
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(life))
	if err != nil {
		timer.Stop()
		cancel()
		return nil, func() {}, ErrUnavailable
	}
	stop := func() { cancel(); _ = conn.Close() }
	ctx, end := context.WithTimeout(parent, Timeout)
	client, err := ForConnection(ctx, conn)
	end()
	if !timer.Stop() || life.Err() != nil || err != nil {
		stop()
		return nil, func() {}, ErrUnavailable
	}
	return client, stop, nil
}

// ForConnection uses a caller-owned bus, including a private fixture bus. No
// global environment or host bus configuration is changed.
func ForConnection(ctx context.Context, conn *dbus.Conn) (*DBusClient, error) {
	var owner string
	if conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, serviceName).Store(&owner) != nil || !strings.HasPrefix(owner, ":") {
		return nil, ErrUnavailable
	}
	return &DBusClient{conn, owner}, nil
}
func (c *DBusClient) current(ctx context.Context) bool {
	var owner string
	return c.connection.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, serviceName).Store(&owner) == nil && owner == c.owner
}
func (c *DBusClient) Call(ctx context.Context, name string, args ...any) error {
	switch name {
	case "SetLinkDNS", "SetLinkDomains", "SetLinkDefaultRoute", "SetLinkDNSSEC", "SetLinkDNSOverTLS", "RevertLink":
	default:
		return ErrInvalid
	}
	if !c.current(ctx) {
		return ErrUnavailable
	}
	if c.connection.Object(c.owner, managerPath).CallWithContext(ctx, managerInterface+"."+name, 0, args...).Err != nil {
		return ErrApply
	}
	return nil
}
func (c *DBusClient) Property(ctx context.Context, index int32, name string, target any) error {
	switch name {
	case "DNS", "Domains", "DefaultRoute", "DNSSEC", "DNSOverTLS":
	default:
		return ErrInvalid
	}
	if !c.current(ctx) {
		return ErrUnavailable
	}
	var path dbus.ObjectPath
	if c.connection.Object(c.owner, managerPath).CallWithContext(ctx, managerInterface+".GetLink", 0, index).Store(&path) != nil {
		return ErrUnavailable
	}
	var value dbus.Variant
	if c.connection.Object(c.owner, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, linkInterface, name).Store(&value) != nil {
		return ErrUnavailable
	}
	if value.Store(target) != nil {
		return ErrUnavailable
	}
	return nil
}
