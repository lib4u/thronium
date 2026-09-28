package wireguard

import (
	"errors"
	"strconv"
	"strings"

	"github.com/sagernet/wireguard-go/device"
)

// Domain peers receive their persistent keepalive only once their endpoint
// resolver is installed. The TUN EventUp brings the device up asynchronously,
// and a keepalive handshake fired before SetEndpointResolver has no endpoint
// until the rekey retry. The standard update-only UAPI path leaves every other
// peer setting untouched.
func applyDeferredKeepalive(wg *device.Device, peers []peerConfig) error {
	for _, peer := range peers {
		if !peer.destination.IsDomain() || peer.keepalive == "" {
			continue
		}
		err := wg.IpcSet("public_key=" + peer.publicKeyHex + "\nupdate_only=true\npersistent_keepalive_interval=" + peer.keepalive + "\n")
		if err != nil {
			return err
		}
	}
	return nil
}

// The TUN EventUp handler can fail asynchronously and reset the device's port
// to zero. Complete startup and verify the requested fixed port before the Core
// reports success. The IPC state contains keys: inspect locally, never log it.
func startFixedPortDevice(wg *device.Device, port uint16) error {
	if err := wg.Up(); err != nil {
		return err
	}
	state, err := wg.IpcGet()
	if err != nil {
		return err
	}
	want := "listen_port=" + strconv.Itoa(int(port))
	for _, line := range strings.Split(state, "\n") {
		if line == want {
			return nil
		}
	}
	return errors.New("requested WireGuard listen port is unavailable")
}
