import type * as Wire from '../shared/api/generated/commands';
import { allTraffic } from '../profiles/wireguardDefaults.ts';
export type WarpConfig = Wire.WarpConfig;
export function settingsValues(config: WarpConfig) {
  return {
    warp_private_key: config.privateKey,
    warp_public_key: config.peerPublicKey,
    warp_ep: config.endpoint,
    warp_ifc_addrs: [...config.addresses],
    warp_reserved: config.reserved.map(String),
  };
}
export function profileValues(current: Record<string, unknown>, config: WarpConfig) {
  return {
    ...current,
    private_key: config.privateKey,
    address: [...config.addresses],
    mtu: config.mtu,
    peers: [
      {
        address: config.host,
        port: config.port,
        public_key: config.peerPublicKey,
        allowed_ips: allTraffic(),
        persistent_keepalive_interval: config.persistentKeepalive,
        reserved: [...config.reserved],
      },
    ],
  };
}
export function profileDraft<
  T extends { text: string; buffers: Record<string, string>; invalid: Record<string, boolean> },
>(current: T, config: WarpConfig): T {
  const replaced = (path: string) =>
    ['private_key', 'address', 'mtu', 'peers'].some((key) => path === key || path.startsWith(key + '.'));
  return {
    ...current,
    text: JSON.stringify(profileValues(JSON.parse(current.text), config), null, 2),
    buffers: Object.fromEntries(Object.entries(current.buffers).filter(([key]) => !replaced(key))),
    invalid: Object.fromEntries(Object.entries(current.invalid).filter(([key]) => !replaced(key))),
  };
}
