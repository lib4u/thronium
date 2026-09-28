// WireGuard and AmneziaWG configuration files.
import type { Draft } from '../api';
import { awgFields, parse, type Config } from './schema.ts';
import { allTraffic } from './wireguardDefaults.ts';
import { fail, number, boolean, list, draft } from './importValues.ts';

// wg-quick directives are classified, never executed: interface settings the
// userspace endpoint has no field for, and host actions that stay unapplied.
const wgQuickSettings = new Set(['dns', 'table', 'fwmark']);
const wgQuickActions = new Set(['preup', 'postup', 'predown', 'postdown', 'saveconfig']);
export function parseWireGuard(
  text: string,
  groupId: string,
  name = 'WireGuard',
): { draft: Draft; warnings: string[] } {
  const config: Config = { type: 'wireguard', peers: [] };
  const peers = config.peers as Config[];
  const warnings = new Set<string>();
  let current: Config | null = null;
  let section = '';
  let sawInterface = false;
  const normalized = (key: string) => key.toLowerCase().replace(/_/g, '');
  const awg = new Map(awgFields.map((f) => [normalized(f.path.split('.').slice(-1)[0]), f]));
  for (const line of text.split(/\r?\n/)) {
    const clean = line.replace(/\s*[#;].*$/, '').trim();
    if (!clean) continue;
    if (clean.startsWith('[')) {
      section = clean.toLowerCase();
      if (section === '[interface]') {
        if (sawInterface) return fail('multiple_interfaces');
        current = config;
        sawInterface = true;
      } else if (section === '[peer]') {
        current = {};
        peers.push(current);
      } else return fail('unsupported_section');
      continue;
    }
    if (!current || !clean.includes('=')) return fail('invalid_wireguard');
    const at = clean.indexOf('=');
    const key = normalized(clean.slice(0, at).trim());
    const value = clean.slice(at + 1).trim();
    if (section === '[interface]') {
      if (key === 'privatekey') config.private_key = value;
      else if (key === 'address')
        config.address = [
          ...((config.address as string[]) || []),
          ...list(value).map((ip) => (ip.includes('/') ? ip : ip + (ip.includes(':') ? '/128' : '/32'))),
        ];
      else if (['mtu', 'listenport'].includes(key))
        config[key === 'mtu' ? 'mtu' : 'listen_port'] = number(value, 65535);
      else if (awg.has(key)) {
        const field = awg.get(key)!;
        config.amnezia_wg ||= {};
        (config.amnezia_wg as Config)[field.path.split('.').slice(-1)[0]] = parse(
          field,
          field.kind === 'bool' ? String(boolean(value)) : value,
        );
      } else
        warnings.add(
          (wgQuickActions.has(key) ? 'wg-action:' : wgQuickSettings.has(key) ? 'wg-setting:' : 'wg:') +
            clean.slice(0, at).trim(),
        );
    } else {
      if (key === 'publickey') current.public_key = value;
      else if (['presharedkey', 'psk'].includes(key)) current.pre_shared_key = value;
      else if (key === 'allowedips')
        current.allowed_ips = [...((current.allowed_ips as string[]) || []), ...list(value)];
      else if (['persistentkeepalive', 'persistentkeepaliveinterval'].includes(key))
        current.persistent_keepalive_interval = parse(
          { path: '', label: 'profiles.port_651531e', kind: 'range' },
          value,
        );
      else if (key === 'endpoint') {
        let endpoint: URL;
        try {
          endpoint = new URL('wg://' + value);
        } catch {
          return fail('invalid_endpoint');
        }
        if (!endpoint.hostname || !endpoint.port || endpoint.username || endpoint.pathname)
          return fail('invalid_endpoint');
        current.address = endpoint.hostname.replace(/^\[|\]$/g, '');
        current.port = number(endpoint.port, 65535, 1);
      } else if (key === 'reserved') current.reserved = list(value).map((s) => number(s, 255));
      else warnings.add('wg:' + clean.slice(0, at).trim());
    }
  }
  if (!sawInterface || !config.private_key || !peers.length || peers.some((p) => !p.public_key))
    return fail('missing_key');
  if (!(config.address as unknown[])?.length) return fail('missing_address');
  for (const peer of peers)
    if (!peer.allowed_ips) {
      peer.allowed_ips = allTraffic();
      warnings.add('wg-default-allowed');
    }
  return {
    draft: draft(config, groupId, name === 'WireGuard' && config.amnezia_wg ? 'AmneziaWG' : name),
    warnings: [...warnings],
  };
}
