import type { Draft, VpnPolicy } from '../api.ts';

const keys = ['onlyAdvertisedRoutes', 'useTunnelDns', 'blockOutsideDns'] as const;
/** A primary VPN endpoint draft (engine `vpn_endpoint`): OpenVPN or OpenConnect as a sing-box outbound. */
const vpnEndpointDraft = (profile: Pick<Draft, 'kind' | 'config'>) =>
  profile.kind === 'sing-box-outbound' &&
  ['openvpn-client', 'openconnect'].includes(String(profile.config?.type));
/** A Tailscale node carries only Qt's `globalDNS`, as its tunnel DNS. */
export const tailscaleNodeDraft = (profile: Pick<Draft, 'kind' | 'config'>) =>
  profile.kind === 'sing-box-outbound' && String(profile.config?.type) === 'tailscale';
export const policyDraft = (profile: Pick<Draft, 'kind' | 'config'>) =>
  vpnEndpointDraft(profile) || tailscaleNodeDraft(profile);
export function parseVpnPolicy(value: unknown, profile: Pick<Draft, 'kind' | 'config'>): VpnPolicy {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).length !== keys.length ||
    keys.some((key) => typeof (value as Record<string, unknown>)[key] !== 'boolean')
  ) {
    throw Error('vpn_policy_invalid');
  }
  if (!policyDraft(profile)) {
    throw Error('vpn_policy_profile_unsupported');
  }
  const policy = value as VpnPolicy;
  if (tailscaleNodeDraft(profile) && (policy.onlyAdvertisedRoutes || policy.blockOutsideDns)) {
    throw Error('vpn_policy_profile_unsupported');
  }
  return Object.fromEntries(keys.map((key) => [key, (value as VpnPolicy)[key]])) as VpnPolicy;
}

/** Run after JSON.parse validates syntax. Inspect only bundle metadata; skip
 * arbitrary Core JSON without interpreting or rewriting its keys or numbers. */
export function assertVpnPolicyWire(text: string): void {
  let i = 0;
  const space = () => {
    while (/\s/.test(text[i] || '') && i < text.length) i++;
  };
  function string(): string {
    const start = i++;
    while (i < text.length) {
      if (text[i] === '\\') {
        i += 2;
        continue;
      }
      if (text[i++] === '"') return JSON.parse(text.slice(start, i)) as string;
    }
    throw Error('invalid_profile_bundle');
  }
  function skip(): void {
    space();
    if (text[i] === '"') {
      string();
      return;
    }
    if (text[i] !== '{' && text[i] !== '[') {
      while (i < text.length && !/[\s,}\]]/.test(text[i])) i++;
      return;
    }
    let depth = 0;
    do {
      if (text[i] === '"') {
        string();
        continue;
      }
      if (text[i] === '{' || text[i] === '[') depth++;
      if (text[i] === '}' || text[i] === ']') depth--;
      i++;
    } while (depth && i < text.length);
  }
  function object(mode: 'bundle' | 'profile' | 'policy'): void {
    space();
    if (text[i] !== '{') {
      skip();
      return;
    }
    i++;
    const seen = new Set<string>();
    space();
    while (text[i] !== '}') {
      const key = string();
      const watched =
        mode === 'policy' ||
        (mode === 'profile' ? key === 'vpnPolicy' : ['format', 'version', 'profiles'].includes(key));
      if (watched && seen.has(key)) throw Error('vpn_policy_invalid');
      seen.add(key);
      space();
      i++;
      space(); // Colon; the caller already checked JSON syntax.
      if (mode === 'bundle' && key === 'profiles' && text[i] === '[') {
        i++;
        space();
        while (text[i] !== ']') {
          object('profile');
          space();
          if (text[i] !== ',') break;
          i++;
          space();
        }
        i++;
      } else if (mode === 'profile' && key === 'vpnPolicy') object('policy');
      else skip();
      space();
      if (text[i] !== ',') break;
      i++;
      space();
    }
    i++;
  }
  object('bundle');
}
