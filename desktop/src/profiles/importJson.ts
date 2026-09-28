// JSON imports: profile kinds, whole configurations split into servers and profile bundles.
import { parseVpnPolicy } from './vpnPolicy.ts';
import type { Draft, Kind } from '../api';
import { definitions, type Config } from './schema.ts';
import { limits } from '../shared/api/generated/limits.ts';
import { type ImportRow, fail, object, draft } from './importValues.ts';

export const maxProfiles = limits.maxBatchProfiles;
// Outbounds that carry traffic somewhere else instead of describing a server.
// Same split as upstream src/configs/sub/SubscriptionParser.cpp.
const infrastructureTypes = new Set(['direct', 'block', 'dns', 'selector', 'urltest']);
const infrastructureProtocols = new Set(['freedom', 'blackhole', 'dns', 'loopback']);
/** Server outbound types, owned by the profile schema rather than a second list. */
const serverTypes = new Set(
  definitions
    .filter((d) => d.kind === 'sing-box-outbound')
    .map((d) => String(d.seed.type))
    .filter((type) => type && !infrastructureTypes.has(type)),
);
const isServer = (value: Config): boolean =>
  typeof value.protocol === 'string'
    ? !!value.protocol && !infrastructureProtocols.has(value.protocol)
    : serverTypes.has(String(value.type));
function members(config: Config): Config[] {
  return [
    ...(Array.isArray(config.outbounds) ? config.outbounds : []),
    ...(Array.isArray(config.endpoints) ? config.endpoints : []),
  ]
    .filter((v): v is Config => !!v && typeof v === 'object' && !Array.isArray(v))
    .filter(isServer);
}
/**
 * A subscription that answers with a whole sing-box or Xray configuration is
 * listing servers, so each outbound becomes its own profile, as in Throne.
 * Selectors, direct and other infrastructure outbounds are not servers and are
 * left out; a configuration without a single server keeps its own row so its
 * routes and DNS survive.
 */
export function splitConfigRows(rows: ImportRow[], groupId: string): ImportRow[] {
  const split = rows.flatMap((row) => {
    if (!row.draft || !['sing-box-config', 'xray-config'].includes(row.draft.kind)) return [row];
    const parts = members(row.draft.config);
    if (!parts.length) return [row];
    const expanded = parts.map((part) => rowFor(row.index, part, groupId));
    return expanded.some((r) => r.draft) ? expanded : [row];
  });
  return split.length > maxProfiles
    ? [{ index: 1, error: 'too_many_profiles', warnings: [] }]
    : split.map((row, index) => ({ ...row, index: index + 1 }));
}
function rowFor(index: number, value: Config, groupId: string): ImportRow {
  try {
    return { index, draft: jsonDraft(value, groupId), warnings: [] };
  } catch (error) {
    const message = error instanceof Error ? error.message : '';
    return { index, error: /^[a-z_]+$/.test(message) ? message : 'invalid_content', warnings: [] };
  }
}
/**
 * The profile kind a JSON object describes; one decision for file import,
 * links and the editor's JSON file. A full configuration is Xray when any of
 * its inbounds or outbounds uses Xray's `protocol`.
 */
export function jsonKind(value: Config): Kind | undefined {
  if (value.type === 'chain') return 'chain';
  if (value.type === 'auto-selector') return 'auto-selector';
  if (value.type === 'extracore') return 'external-core';
  if (value.type) return 'sing-box-outbound';
  if (value.protocol) return 'xray-outbound';
  if (Array.isArray(value.outbounds) || Array.isArray(value.endpoints) || Array.isArray(value.inbounds))
    return [...((value.outbounds as Config[]) || []), ...((value.inbounds as Config[]) || [])].some(
      (p) => p?.protocol,
    )
      ? 'xray-config'
      : 'sing-box-config';
  return undefined;
}
export function jsonDraft(value: Config, groupId: string, name?: string): Draft {
  const kind = jsonKind(value) ?? fail('unsupported_json');
  return draft(value, groupId, name || (typeof value.tag === 'string' ? value.tag : undefined), kind);
}
export function bundledDraft(value: unknown, groupId: string, version: number): Draft {
  const p = object(value);
  if (
    typeof p.name !== 'string' ||
    !p.name.trim() ||
    new TextEncoder().encode(p.name).length > 512 ||
    ![
      'sing-box-outbound',
      'sing-box-config',
      'xray-outbound',
      'xray-config',
      'chain',
      'auto-selector',
      'external-core',
    ].includes(String(p.kind))
  )
    return fail('invalid_profile_bundle');
  if (
    p.reference !== undefined &&
    (typeof p.reference !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(p.reference))
  )
    return fail('invalid_profile_bundle');
  if (p.vlessCore !== undefined && !['xray', 'sing-box'].includes(p.vlessCore as string))
    return fail('invalid_profile_bundle');
  const config = object(p.config),
    kind = p.kind as Kind;
  const present = Object.prototype.hasOwnProperty.call(p, 'vpnPolicy');
  if (present && version !== 2) return fail('vpn_policy_invalid');
  return {
    name: p.name,
    kind,
    config,
    groupId,
    ...(present ? { vpnPolicy: parseVpnPolicy(p.vpnPolicy, { kind, config }) } : {}),
    ...(p.vlessCore === undefined ? {} : { vlessCore: p.vlessCore as 'xray' | 'sing-box' }),
    ...(p.reference === undefined ? {} : { reference: p.reference as string }),
  };
}
