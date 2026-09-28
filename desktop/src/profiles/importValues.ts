// Shared readers for link queries and imported JSON: typed values, URI fields and drafts.
import type { Draft, Kind } from '../api';
import type { Config } from './schema.ts';
import { decodeText } from '../shared/base64.ts';
import {
  dialFields,
  echFields,
  multiplexFields,
  quicFields,
  tlsFields,
  transportFields,
  type UriField,
} from './uriFields.ts';
import { httpTransports, singBoxTransports } from './schemaCommon.ts';

export type ImportRow = { index: number; draft?: Draft; error?: string; warnings: string[] };
export const fail = (code: string): never => {
  throw new Error(code);
};
export const object = (value: unknown): Config =>
  value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Config)
    : fail('invalid_json');
export const unescape = (value: string) => {
  try {
    return decodeURIComponent(value);
  } catch {
    return fail('invalid_encoding');
  }
};
export const number = (value: string, max = 4294967295, min = 0): number =>
  /^\d+$/.test(value) && Number.isSafeInteger(Number(value)) && Number(value) >= min && Number(value) <= max
    ? Number(value)
    : fail('invalid_number');
export const boolean = (value: string): boolean =>
  /^(true|1|yes|on)$/i.test(value)
    ? true
    : /^(false|0|no|off)$/i.test(value)
      ? false
      : fail('invalid_boolean');
export const list = (value: string, delimiter = ',') =>
  value
    .split(delimiter)
    .map((s) => s.trim())
    .filter(Boolean);
export const duration = (value: string) => (/^\d+(?:\.\d+)?$/.test(value) ? value + 's' : value);
export const pair = (value: string): [string, string] => {
  const i = value.indexOf(':');
  return i < 0 ? [value, ''] : [value.slice(0, i), value.slice(i + 1)];
};
export const decodeBase64 = decodeText;
export class Query {
  values = new Map<string, string[]>();
  used = new Set<string>();
  constructor(query: string) {
    for (const part of query.replace(/^\?/, '').split('&').filter(Boolean)) {
      const i = part.indexOf('=');
      // QUrlQuery does not turn '+' into a space. This matters for keys/passwords.
      const key = unescape(i < 0 ? part : part.slice(0, i));
      const value = unescape(i < 0 ? '' : part.slice(i + 1));
      this.values.set(key, [...(this.values.get(key) || []), value]);
    }
  }
  get(...keys: string[]): string | undefined {
    let result: string | undefined;
    for (const key of keys)
      if (this.values.has(key)) {
        this.used.add(key);
        result = this.values.get(key)![0];
      }
    return result;
  }
  all(key: string): string[] {
    this.used.add(key);
    return this.values.get(key) || [];
  }
  warnings(): string[] {
    return [...this.values.keys()].filter((k) => !this.used.has(k)).map((k) => 'query:' + k);
  }
}
export function assign(
  target: Config,
  query: Query,
  mapping: Record<string, string>,
  convert: (s: string) => unknown = (s) => s,
) {
  for (const [key, path] of Object.entries(mapping)) {
    const value = query.get(key);
    if (value !== undefined) target[path] = convert(value);
  }
}
/** Reads the fields of `table` present in the query into `target`, nested by path. */
function read(target: Config, query: Query, table: readonly UriField[]) {
  const convert = {
    string: (s: string) => s,
    boolean,
    number: (s: string) => number(s),
    list: (s: string) => list(s),
  };
  for (const [path, key, kind] of table) {
    const value = query.get(key);
    if (value === undefined) continue;
    const parts = path.split('.');
    let node = target;
    for (const part of parts.slice(0, -1)) node = (node[part] ??= {}) as Config;
    node[parts[parts.length - 1]] = convert[kind](value);
  }
  return target;
}
export function headers(value: string, arrays = true): Config {
  if (value.trim().startsWith('{')) return object(JSON.parse(value));
  const parts = value.split('|');
  if (parts.length % 2) return fail('invalid_headers');
  const result: Config = Object.create(null);
  for (let i = 0; i < parts.length; i += 2) result[parts[i]] = arrays ? [parts[i + 1]] : parts[i + 1];
  return result;
}
export function tls(query: Query, required: boolean): Config | undefined {
  const result: Config = {};
  const security = query.get('security');
  if (security !== undefined) result.enabled = ['tls', 'reality', '1', 'true', 'false'].includes(security);
  const sni = query.get('sni', 'peer', 'server_name');
  if (sni) {
    result.server_name = sni;
    result.enabled = true;
  }
  const insecure = query.get('allowInsecure', 'allow_insecure', 'insecure');
  if (insecure !== undefined) result.insecure = boolean(insecure);
  read(result, query, tlsFields);
  const tricks = query.get('tls_tricks');
  if (tricks !== undefined) result.tls_tricks = { mixedcase_sni: boolean(tricks) };
  // Empty values in a Throne URI inherit its preset. A stored core JSON empty
  // spoof string instead means Off, so do not create that sentinel here.
  if (result.spoof_enabled === undefined) {
    if (result.spoof === '') delete result.spoof;
    if (result.spoof_method === '') delete result.spoof_method;
  }
  const fp = query.get('fp');
  if (fp) result.utls = { enabled: true, fingerprint: fp };
  const pbk = query.get('pbk');
  if (pbk) {
    result.enabled = true;
    result.reality = { enabled: true, public_key: pbk, short_id: query.get('sid') || '' };
  }
  const ech = read({}, query, echFields);
  if (Object.keys(ech).length) result.ech = ech;
  if (required) result.enabled = true;
  return Object.keys(result).length ? result : undefined;
}
export function transport(query: Query): Config | undefined {
  let type = query.get('type') || '';
  const header = query.get('headerType');
  if (type === 'h2' || (type === 'tcp' && header === 'http')) type = 'http';
  if (!type || ['tcp', 'raw', 'none'].includes(type)) return undefined;
  if (!singBoxTransports.includes(type)) return fail('unsupported_transport');
  const result: Config = { type };
  // sing-box gRPC and QUIC transports have no host; left unread, a host of
  // such a link is reported as an unused field instead of vanishing.
  const host = httpTransports.includes(type) ? query.get('host') : undefined;
  if (host) {
    if (type === 'http') result.host = list(host);
    else if (type === 'ws') result.headers = { Host: [host] };
    else if (type === 'httpupgrade') result.host = host;
  }
  read(result, query, transportFields);
  assign(result, query, { ed: 'max_early_data' }, (s) => number(s));
  const raw = query.get('headers');
  if (raw) result.headers = { ...((result.headers as Config) || {}), ...headers(raw) };
  // Common subscription convention: early data is encoded inside the WS path.
  if (type === 'ws' && typeof result.path === 'string' && result.path.includes('?ed=')) {
    const [path, ed] = result.path.split('?ed=');
    result.path = path;
    result.max_early_data = number(ed);
    result.early_data_header_name ||= 'Sec-WebSocket-Protocol';
  }
  return result;
}
export function mux(query: Query): Config | undefined {
  const result = read({}, query, multiplexFields);
  return Object.keys(result).length ? result : undefined;
}
export function dial(config: Config, query: Query) {
  read(config, query, dialFields);
}
export function quic(config: Config, query: Query) {
  read(config, query, quicFields);
}
export function draft(
  config: Config,
  groupId: string,
  name?: string,
  kind: Kind = 'sing-box-outbound',
): Draft {
  const fallback =
    config.server ||
    (config.settings as Config)?.address ||
    (config.peers as Config[])?.[0]?.address ||
    config.type ||
    config.protocol ||
    (kind.startsWith('xray') ? 'Xray' : 'sing-box');
  return { name: name?.trim() || String(fallback), groupId, kind, config };
}
