import { parseDocument } from 'yaml';
import { Unzlib } from 'fflate';
import { parseImport, jsonDraft, maxImportBytes, type ImportRow } from './import.ts';
import { clashProfile } from './clashImport.ts';
import { openVpn } from './fileFormats.ts';
import { openConnect, anyConnectXml } from './openConnectFormat.ts';
import type { Config } from './schema';
import { limits } from '../shared/api/generated/limits.ts';
import { decodeBytes } from '../shared/base64.ts';

const row = (index: number, parse: () => Omit<ImportRow, 'index'>): ImportRow => {
  try {
    return { index, ...parse() };
  } catch (e) {
    const code = e instanceof Error ? e.message : '';
    return { index, warnings: [], error: /^[a-z_]+$/.test(code) ? code : 'invalid_content' };
  }
};
const failure = (error: string): ImportRow[] => [{ index: 1, error, warnings: [] }];
function vpnPayload(link: string): string {
  let bytes = decodeBytes(decodeURIComponent(link.slice(6).split('#')[0]));
  const zlib = (offset: number) =>
    bytes.length > offset + 2 &&
    (bytes[offset] & 15) === 8 &&
    ((bytes[offset] << 8) + bytes[offset + 1]) % 31 === 0;
  const qt = zlib(4);
  const offset = qt ? 4 : 0;
  if (qt || zlib(0)) {
    const expected = qt ? new DataView(bytes.buffer).getUint32(0) : null;
    if (expected !== null && (!expected || expected > maxImportBytes)) throw new Error('import_too_large');
    const chunks: Uint8Array[] = [];
    let size = 0;
    const decoder = new Unzlib((chunk) => {
      size += chunk.length;
      if (size > maxImportBytes) throw new Error('import_too_large');
      chunks.push(chunk);
    });
    // Small compressed chunks bound the decoder's temporary output allocation.
    for (let i = offset; i < bytes.length; i += 1024)
      decoder.push(bytes.subarray(i, i + 1024), i + 1024 >= bytes.length);
    if (expected !== null && expected !== size) throw new Error('invalid_content');
    bytes = new Uint8Array(size);
    let at = 0;
    for (const c of chunks) {
      bytes.set(c, at);
      at += c.length;
    }
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}
export function extendedImport(
  text: string,
  group: string,
  filename: string | undefined,
  depth: number,
): ImportRow[] | null {
  const baseName = filename?.replace(/\.[^.]+$/, '');
  const wrap = (value: { config: Config; warnings: string[]; name?: string }): Omit<ImportRow, 'index'> => ({
    draft: jsonDraft(value.config, group, value.name || baseName),
    warnings: value.warnings,
  });
  if (/^vpn:\/\//i.test(text) && !/\s/.test(text)) {
    try {
      return parseImport(vpnPayload(text), group, filename, depth + 1);
    } catch (e) {
      return failure(e instanceof Error && e.message === 'import_too_large' ? e.message : 'invalid_content');
    }
  }
  if (/<(?:\w+:)?(?:AnyConnectProfile|ServerList)\b/.test(text)) {
    try {
      const entries = anyConnectXml(text);
      return entries.length ? entries.map((v, i) => row(i + 1, () => wrap(v))) : failure('invalid_vpn_file');
    } catch {
      return failure('invalid_vpn_file');
    }
  }
  if (
    /^(?:\s*(?:#.*)?\n)*\s*(?:client|tls-client|dev\s|proto\s)/.test(text) ||
    /^\s*remote\s+\S+/m.test(text)
  )
    return [row(1, () => wrap(openVpn(text)))];
  if (
    /^\s*(?:protocol(?:\s*=\s*|\s+)(?:anyconnect|gp|fortinet|f5|pulse|nc)|openconnect\s)/m.test(text) ||
    /(?:^|\s)--protocol[= ]/.test(text)
  )
    return [row(1, () => wrap(openConnect(text)))];
  if (/^[{[]/.test(text)) {
    let value: Config;
    try {
      value = JSON.parse(text);
    } catch {
      return null;
    }
    if (!value || Array.isArray(value)) return null;
    if (
      !value.type &&
      !value.protocol &&
      !value.outbounds &&
      !value.endpoints &&
      Array.isArray(value.servers)
    ) {
      if (value.servers.length > limits.maxBatchProfiles) return failure('too_many_profiles');
      return value.servers.map((v, i) =>
        row(i + 1, () => {
          const p = v as Config;
          if (!p || !p.server || !p.server_port || !p.method || !p.password)
            throw new Error('invalid_content');
          // As Qt's shadowsocks::ParseFromSIP008: simple-obfs is obfs-local,
          // UDP over TCP and multiplex are kept.
          const uot = typeof p.uot === 'object' && p.uot ? (p.uot as Config).enabled : p.uot;
          return {
            draft: jsonDraft(
              {
                type: 'shadowsocks',
                server: p.server,
                server_port: p.server_port,
                method: p.method,
                password: p.password,
                ...(p.plugin
                  ? {
                      plugin: String(p.plugin).replace('simple-obfs', 'obfs-local'),
                      plugin_opts: p.plugin_opts,
                    }
                  : {}),
                ...(uot === true ? { udp_over_tcp: { enabled: true } } : {}),
                ...(p.multiplex && typeof p.multiplex === 'object' ? { multiplex: p.multiplex } : {}),
              },
              group,
              String(p.remarks || p.server),
            ),
            warnings: [],
          };
        }),
      );
    }
    if (Array.isArray(value.containers)) {
      const rows: ImportRow[] = [];
      const location = typeof value.description === 'string' ? value.description.trim() : '';
      for (const c of value.containers)
        if (c && typeof c === 'object')
          for (const p of Object.values(c)) {
            if (!p || typeof p !== 'object' || !('last_config' in p)) continue;
            let inner = p.last_config;
            if (typeof inner === 'string') {
              try {
                inner = JSON.parse(inner);
              } catch {
                /* raw config */
              }
            }
            const content = inner && typeof inner === 'object' && 'config' in inner ? inner.config : inner;
            const imported =
              typeof content === 'string'
                ? parseImport(content, group, filename, depth + 1)
                : content && typeof content === 'object'
                  ? parseImport(JSON.stringify(content), group, filename, depth + 1)
                  : [];
            for (const result of imported) if (result.draft && location) result.draft.name = location;
            rows.push(...imported);
            if (rows.length > limits.maxBatchProfiles) return failure('too_many_profiles');
          }
      return rows.length ? rows.map((r, i) => ({ ...r, index: i + 1 })) : failure('invalid_content');
    }
    if (!Array.isArray(value.proxies)) return null;
  }
  if (/^\s*(?:proxies\s*:|["']proxies["']\s*:)/m.test(text) || /^[{][\s\S]*"proxies"\s*:/.test(text)) {
    try {
      const doc = parseDocument(text, { uniqueKeys: true, version: '1.2' });
      if (doc.errors.length) return failure('invalid_yaml');
      const value = doc.toJS({ maxAliasCount: 50 }) as Config;
      if (!value || !Array.isArray(value.proxies) || !value.proxies.length) return failure('invalid_yaml');
      if (value.proxies.length > limits.maxBatchProfiles) return failure('too_many_profiles');
      return value.proxies.map((p, i) => row(i + 1, () => clashProfile(p, group)));
    } catch {
      return failure('invalid_yaml');
    }
  }
  return null;
}
