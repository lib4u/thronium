// Parsing is local. The import dialog can hand subscription URLs to the native downloader.
import { extendedImport } from './extendedImport.ts';
import { assertVpnPolicyWire } from './vpnPolicy.ts';
import type { Draft } from '../api';
import { limits } from '../shared/api/generated/limits.ts';
import { defaults } from '../shared/api/generated/defaults.ts';
import { type ImportRow, object, decodeBase64 } from './importValues.ts';
import { maxProfiles, jsonDraft, bundledDraft } from './importJson.ts';
import { parseLink } from './link.ts';
import { parseWireGuard } from './wireguardImport.ts';
export type { ImportRow } from './importValues.ts';
export { linkTypes, parseLink } from './link.ts';
export { jsonDraft, jsonKind, splitConfigRows } from './importJson.ts';
export { parseWireGuard } from './wireguardImport.ts';

export function importDrafts(rows: ImportRow[]): Draft[] {
  return rows.map((row) => {
    if (row.error || !row.draft) throw new Error('invalid_import_batch');
    return row.draft;
  });
}
export const maxImportBytes = limits.maxConfigBytes;
/** Largest image decoded for QR codes. */
export const maxQrImageBytes = limits.maxQrImageBytes;
/**
 * Whether a file is a QR image, decided from its declared type and first
 * twelve bytes, so each kind is bounded by its own limit before it is read.
 */
export function importFileKind(head: Uint8Array, type: string, qrOnly: boolean) {
  const image =
    qrOnly ||
    type.startsWith('image/') ||
    (head[0] === 0x89 && head[1] === 0x50) ||
    (head[0] === 0xff && head[1] === 0xd8) ||
    String.fromCharCode(...head.subarray(0, 3)) === 'GIF' ||
    (head[0] === 0x42 && head[1] === 0x4d) ||
    String.fromCharCode(...head.subarray(8, 12)) === 'WEBP';
  return image
    ? { image, limit: maxQrImageBytes, error: 'qr_image_too_large' }
    : { image, limit: maxImportBytes, error: 'import_too_large' };
}
// Keep valid HTTP proxy links on their existing path; a web URL with a resource
// path or unknown query parameters is a subscription candidate, not a broken proxy.
// Return the exact URL so signed query strings are not rewritten by URL serialization.
export function subscriptionSource(
  text: string,
): { url: string; automatic: boolean; name?: string; link?: boolean } | null {
  const source = text.replace(/^\uFEFF/, '').trim();
  if (/^throne:\/\/addsub\//i.test(source)) {
    try {
      const encoded = source.match(/^throne:\/\/addsub\/([^?#]+)$/i)?.[1];
      if (!encoded || encoded.length > 12000) return null;
      const decoded = decodeBase64(decodeURIComponent(encoded));
      const at = decoded.indexOf('#');
      const url = at < 0 ? decoded : decoded.slice(0, at);
      const name = at < 0 ? '' : decodeURIComponent(decoded.slice(at + 1));
      const nested = /^https?:\/\//i.test(url) ? subscriptionSource(url) : null;
      // The encoded address is shown before the group is added, as Qt's
      // confirmation does.
      return nested ? { ...nested, automatic: true, link: true, ...(name ? { name } : {}) } : null;
    } catch {
      return null;
    }
  }

  if (source.length > 8192 || !/^https?:\/\//i.test(source) || /\s/.test(source)) return null;
  let url: URL;
  try {
    url = new URL(source);
  } catch {
    return null;
  }
  if (!url.hostname || url.username || url.password || url.hash || source.includes('#')) return null;
  try {
    return { url: source, automatic: parseLink(source, defaults.personalGroup).warnings.length > 0 };
  } catch {
    return { url: source, automatic: true };
  }
}

export function parseImport(text: string, groupId: string, filename?: string, depth = 0): ImportRow[] {
  if (new TextEncoder().encode(text).length > maxImportBytes)
    return [{ index: 1, error: 'import_too_large', warnings: [] }];
  text = text.replace(/^\uFEFF/, '').trim();
  if (!text) return [];
  if (depth > 16) return [{ index: 1, error: 'invalid_content', warnings: [] }];
  if (/^(?:thronium|throne):\/\/profiles\/[^\s]+$/i.test(text)) {
    try {
      const encoded = text.match(/^(?:thronium|throne):\/\/profiles\/([A-Za-z0-9_-]+)$/i)?.[1];
      if (!encoded) return [{ index: 1, error: 'invalid_profile_bundle', warnings: [] }];
      const decoded = decodeBase64(encoded);
      const value = JSON.parse(decoded);
      if (value?.format !== 'thronium-profiles')
        return [{ index: 1, error: 'invalid_profile_bundle', warnings: [] }];
      return parseImport(decoded, groupId, filename, depth + 1);
    } catch {
      return [{ index: 1, error: 'invalid_profile_bundle', warnings: [] }];
    }
  }
  const extended = extendedImport(text, groupId, filename, depth);
  if (extended) return extended;
  function row(index: number, fn: () => { draft: Draft; warnings: string[] }): ImportRow {
    try {
      return { index, ...fn() };
    } catch (error) {
      const message = error instanceof Error ? error.message : '';
      return { index, error: /^[a-z_]+$/.test(message) ? message : 'invalid_content', warnings: [] };
    }
  }
  if (/^[{[]/.test(text) && !/^\[Interface\]/i.test(text)) {
    try {
      const value = JSON.parse(text);
      if (value?.format === 'thronium-profiles') {
        if (![1, 2].includes(value.version))
          return [{ index: 1, error: 'unsupported_bundle_version', warnings: [] }];
        assertVpnPolicyWire(text);
        if (!Array.isArray(value.profiles) || !value.profiles.length)
          return [{ index: 1, error: 'invalid_profile_bundle', warnings: [] }];
        if (value.profiles.length > maxProfiles)
          return [{ index: 1, error: 'too_many_profiles', warnings: [] }];
        return value.profiles.map((p: unknown, i: number) =>
          row(i + 1, () => ({ draft: bundledDraft(p, groupId, value.version), warnings: [] })),
        );
      }
      const values = Array.isArray(value) ? value : [value];
      if (values.length > maxProfiles) return [{ index: 1, error: 'too_many_profiles', warnings: [] }];
      return values.map((v, i) =>
        row(i + 1, () => ({
          draft: jsonDraft(
            object(v),
            groupId,
            values.length === 1 ? filename?.replace(/\.json$/i, '') : undefined,
          ),
          warnings: [],
        })),
      );
    } catch (error) {
      return [
        {
          index: 1,
          error:
            error instanceof Error && error.message === 'vpn_policy_invalid'
              ? 'vpn_policy_invalid'
              : 'invalid_json',
          warnings: [],
        },
      ];
    }
  }
  if (/\[Interface\]/i.test(text))
    return [row(1, () => parseWireGuard(text, groupId, filename?.replace(/\.(conf|txt)$/i, '')))];
  if (!text.includes('://')) {
    try {
      const decoded = decodeBase64(text);
      return parseImport(decoded, groupId, filename, depth + 1);
    } catch {
      return [{ index: 1, error: 'unsupported_content', warnings: [] }];
    }
  }
  const lines = text
    .split(/\r?\n/)
    .map((value, index) => ({ value: value.trim(), index: index + 1 }))
    .filter((l) => l.value && !l.value.startsWith('#') && !l.value.startsWith('//'));
  if (lines.length > maxProfiles) return [{ index: 1, error: 'too_many_profiles', warnings: [] }];
  const parsed = lines.flatMap(({ value, index }) =>
    /^(vpn:\/\/|(?:thronium|throne):\/\/profiles\/)/i.test(value)
      ? parseImport(value, groupId, undefined, depth + 1)
      : [row(index, () => parseLink(value, groupId))],
  );
  return parsed.length > maxProfiles
    ? [{ index: 1, error: 'too_many_profiles', warnings: [] }]
    : lines.some((l) => /^(vpn:\/\/|(?:thronium|throne):\/\/profiles\/)/i.test(l.value))
      ? parsed.map((r, i) => ({ ...r, index: i + 1 }))
      : parsed;
}
