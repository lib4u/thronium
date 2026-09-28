import { strToU8, zipSync } from 'fflate';
import { nativeLink, wireguardFile, type SharedProfile } from './share.ts';
import { decodeBytes, encodeBytes } from '../shared/base64.ts';
import { limits } from '../shared/limits.ts';

export type ArchiveFormat = 'wireguard-archive' | 'qr-archive';
export type ArchiveEntry = { name: string; text: string };
export const MAX_ARCHIVE_PROFILES = limits.maxArchiveProfiles;
export const MAX_ARCHIVE_BYTES = limits.maxArchiveBytes;

function filename(name: string, index: number, extension: string): string {
  const clean = name
    .normalize('NFC')
    // eslint-disable-next-line no-control-regex -- Control and bidi characters must be removed from exported filenames.
    .replace(/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069<>:"/\\|?*]/g, '_')
    .replace(/^[. ]+|[. ]+$/g, '');
  let stem = '',
    length = 0;
  for (const character of Array.from(clean).slice(0, 64)) {
    const bytes = strToU8(character).length;
    if (length + bytes > 180) break;
    stem += character;
    length += bytes;
  }
  return `${String(index + 1).padStart(3, '0')}${stem ? '-' + stem : ''}.${extension}`;
}

/** Validate every conversion before preparing any output or opening a save dialog. */
export function planArchive(profiles: SharedProfile[], format: ArchiveFormat): ArchiveEntry[] {
  if (!profiles.length || profiles.length > MAX_ARCHIVE_PROFILES) throw Error('archive_invalid_selection');
  if (!['wireguard-archive', 'qr-archive'].includes(format)) throw Error('invalid_export_format');
  const extension = format === 'wireguard-archive' ? 'conf' : 'png';
  return profiles.map((profile, index) => ({
    name: filename(profile.name, index, extension),
    text: format === 'wireguard-archive' ? wireguardFile(profile) : nativeLink(profile),
  }));
}

function pngBytes(data: string): Uint8Array {
  const prefix = 'data:image/png;base64,';
  if (!data.startsWith(prefix) || data.length > (MAX_ARCHIVE_BYTES * 4) / 3 + 128)
    throw Error('archive_invalid_data');
  let bytes: Uint8Array;
  try {
    bytes = decodeBytes(data.slice(prefix.length));
  } catch {
    throw Error('archive_invalid_data');
  }
  if (![137, 80, 78, 71, 13, 10, 26, 10].every((b, i) => bytes[i] === b)) throw Error('archive_invalid_data');
  return bytes;
}

export async function createArchive(
  entries: ArchiveEntry[],
  format: ArchiveFormat,
  renderQr: (text: string) => Promise<string>,
  progress: (done: number, total: number) => void,
  signal: AbortSignal,
): Promise<string> {
  const files: Record<string, Uint8Array> = Object.create(null);
  let totalBytes = 0;
  function cancelled() {
    if (signal.aborted) throw Error('archive_cancelled');
  }
  cancelled();
  for (const [index, entry] of entries.entries()) {
    cancelled();
    const bytes = format === 'wireguard-archive' ? strToU8(entry.text) : pngBytes(await renderQr(entry.text));
    cancelled();
    totalBytes += bytes.length;
    if (totalBytes > MAX_ARCHIVE_BYTES) throw Error('archive_too_large');
    files[entry.name] = bytes;
    progress(index + 1, entries.length);
  }
  cancelled();
  const bytes = zipSync(files, { level: 6 });
  if (bytes.length > MAX_ARCHIVE_BYTES) throw Error('archive_too_large');
  return encodeBytes(bytes);
}
