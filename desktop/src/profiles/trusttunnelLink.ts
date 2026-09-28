// TrustTunnel deep links: `tt://?` (DEEP_LINK.md draft 2) or the older `tt://`
// prefix followed by a base64url TLV payload. Mirrors the tturl package of the
// pinned core's sing-trusttunnel dependency. The Throne URI spelling
// `tt://user:password@host:port` stays with the other URI families in import.ts.
import type { Config } from './schema.ts';
import { decodeBytes, encodeBytes } from '../shared/base64.ts';

export type TrustTunnelLink = { config: Config; name: string; warnings: string[] };

const fail = (code: string): never => {
  throw new Error(code);
};
const prefix = 'tt://';
const maxVersion = 1;
const tag = {
  version: 0,
  hostname: 1,
  address: 2,
  customSni: 3,
  hasIpv6: 4,
  username: 5,
  password: 6,
  skipVerification: 7,
  certificate: 8,
  upstreamProtocol: 9,
  antiDpi: 10,
  clientRandomPrefix: 11,
  name: 12,
  dnsUpstreams: 13,
} as const;
const protocols = { http2: 1, http3: 2 } as const;

/** True for the binary payload spelling; the URI spelling carries credentials with `@`. */
export function isTrustTunnelDeepLink(input: string): boolean {
  if (!input.toLowerCase().startsWith(prefix)) return false;
  return /^\??[A-Za-z0-9_-]+=*$/.test(input.slice(prefix.length));
}

class Reader {
  position = 0;
  private readonly bytes: Uint8Array;
  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }
  get done() {
    return this.position >= this.bytes.length;
  }
  byte(): number {
    return this.position < this.bytes.length ? this.bytes[this.position++] : fail('invalid_link');
  }
  // QUIC-style variable-length integer: the top two bits select 1, 2, 4 or 8 bytes.
  varint(): number {
    const first = this.byte();
    const size = 1 << (first >> 6);
    let value = first & 0x3f;
    for (let i = 1; i < size; i++) value = value * 256 + this.byte();
    return Number.isSafeInteger(value) ? value : fail('invalid_link');
  }
  take(length: number): Uint8Array {
    if (length > this.bytes.length - this.position) return fail('invalid_link');
    const value = this.bytes.subarray(this.position, this.position + length);
    this.position += length;
    return value;
  }
}

function text(bytes: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return fail('invalid_link');
  }
}

function flag(bytes: Uint8Array): number {
  return bytes.length === 1 ? bytes[0] : fail('invalid_link');
}

function strings(bytes: Uint8Array): string[] {
  const reader = new Reader(bytes);
  const result: string[] = [];
  while (!reader.done) result.push(text(reader.take(reader.varint())));
  return result;
}

function endpoint(value: string): { host: string; port: number } {
  const match = value.match(/^\[([^\]]+)\]:(\d{1,5})$/) ?? value.match(/^([^:]+):(\d{1,5})$/);
  const port = match ? Number(match[2]) : 0;
  return match && port >= 1 && port <= 65535 ? { host: match[1], port } : fail('invalid_link');
}

// A DER chain is a sequence of SEQUENCE elements; the core accepts PEM lines.
function certificates(der: Uint8Array): string[] {
  const lines: string[] = [];
  let offset = 0;
  while (offset < der.length) {
    if (der[offset] !== 0x30 || offset + 1 >= der.length) return fail('invalid_link');
    let length = der[offset + 1];
    let header = 2;
    if (length & 0x80) {
      const count = length & 0x7f;
      if (count < 1 || count > 4 || offset + 2 + count > der.length) return fail('invalid_link');
      length = 0;
      for (let i = 0; i < count; i++) length = length * 256 + der[offset + 2 + i];
      header += count;
    }
    const end = offset + header + length;
    if (end > der.length) return fail('invalid_link');
    lines.push(
      '-----BEGIN CERTIFICATE-----',
      ...(encodeBytes(der.subarray(offset, end)).match(/.{1,64}/g) ?? []),
      '-----END CERTIFICATE-----',
    );
    offset = end;
  }
  return lines;
}

export function decodeTrustTunnelLink(input: string): TrustTunnelLink {
  const reader = new Reader(decodeBytes(input.slice(prefix.length).replace(/^\?/, '')));
  const fields = { hostname: '', customSni: '', username: '', password: '', name: '' };
  const addresses: string[] = [];
  const unknown: number[] = [];
  let certificate: Uint8Array = new Uint8Array();
  let protocol: number = protocols.http2;
  let skipVerification = false;
  let antiDpi = false;
  let clientRandomPrefix = '';
  let dnsUpstreams: string[] = [];
  while (!reader.done) {
    const current = reader.varint();
    const value = reader.take(reader.varint());
    switch (current) {
      case tag.version:
        if (flag(value) > maxVersion) fail('unsupported_version');
        break;
      case tag.hostname:
        fields.hostname = text(value);
        break;
      case tag.address:
        addresses.push(text(value));
        break;
      case tag.customSni:
        fields.customSni = text(value);
        break;
      case tag.username:
        fields.username = text(value);
        break;
      case tag.password:
        fields.password = text(value);
        break;
      case tag.name:
        fields.name = text(value);
        break;
      case tag.skipVerification:
        skipVerification = flag(value) !== 0;
        break;
      case tag.certificate:
        certificate = value;
        break;
      case tag.upstreamProtocol:
        protocol = flag(value);
        if (protocol !== protocols.http2 && protocol !== protocols.http3) fail('unsupported_version');
        break;
      case tag.antiDpi:
        antiDpi = flag(value) !== 0;
        break;
      case tag.clientRandomPrefix:
        clientRandomPrefix = text(value);
        break;
      case tag.dnsUpstreams:
        dnsUpstreams = strings(value);
        break;
      case tag.hasIpv6:
        // Always true in the original client; nothing to carry.
        break;
      default:
        unknown.push(current);
    }
  }
  if (!fields.hostname || !addresses.length) return fail('missing_server');
  if (!fields.username || !fields.password) return fail('missing_credentials');
  const [first, ...rest] = addresses.map(endpoint);
  const tls: Config = { enabled: true, server_name: fields.customSni || fields.hostname };
  if (skipVerification) tls.insecure = true;
  if (certificate.length) tls.certificate = certificates(certificate);
  const config: Config = {
    type: 'trusttunnel',
    server: first.host,
    server_port: first.port,
    username: fields.username,
    password: fields.password,
  };
  if (protocol === protocols.http3) config.quic = true;
  config.tls = tls;
  const warnings = [
    ...(rest.length ? ['link:addresses'] : []),
    ...(antiDpi ? ['link:anti_dpi'] : []),
    ...(clientRandomPrefix ? ['link:client_random_prefix'] : []),
    ...(dnsUpstreams.length ? ['link:dns_upstreams'] : []),
    ...unknown.map((n) => 'link:tag_' + n),
  ];
  return { config, name: fields.name, warnings };
}
