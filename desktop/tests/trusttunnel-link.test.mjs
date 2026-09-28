import test from 'node:test';
import assert from 'node:assert/strict';
import { parseImport, parseLink } from '../src/profiles/import.ts';
import { decodeTrustTunnelLink, isTrustTunnelDeepLink } from '../src/profiles/trusttunnelLink.ts';
import { importWarning } from '../src/profiles/ImportModel.ts';
import { shareProfiles } from '../src/profiles/share.ts';

// Reference links were built by the tturl package of the pinned core's
// sing-trusttunnel dependency (v0.3.0-beta.7) from synthetic values; the DER
// certificate is a throwaway self-signed one whose PEM text is pinned below.
const reference = {
  full: "tt://?AAEBARJ0dC5maXh0dXJlLmludmFsaWQCDjEyNy4wLjAuMTo4NDQzAhJbMjAwMTpkYjg6OjddOjg0NDMDE3NuaS5maXh0dXJlLmludmFsaWQFDGZpeHR1cmUtdXNlcgYfZml4dHVyZS1wYXNzOndpdGgvc3BlY2lhbD1jaGFycwsIMTYwMzAxMDAIQ0QwggNAMIICKKADAgECAhQg7hr7JhCBGQ4V3HSuJbqpjSPinjANBgkqhkiG9w0BAQsFADAdMRswGQYDVQQDDBJ0dC5maXh0dXJlLmludmFsaWQwHhcNMjYwOTE0MDczMjIyWhcNMjYwOTE1MDczMjIyWjAdMRswGQYDVQQDDBJ0dC5maXh0dXJlLmludmFsaWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDi4FjBLSbJc3wh4abqjCSRLs266HMQ4p0_aDfUXUwfVJKfOwHsuXjFiJS_GAPn08j9nbF6m099AHtQEi0IyuFVtAe3bKkLedmaVpZjirGjeGaafHcKm6lEbhHBkS-8rO1G9wgEpqPmBr7UolCyU8Mh0qQz6lyXVHreP0ssFl38WZBPKKI9okWwx7o0RXU4yTiLtWVyPU51Sgo0ChRFlNXLE2O8E1I9nqzRK2AmXvYOXE8XwYAEx3CUzmhTXDyN62Q6f1n8oFq5m9CtUF0tSUFyVQD9YxRFJIWN27YDepKgz84-3yeeTMEAvOgnfvHuxCGlz_wel2bSOFW-pnIuLYJnAgMBAAGjeDB2MB0GA1UdDgQWBBSaR5oVWMR192YTXmoA1pu5r3eZOTAfBgNVHSMEGDAWgBSaR5oVWMR192YTXmoA1pu5r3eZOTAPBgNVHRMBAf8EBTADAQH_MCMGA1UdEQQcMBqHBH8AAAGCEnR0LmZpeHR1cmUuaW52YWxpZDANBgkqhkiG9w0BAQsFAAOCAQEAckTHi-3aYk1y6SdnBWz4jIcGQSfyWbT4plX-dxHoCSGyUJ0PprXbmNq7BY3w5FL6wIOXP-0THIsbTwtWQQYJNKahDSHiT_HixAi5WlDP0CRVz7B6gI8m_luVOdpLZm_J57JRD-ggR3beqHEZKYjqmqqsI_KJy2Iz7Uq0PoeFUak3K7FiTs85z7hPKf3nbsRzQKaOYunLvUDN_oSvYdC_Nv3zIaqVBAVmW7VuoymPGPeerbYqkSv3MaJ9rHx6M_JOjDgmow3KYYOgWWO6yYW3rXL6t2rYiQQ8ZuuCfoDSDdldMgfPoTf8D6tKBFqpSCdGf9V88GAfsvfjMkLIjQZHXAkBAgoBAQwZ0KHRgtC10L3QtCDCtyBUcnVzdFR1bm5lbA0aBzEuMS4xLjERdGxzOi8vZG5zLmV4YW1wbGU",
  minimal: "tt://?AAEBARJ0dC5maXh0dXJlLmludmFsaWQCDjE5Mi4wLjIuMTA6NDQzBQF1BgFw",
  skip: "tt://?AAEBAQsyMDMuMC4xMTMuNQIPMjAzLjAuMTEzLjU6NDQzBQF1BgFwBwEBDAVwbGFpbg",
};
const pem = ["-----BEGIN CERTIFICATE-----", "MIIDQDCCAiigAwIBAgIUIO4a+yYQgRkOFdx0riW6qY0j4p4wDQYJKoZIhvcNAQEL", "BQAwHTEbMBkGA1UEAwwSdHQuZml4dHVyZS5pbnZhbGlkMB4XDTI2MDkxNDA3MzIy", "MloXDTI2MDkxNTA3MzIyMlowHTEbMBkGA1UEAwwSdHQuZml4dHVyZS5pbnZhbGlk", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4uBYwS0myXN8IeGm6owk", "kS7NuuhzEOKdP2g31F1MH1SSnzsB7Ll4xYiUvxgD59PI/Z2xeptPfQB7UBItCMrh", "VbQHt2ypC3nZmlaWY4qxo3hmmnx3CpupRG4RwZEvvKztRvcIBKaj5ga+1KJQslPD", "IdKkM+pcl1R63j9LLBZd/FmQTyiiPaJFsMe6NEV1OMk4i7Vlcj1OdUoKNAoURZTV", "yxNjvBNSPZ6s0StgJl72DlxPF8GABMdwlM5oU1w8jetkOn9Z/KBauZvQrVBdLUlB", "clUA/WMURSSFjdu2A3qSoM/OPt8nnkzBALzoJ37x7sQhpc/8Hpdm0jhVvqZyLi2C", "ZwIDAQABo3gwdjAdBgNVHQ4EFgQUmkeaFVjEdfdmE15qANabua93mTkwHwYDVR0j", "BBgwFoAUmkeaFVjEdfdmE15qANabua93mTkwDwYDVR0TAQH/BAUwAwEB/zAjBgNV", "HREEHDAahwR/AAABghJ0dC5maXh0dXJlLmludmFsaWQwDQYJKoZIhvcNAQELBQAD", "ggEBAHJEx4vt2mJNcuknZwVs+IyHBkEn8lm0+KZV/ncR6AkhslCdD6a125jauwWN", "8ORS+sCDlz/tExyLG08LVkEGCTSmoQ0h4k/x4sQIuVpQz9AkVc+weoCPJv5blTna", "S2ZvyeeyUQ/oIEd23qhxGSmI6pqqrCPyictiM+1KtD6HhVGpNyuxYk7POc+4Tyn9", "527Ec0CmjmLpy71Azf6Er2HQvzb98yGqlQQFZlu1bqMpjxj3nq22KpEr9zGifax8", "ejPyTow4JqMNymGDoFljusmFt61y+rdq2IkEPGbrgn6A0g3ZXTIHz6E3/A+rSgRa", "qUgnRn/VfPBgH7L34zJCyI0GR1w=", "-----END CERTIFICATE-----"];
const config = link => parseLink(link, 'work').draft.config;
const payload = link => link.replace(/^tt:\/\/\??/, '');
const bytes = link => Buffer.from(payload(link), 'base64url');
const relink = buffer => 'tt://?' + Buffer.from(buffer).toString('base64url');
const tlv = (tag, value) => Buffer.concat([Buffer.from([tag, value.length]), value]);

test('a full TrustTunnel deep link maps hostname to SNI, first address to server and the DER chain to PEM', () => {
  const row = parseLink(reference.full, 'work');
  assert.equal(row.draft.name, 'Стенд · TrustTunnel');
  assert.equal(row.draft.kind, 'sing-box-outbound');
  assert.deepEqual(row.draft.config, {
    type: 'trusttunnel', server: '127.0.0.1', server_port: 8443, username: 'fixture-user', password: 'fixture-pass:with/special=chars', quic: true,
    tls: { enabled: true, server_name: 'sni.fixture.invalid', certificate: pem },
  });
  assert.deepEqual(row.warnings, ['link:addresses', 'link:anti_dpi', 'link:client_random_prefix', 'link:dns_upstreams']);
  assert.equal(importWarning('link:anti_dpi', 'en'), 'Link parameter not applied by the app: anti_dpi');
  assert.equal(importWarning('link:dns_upstreams', 'ru'), 'Параметр ссылки не применяется приложением: dns_upstreams');
});

test('minimal and skip-verification links use defaults, the old spelling decodes identically and names fall back to the server', () => {
  const minimal = parseLink(reference.minimal, 'work');
  assert.deepEqual(minimal.draft.config, { type: 'trusttunnel', server: '192.0.2.10', server_port: 443, username: 'u', password: 'p', tls: { enabled: true, server_name: 'tt.fixture.invalid' } });
  assert.equal(minimal.draft.name, '192.0.2.10');
  assert.deepEqual(minimal.warnings, []);
  const skip = parseLink(reference.skip, 'work');
  assert.deepEqual(skip.draft.config.tls, { enabled: true, server_name: '203.0.113.5', insecure: true });
  assert.equal(skip.draft.config.quic, undefined);
  assert.equal(skip.draft.name, 'plain');
  assert.deepEqual(config('tt://' + payload(reference.full)), config(reference.full));
  assert.deepEqual(config('TT://?' + payload(reference.minimal)), config(reference.minimal));
  assert(isTrustTunnelDeepLink(reference.minimal) && isTrustTunnelDeepLink('tt://' + payload(reference.minimal)));
  assert(!isTrustTunnelDeepLink('tt://user:password@127.0.0.1:443?sni=example.test'));
  assert.equal(config('tt://user:password@127.0.0.1:443?sni=example.test').username, 'user');
});

test('deep links are recognized inside a mixed paste and unknown tags are reported, not dropped silently', () => {
  const rows = parseImport(reference.minimal + '\n' + 'tt://user:password@127.0.0.1:443?sni=example.test' + '\n' + reference.skip, 'work');
  assert.deepEqual(rows.map(r => [r.error, r.draft.config.server, r.warnings]), [[undefined, '192.0.2.10', []], [undefined, '127.0.0.1', []], [undefined, '203.0.113.5', []]]);
  const future = relink(Buffer.concat([bytes(reference.minimal), tlv(14, Buffer.from('later'))]));
  assert.deepEqual(parseLink(future, 'work').warnings, ['link:tag_14']);
  const ipv6 = relink(Buffer.concat([bytes(reference.minimal), tlv(4, Buffer.from([1]))]));
  assert.deepEqual(parseLink(ipv6, 'work').warnings, []);
});

test('malformed or unsupported deep links fail with precise codes and never yield a draft', () => {
  const minimal = bytes(reference.minimal);
  const cases = [
    ['tt://?AAEB*', /invalid_base64/],
    ['tt://?AAEBA', /invalid_base64/],
    [relink(minimal.subarray(0, minimal.length - 1)), /invalid_link/],
    [relink(Buffer.concat([tlv(0, Buffer.from([2])), minimal.subarray(3)])), /unsupported_version/],
    [relink(Buffer.concat([minimal, tlv(9, Buffer.from([3]))])), /unsupported_version/],
    [relink(Buffer.concat([minimal, tlv(9, Buffer.from([1, 2]))])), /invalid_link/],
    [relink(Buffer.concat([tlv(0, Buffer.from([1])), tlv(1, Buffer.from('h')), tlv(2, Buffer.from('192.0.2.10:443')), tlv(5, Buffer.from('u'))])), /missing_credentials/],
    [relink(Buffer.concat([tlv(0, Buffer.from([1])), tlv(1, Buffer.from('h')), tlv(5, Buffer.from('u')), tlv(6, Buffer.from('p'))])), /missing_server/],
    [relink(Buffer.concat([tlv(0, Buffer.from([1])), tlv(1, Buffer.from('h')), tlv(2, Buffer.from('192.0.2.10')), tlv(5, Buffer.from('u')), tlv(6, Buffer.from('p'))])), /invalid_link/],
    [relink(Buffer.concat([tlv(0, Buffer.from([1])), tlv(1, Buffer.from('h')), tlv(2, Buffer.from('192.0.2.10:0')), tlv(5, Buffer.from('u')), tlv(6, Buffer.from('p'))])), /invalid_link/],
    [relink(Buffer.concat([minimal, tlv(8, Buffer.from([0x31, 0x01, 0x00]))])), /invalid_link/],
    [relink(Buffer.concat([minimal, tlv(12, Buffer.from([0xff, 0xfe]))])), /invalid_link/],
  ];
  for (const [link, expected] of cases) {
    assert.throws(() => decodeTrustTunnelLink(link), expected, link.slice(0, 40));
    const row = parseImport(link, 'work')[0];
    assert(row.error && !row.draft, link.slice(0, 40));
  }
});

test('IPv6 first addresses, two-byte lengths and a DER chain of two certificates decode', () => {
  const minimal = bytes(reference.minimal);
  const v6 = relink(Buffer.concat([tlv(0, Buffer.from([1])), tlv(1, Buffer.from('tt.fixture.invalid')), tlv(2, Buffer.from('[2001:db8::7]:8443')), tlv(5, Buffer.from('u')), tlv(6, Buffer.from('p'))]));
  assert.equal(config(v6).server, '2001:db8::7');
  assert.equal(config(v6).server_port, 8443);
  const der = Buffer.from(pem.filter(l => !l.startsWith('-----')).join(''), 'base64');
  const chain = Buffer.concat([der, der]);
  const length = Buffer.from([0x40 | (chain.length >> 8), chain.length & 0xff]);
  const two = relink(Buffer.concat([minimal, Buffer.from([8]), length, chain]));
  assert.deepEqual(config(two).tls.certificate, [...pem, ...pem]);
  const name = 'n'.repeat(70);
  const long = relink(Buffer.concat([minimal, Buffer.from([12, 0x40, 70]), Buffer.from(name)]));
  assert.equal(parseLink(long, 'work').draft.name, name);
});

test('imported deep-link profiles share as the Throne URI form with SNI and certificate lines', () => {
  const row = parseLink(reference.full, 'work');
  const link = shareProfiles([{ name: row.draft.name, kind: row.draft.kind, config: row.draft.config, format: 'link' }], 'links');
  assert(link.startsWith('tt://fixture-user:fixture-pass%3Awith%2Fspecial%3Dchars@127.0.0.1:8443?'), link);
  assert(link.includes('sni=sni.fixture.invalid') && link.includes('tls_certificate='), link);
  const back = parseLink(link, 'work');
  assert.deepEqual(back.draft.config, row.draft.config);
});
