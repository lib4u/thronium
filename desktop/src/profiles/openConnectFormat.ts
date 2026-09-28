// OpenConnect command lines and AnyConnect XML profiles, as src/configs/sub/vpnFileImport.cpp reads them.
import type { Config } from './schema';
import { fail, unsupported, words, owns, pathWarning } from './fileFormats.ts';

const OC_VALUE = new Set([
  'authgroup',
  'base-mtu',
  'cafile',
  'cert-expire-warning',
  'certificate',
  'compression',
  'config',
  'cookie',
  'csd-user',
  'csd-wrapper',
  'dpd',
  'dtls-local-port',
  'force-dpd',
  'force-trojan',
  'form-entry',
  'gnutls-priority',
  'http-auth',
  'interface',
  'key-password',
  'key-type',
  'local-hostname',
  'localname',
  'mca-certificate',
  'mca-key',
  'mca-key-password',
  'mtu',
  'os',
  'pid-file',
  'protocol',
  'proxy',
  'proxy-auth',
  'queue-len',
  'reconnect-timeout',
  'resolve',
  'script',
  'server',
  'servercert',
  'setuid',
  'sni',
  'sslkey',
  'token-mode',
  'token-secret',
  'user',
  'useragent',
  'user-agent',
  'usergroup',
  'version-string',
  'xmlconfig',
]);
/** Client-side options with no endpoint meaning, ignored as in Qt. */
const OC_IGNORED = new Set([
  'authenticate',
  'background',
  'cert-expire-warning',
  'config',
  'cookie-on-stdin',
  'cookieonly',
  'csd-user',
  'deflate',
  'dump-http-traffic',
  'gnutls-debug',
  'gnutls-priority',
  'help',
  'interface',
  'key-password-from-fsid',
  'key-type',
  'libproxy',
  'no-deflate',
  'no-proxy',
  'non-inter',
  'passtos',
  'passwd-on-stdin',
  'pid-file',
  'printcookie',
  'quiet',
  'resolve',
  'script',
  'script-tun',
  'setuid',
  'syslog',
  'timestamp',
  'verbose',
  'version',
  'xmlconfig',
]);
/** Short options (Qt vpnfiOcLongName). */
const OC_SHORT: Record<string, string> = {
  b: 'background',
  C: 'cookie',
  c: 'certificate',
  e: 'cert-expire-warning',
  F: 'form-entry',
  g: 'usergroup',
  h: 'help',
  i: 'interface',
  k: 'sslkey',
  l: 'syslog',
  m: 'mtu',
  p: 'key-password',
  P: 'proxy',
  Q: 'queue-len',
  q: 'quiet',
  S: 'script-tun',
  s: 'script',
  t: 'token-mode',
  U: 'setuid',
  u: 'user',
  V: 'version',
  v: 'verbose',
  x: 'xmlconfig',
};
export function openConnect(text: string): { config: Config; warnings: string[] } {
  const config: Config = { type: 'openconnect', flavor: 'anyconnect' };
  const tls: Config = {};
  const warnings = new Set<string>();
  const fields: Record<string, string> = {
    protocol: 'flavor',
    server: 'server',
    user: 'username',
    username: 'username',
    password: 'password',
    cookie: 'cookie',
    authgroup: 'auth_group',
    usergroup: 'auth_group',
    useragent: 'user_agent',
    os: 'reported_os',
    'local-hostname': 'local_hostname',
    'token-mode': 'token.mode',
    'token-secret': 'token.secret',
    'key-password': 'tls.client_key_password',
    servercert: 'tls.peer_fingerprint',
    cafile: 'tls.certificate_authority_path',
    certificate: 'tls.client_certificate_path',
    sslkey: 'tls.client_key_path',
  };
  const flags: Record<string, string> = {
    'no-dtls': 'no_udp',
    'no-compression': 'compression_disabled',
    'disable-ipv6': 'ipv6_disabled',
    'no-http-keepalive': 'http_keepalive_disabled',
    'no-xmlpost': 'xml_post_disabled',
    'no-external-auth': 'external_auth_disabled',
    'no-passwd': 'password_authentication_disabled',
    'no-system-trust': 'tls.system_trust_disabled',
    'allow-insecure-crypto': 'allow_insecure_crypto',
    pfs: 'pfs',
  };
  function put(path: string, value: unknown) {
    const [a, b] = path.split('.');
    if (a === 'tls') tls[b] = value;
    else if (b) {
      config[a] ||= {};
      (config[a] as Config)[b] = value;
    } else config[a] = value;
  }
  // Qt's vpnfiIsOcCommandLine / vpnfiWalkOcArgs, including short options,
  // `option value` lines of a config file and a bare server address.
  const lines = text.split('\n');
  const commandLine = lines.map((line) => line.trim()).find((line) => line && !line.startsWith('#'));
  let argv: string[] = [];
  if (commandLine && (commandLine.startsWith('openconnect') || commandLine.startsWith('-')))
    argv = words(lines.map((line) => line.trim().replace(/\r/g, '').replace(/\\$/, '')).join(' ') + ' ');
  else
    for (const line of lines) {
      // `option = value` is accepted beside Qt's `option=value` and `option value`.
      const tokens = words(line.replace(/^(\s*[^\s=#;]+)\s*=\s*/, '$1='));
      if (!tokens.length) continue;
      if (tokens[0].includes('=')) argv.push('--' + tokens[0]);
      else if (tokens.length > 1) argv.push('--' + tokens[0] + '=' + tokens.slice(1).join(' '));
      else if (OC_VALUE.has(tokens[0]) || owns(flags, tokens[0]) || OC_IGNORED.has(tokens[0]))
        argv.push('--' + tokens[0]);
      else argv.push(tokens[0]);
    }
  const apply = (key: string, value: string | undefined) => {
    if (owns(flags, key)) {
      if (value === undefined || ['true', '1', 'yes'].includes(value)) put(flags[key], true);
      else if (!['false', '0', 'no'].includes(value)) fail();
      return;
    }
    if (OC_IGNORED.has(key)) return;
    if (!owns(fields, key)) {
      warnings.add('file:' + key);
      return;
    }
    if (!value) throw new Error('invalid_vpn_file');
    if (key === 'servercert') put(fields[key], [...((tls.peer_fingerprint as string[]) || []), value]);
    else {
      put(fields[key], value);
      if (fields[key].endsWith('_path')) pathWarning(warnings, key, value);
    }
  };
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (
      i === 0 &&
      (token === 'openconnect' || token.endsWith('/openconnect') || token.endsWith('openconnect.exe'))
    )
      continue;
    if (token.startsWith('--')) {
      let key = token.slice(2);
      let value: string | undefined;
      const equal = key.indexOf('=');
      if (equal >= 0) {
        value = key.slice(equal + 1);
        key = key.slice(0, equal);
      } else if (OC_VALUE.has(key) && i + 1 < argv.length) value = argv[++i];
      else if (
        !owns(flags, key) &&
        !OC_IGNORED.has(key) &&
        i + 2 < argv.length &&
        !argv[i + 1].startsWith('-')
      )
        // Swallow a detached value only while a trailing positional is left.
        value = argv[++i];
      apply(key, value);
      continue;
    }
    if (token.length > 1 && token.startsWith('-')) {
      for (let c = 1; c < token.length; c++) {
        const key = OC_SHORT[token[c]];
        if (!key) {
          warnings.add('file:-' + token[c]);
          break;
        }
        if (!OC_VALUE.has(key)) {
          apply(key, undefined);
          continue;
        }
        apply(key, c + 1 < token.length ? token.slice(c + 1) : argv[++i]);
        break;
      }
      continue;
    }
    config.server = token;
  }
  if (
    !config.server ||
    !['anyconnect', 'gp', 'fortinet', 'f5', 'pulse', 'nc'].includes(String(config.flavor))
  )
    fail();
  const url = new URL(
    String(config.server).includes('://') ? String(config.server) : 'https://' + config.server,
  );
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname) fail();
  config.server = url.toString();
  if (Object.keys(tls).length) config.tls = tls;
  return { config, warnings: [...warnings] };
}

export function anyConnectXml(text: string): { config: Config; warnings: string[]; name?: string }[] {
  if (typeof DOMParser === 'undefined') throw new Error('xml_parser_unavailable');
  const doc = new DOMParser().parseFromString(text, 'application/xml');
  if (doc.querySelector('parsererror')) fail();
  const all = [...doc.getElementsByTagName('*')];
  return all
    .filter((e) => e.localName === 'HostEntry')
    .map((entry) => {
      const children = [...entry.getElementsByTagName('*')];
      const get = (name: string) => children.find((e) => e.localName === name)?.textContent?.trim();
      const server = get('HostAddress');
      if (!server) fail();
      const config: Config = { type: 'openconnect', flavor: 'anyconnect', server };
      const group = get('UserGroup');
      if (group) config.auth_group = group;
      const protocol = get('PrimaryProtocol');
      if (protocol && protocol.toLowerCase() !== 'ssl') unsupported();
      const warnings = children
        .filter(
          (e) =>
            !['HostName', 'HostAddress', 'UserGroup', 'PrimaryProtocol'].includes(e.localName) &&
            !e.children.length,
        )
        .map((e) => 'file:' + e.localName);
      return { config, name: get('HostName'), warnings };
    });
}
