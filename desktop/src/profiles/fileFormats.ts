// Mappings follow src/configs/sub/vpnFileImport.cpp and configs/outbounds/*.
// Unmapped directives stay visible in the import review, never silently applied.
import type { Config } from './schema';

export const fail = (): never => {
  throw new Error('invalid_vpn_file');
};
export const unsupported = (): never => {
  throw new Error('unsupported_vpn_file');
};
/**
 * Qt's vpnfiTokenize: quotes may start inside a token (`--user="a b"`), only
 * `\"` and `\\` escape inside double quotes, a backslash escapes outside
 * quotes, and `#`/`;` start a comment only at the start of a token.
 */
export const words = (line: string) => {
  const tokens: string[] = [];
  let token = '';
  let quote = '';
  let inToken = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (ch === quote) quote = '';
      else if (ch === '\\' && quote === '"' && (line[i + 1] === '"' || line[i + 1] === '\\'))
        token += line[++i];
      else token += ch;
      continue;
    }
    if (/\s/.test(ch)) {
      if (inToken) tokens.push(token);
      token = '';
      inToken = false;
      continue;
    }
    if (!inToken && (ch === '#' || ch === ';')) break;
    inToken = true;
    if (ch === '"' || ch === "'") quote = ch;
    else if (ch === '\\' && i + 1 < line.length) token += line[++i];
    else token += ch;
  }
  if (inToken) tokens.push(token);
  return tokens;
};
export const owns = (object: object, key: string) => Object.prototype.hasOwnProperty.call(object, key);
const num = (s: string, max = 4294967295) => (/^\d+$/.test(s) && Number(s) <= max ? Number(s) : fail());
const network = (value: string) =>
  /^(udp[46]?|tcp[46]?(?:-client)?)$/.test(value) ? value.replace('-client', '') : unsupported();
export const pathWarning = (warnings: Set<string>, key: string, path: string) => {
  if (!/^(?:\/|[A-Za-z]:[\\/])/.test(path)) warnings.add('file-relative:' + key);
};

export function openVpn(text: string): { config: Config; warnings: string[]; name?: string } {
  const tls: Config = { remote_certificate_tls: 'server' };
  const config: Config = { type: 'openvpn-client', mode: 'tls', network: 'udp', tls };
  const warnings = new Set<string>();
  const remotes: Config[] = [];
  let defaultPort = 1194;
  let direction: string | undefined;
  const name = text.match(/^\s*#\s*OVPN_FRIENDLY_PROFILE_NAME=(.+)$/m)?.[1].trim();
  const pathFields: Record<string, string> = {
    ca: 'certificate_path',
    cert: 'client_certificate_path',
    key: 'client_key_path',
    'crl-verify': 'crl_path',
  };
  const stringFields: Record<string, string> = {
    cipher: 'cipher',
    auth: 'auth',
    topology: 'topology',
    'auth-retry': 'auth_retry',
    'data-ciphers-fallback': 'data_ciphers_fallback',
    'allow-compression': 'allow_compression',
    compress: 'compression',
    'route-gateway': 'route_gateway',
  };
  const numberFields: Record<string, string> = {
    'tun-mtu': 'mtu',
    fragment: 'fragment',
    'reneg-bytes': 'renegotiate_bytes',
    'reneg-pkts': 'renegotiate_packets',
    'explicit-exit-notify': 'explicit_exit_notify',
    'route-metric': 'route_metric',
  };
  const durations: Record<string, string> = {
    ping: 'ping_interval',
    'ping-restart': 'ping_restart',
    'reneg-sec': 'renegotiate_interval',
    'tls-timeout': 'tls_timeout',
    'hand-window': 'handshake_window',
  };
  const flags: Record<string, string> = {
    'remote-random': 'remote_random',
    'route-nopull': 'route_no_pull',
    'block-ipv6': 'block_ipv6',
  };
  // Client lifecycle directives have no bearing on the imported core profile.
  const benign = new Set([
    'client',
    'tls-client',
    'nobind',
    'persist-key',
    'persist-tun',
    'auth-nocache',
    'verb',
    'mute',
    'resolv-retry',
    'float',
    'pull',
  ]);
  function remote(args: string[], net?: string, port?: number) {
    if (!args[0]) fail();
    const explicitPort = args[1] && /^\d+$/.test(args[1]);
    remotes.push({
      server: args[0],
      ...(explicitPort ? { server_port: num(args[1], 65535) } : port ? { server_port: port } : {}),
      ...(args[explicitPort ? 2 : 1] || net ? { network: network(args[explicitPort ? 2 : 1] || net!) } : {}),
    });
  }
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || /^[#;]/.test(line)) continue;
    const tag = line.match(/^<([\w-]+)>$/)?.[1];
    if (tag) {
      const body: string[] = [];
      while (++i < lines.length && lines[i].trim() !== `</${tag}>`) body.push(lines[i].trim());
      if (i === lines.length) fail();
      if (tag === 'pkcs12') unsupported();
      if (tag === 'connection') {
        let net: string | undefined;
        let port: number | undefined;
        const directives = body.map(words);
        for (const [key, value] of directives) {
          if (key === 'proto') net = network(value);
          if (key === 'port' || key === 'rport') port = num(value, 65535);
        }
        for (const [key, ...args] of directives)
          if (key === 'remote') remote(args, net, port);
          else if (!['proto', 'port', 'rport'].includes(key)) warnings.add('file:connection/' + key);
      } else if (['ca', 'cert', 'key'].includes(tag))
        tls[{ ca: 'certificate', cert: 'client_certificate', key: 'client_key' }[tag]!] = body;
      else if (tag.startsWith('tls-')) tls.control_wrap = { type: tag.replace(/-/g, '_'), key: body };
      else if (tag === 'secret') {
        config.mode = 'static_key';
        config.static_key = body;
      } else if (tag === 'auth-user-pass') {
        config.username = body[0] || '';
        config.password = body[1] || '';
      } else if (tag === 'peer-fingerprint')
        tls.peer_fingerprint = body.map((v) => v.replace(/:/g, '').toLowerCase());
      else warnings.add('file:<' + tag + '>');
      continue;
    }
    const [key, value = '', ...args] = words(line.replace(/\s+[#;].*$/, ''));
    if (
      ['server', 'server-ipv6', 'tls-server', 'pkcs12'].includes(key) ||
      (key === 'mode' && value === 'server')
    )
      unsupported();
    if (key === 'dev' || key === 'dev-type') {
      if (!value.startsWith('tun')) unsupported();
    } else if (key === 'remote') remote([value, ...args]);
    else if (key === 'proto') config.network = network(value);
    else if (key === 'port' || key === 'rport') defaultPort = num(value, 65535);
    else if (key === 'key-direction')
      direction = value === '1' ? 'client' : value === '0' ? 'server' : fail();
    else if (owns(pathFields, key)) {
      if (value !== '[inline]') {
        tls[pathFields[key]] = value;
        pathWarning(warnings, key, value);
      }
    } else if (['tls-auth', 'tls-crypt', 'tls-crypt-v2'].includes(key)) {
      if (value !== '[inline]') {
        tls.control_wrap = { type: key.replace(/-/g, '_'), key_path: value };
        pathWarning(warnings, key, value);
      }
      if (args[0]) direction = args[0] === '1' ? 'client' : args[0] === '0' ? 'server' : fail();
    } else if (key === 'secret') {
      config.mode = 'static_key';
      if (value !== '[inline]') {
        config.static_key_path = value;
        pathWarning(warnings, key, value);
      }
      if (args[0]) direction = args[0] === '1' ? 'client' : 'server';
    } else if (key === 'auth-user-pass') {
      if (value && value !== '[inline]') warnings.add('file-external:auth-user-pass');
    } else if (key === 'remote-cert-tls') tls.remote_certificate_tls = value;
    else if (key === 'verify-x509-name') {
      tls.server_name = value;
      tls.server_name_type = args[0] || 'subject';
    } else if (key === 'peer-fingerprint')
      tls.peer_fingerprint = [
        ...((tls.peer_fingerprint as string[]) || []),
        value.replace(/:/g, '').toLowerCase(),
      ];
    else if (key === 'data-ciphers' || key === 'ncp-ciphers') config.data_ciphers = value.split(':');
    else if (owns(stringFields, key)) config[stringFields[key]] = value;
    else if (owns(numberFields, key)) config[numberFields[key]] = num(value || '1');
    else if (owns(durations, key)) {
      config[durations[key]] = num(value) + 's';
      if (value === '0' && ['reneg-sec', 'ping-restart'].includes(key))
        config[key === 'reneg-sec' ? 'renegotiate_disabled' : 'ping_restart_disabled'] = true;
    } else if (owns(flags, key)) config[flags[key]] = true;
    else if (key === 'mssfix') {
      config.mss_fix = num(value || '1492');
      if (value === '0') config.mss_fix_disabled = true;
      if (args[0] === 'mtu') config.mss_fix_mode = 'mtu';
    } else if (key === 'redirect-gateway' || key === 'redirect-private') {
      config[key.replace('-', '_')] = true;
      config.redirect_gateway_flags = [value, ...args].filter(Boolean);
    } else if (key === 'static-challenge') {
      config.static_challenge = value;
      config.static_challenge_echo = args[0] === '1';
    } else if (key === 'pull-filter')
      config.pull_filters = [
        ...((config.pull_filters as Config[]) || []),
        { action: value, text: args.join(' ') },
      ];
    else if (!benign.has(key)) warnings.add('file:' + key);
  }
  if (!remotes.length || remotes.some((r) => r.server_port === 0)) fail();
  for (const r of remotes) {
    r.server_port ??= defaultPort;
    r.network ??= config.network;
  }
  if (remotes.length === 1) Object.assign(config, remotes[0]);
  else config.servers = remotes;
  if (direction) {
    if (config.mode === 'static_key') config.key_direction = direction;
    else if (tls.control_wrap) (tls.control_wrap as Config).direction = direction;
  }
  return { config, warnings: [...warnings], name };
}

/** Options that take a value (Qt vpnfiOcOptionHasValue). */
