// Protocol-specific link readers: Xray VLESS, WireGuard queries, VMess JSON links and Hysteria congestion.
import type { Draft } from '../api';
import { awgFields, parse, type Config } from './schema.ts';
import { maxXrayEarlyData } from './wsEarlyData.ts';
import { allTraffic } from './wireguardDefaults.ts';
import {
  fail,
  object,
  number,
  boolean,
  list,
  decodeBase64,
  Query,
  assign,
  headers,
  tls,
  transport,
  mux,
  draft,
} from './importValues.ts';

export function xray(query: Query, server: string, port: number, id: string): Config {
  if (!id) return fail('missing_credentials');
  const config: Config = {
    protocol: 'vless',
    settings: { address: server, port, id, encryption: query.get('encryption') || 'none' },
  };
  assign(config.settings as Config, query, { flow: 'flow' });
  let network = query.get('type') || 'raw';
  if (network === 'tcp') network = 'raw';
  if (network === 'splithttp') network = 'xhttp';
  if (!['raw', 'xhttp', 'ws', 'httpupgrade', 'grpc'].includes(network)) return fail('unsupported_transport');
  const security = query.get('security') || 'none';
  const stream: Config = { network, security };
  config.streamSettings = stream;
  if (security === 'tls' || security === 'reality') {
    const secure: Config = {};
    const sni = query.get('sni', 'peer', 'server_name');
    if (sni) secure.serverName = sni;
    assign(secure, query, { fp: 'fingerprint' });
    if (security === 'tls') {
      const insecure = query.get('allowInsecure', 'allow_insecure', 'insecure');
      if (insecure !== undefined) secure.allowInsecure = boolean(insecure);
      assign(secure, query, { pcs: 'pinnedPeerCertSha256', vcn: 'verifyPeerCertByName' });
      assign(secure, query, { alpn: 'alpn' }, (s) => list(s));
    } else {
      assign(secure, query, { pbk: 'password', sid: 'shortId', spx: 'spiderX' });
    }
    stream[security + 'Settings'] = secure;
  }
  const setting: Config = {};
  const rawHeader = query.get('headerType');
  if (network === 'raw' && rawHeader === 'http') {
    const request: Config = {};
    const paths = query.get('path');
    if (paths) request.path = list(paths);
    const host = query.get('host');
    if (host) request.headers = { Host: list(host) };
    setting.header = { type: 'http', request };
  } else if (network === 'grpc') {
    assign(setting, query, { serviceName: 'serviceName', authority: 'authority' });
    const mode = query.get('mode');
    if (mode && !['gun', 'multi'].includes(mode)) return fail('unsupported_transport');
    if (mode) setting.multiMode = mode === 'multi';
  } else if (network !== 'raw') {
    assign(setting, query, { host: 'host', path: 'path' });
    const rawHeaders = query.get('headers');
    if (network === 'xhttp') {
      assign(setting, query, { mode: 'mode' });
      const extra = query.get('extra');
      const extras: Config = extra ? object(JSON.parse(extra)) : {};
      if (rawHeaders) extras.headers = headers(rawHeaders, false);
      assign(extras, query, {
        x_padding_bytes: 'xPaddingBytes',
        sc_max_each_post_bytes: 'scMaxEachPostBytes',
        sc_min_posts_interval_ms: 'scMinPostsIntervalMs',
      });
      assign(extras, query, { no_grpc_header: 'noGRPCHeader' }, boolean);
      const xmux = extras.xmux ? object(extras.xmux) : {};
      assign(xmux, query, {
        max_concurrency: 'maxConcurrency',
        max_connections: 'maxConnections',
        max_reuse_times: 'cMaxReuseTimes',
        max_request_times: 'hMaxRequestTimes',
        max_reusable_secs: 'hMaxReusableSecs',
      });
      assign(xmux, query, { keep_alive_period: 'hKeepAlivePeriod' }, (s) => number(s));
      if (Object.keys(xmux).length) extras.xmux = xmux;
      if (Object.keys(extras).length) setting.extra = extras;
    } else {
      if (rawHeaders) setting.headers = headers(rawHeaders, false);
      const ed = query.get('ed');
      if (ed)
        setting.path =
          String(setting.path || '/') +
          (String(setting.path || '').includes('?') ? '&' : '?') +
          'ed=' +
          number(ed, maxXrayEarlyData);
      assign(setting, query, { heartbeat_period: 'heartbeatPeriod' }, (s) => number(s));
    }
  }
  if (Object.keys(setting).length) stream[network + 'Settings'] = setting;
  const fm = query.get('fm', 'finalmask');
  if (fm) stream.finalmask = object(JSON.parse(fm));
  const multiplex: Config = {};
  assign(multiplex, query, { mux: 'enabled' }, boolean);
  assign(multiplex, query, { mux_concurrency: 'concurrency', mux_xudp_concurrency: 'xudpConcurrency' }, (s) =>
    number(s),
  );
  if (Object.keys(multiplex).length) config.mux = multiplex;
  return config;
}
export function wgQuery(query: Query, server: string, port: number, username: string): Config {
  const config: Config = {
    type: 'wireguard',
    private_key: query.get('private_key', 'privatekey') || username,
    peers: [],
  };
  const peer: Config = {
    address: server,
    port,
    public_key: query.get('public_key', 'publickey', 'peer_public_key') || '',
    allowed_ips: allTraffic(),
  };
  const allowed = query.get('allowed_ips');
  if (allowed !== undefined) peer.allowed_ips = list(allowed);
  const psk = query.get('pre_shared_key', 'preshared_key', 'presharedkey', 'psk');
  if (psk) peer.pre_shared_key = psk;
  const reserved = query.get('reserved');
  if (reserved) peer.reserved = list(reserved.replace(/-/g, ',')).map((s) => number(s, 255));
  const keepalive = query.get('persistent_keepalive_interval', 'persistent_keepalive', 'keepalive');
  if (keepalive)
    peer.persistent_keepalive_interval = parse(
      { path: '', label: 'profiles.port_651531e', kind: 'range' },
      keepalive,
    );
  config.peers = [peer];
  const local = query.get('local_address');
  const addresses = query.get('address', 'ip');
  config.address = local ? list(local, '-') : addresses ? list(addresses) : [];
  if (!(config.address as string[]).length) return fail('missing_address');
  config.address = (config.address as string[]).map((ip) =>
    ip.includes('/') ? ip : ip + (ip.includes(':') ? '/128' : '/32'),
  );
  assign(config, query, { mtu: 'mtu', workers: 'workers' }, (s) => number(s));
  assign(config, query, { use_system_interface: 'system' }, boolean);
  assign(config, query, { udp_timeout: 'udp_timeout' });
  const awg: Config = {};
  const enabled = query.get('enable_amnezia');
  for (const field of awgFields) {
    const key = field.path.split('.').slice(-1)[0];
    const value = query.get(key);
    if (value !== undefined) awg[key] = parse(field, field.kind === 'bool' ? String(boolean(value)) : value);
  }
  if (enabled === 'true' || Object.keys(awg).length) config.amnezia_wg = awg;
  if (!config.private_key || !peer.public_key) return fail('missing_key');
  return config;
}
export function vmessJson(text: string, groupId: string): { draft: Draft; warnings: string[] } {
  const value = object(JSON.parse(decodeBase64(text.slice(8).split('#')[0])));
  const query = new Query(typeof value.throneExtra === 'string' ? value.throneExtra : '');
  if (!query.values.has('type'))
    query.values.set('type', [String(value.type === 'http' ? 'http' : value.net || 'tcp')]);
  // As Qt's vmess::ParseFromLink, TLS details apply only when "tls" is "tls";
  // a stray SNI or fingerprint of a plain link does not turn TLS on.
  const secured = value.tls === 'tls';
  for (const [key, input] of Object.entries({
    host: value.host,
    path: value.path,
    ...(secured ? { sni: value.sni, alpn: value.alpn, fp: value.fp } : {}),
  }))
    if (input && !query.values.has(key)) query.values.set(key, [String(input)]);
  if (value.net === 'grpc') {
    query.values.delete('path');
    query.values.set('serviceName', [String(value.path || '')]);
  }
  if (secured) query.values.set('security', ['tls']);
  if (secured && (value.insecure !== undefined || value.allowInsecure !== undefined))
    query.values.set('insecure', [String(value.insecure ?? value.allowInsecure)]);
  if (!value.id || !value.add) return fail('missing_server');
  const config: Config = {
    type: 'vmess',
    server: String(value.add),
    server_port: number(String(value.port), 65535, 1),
    uuid: String(value.id),
    security: String(value.scy || 'auto'),
    alter_id: number(String(value.aid || 0)),
  };
  const trans = transport(query);
  if (trans) config.transport = trans;
  const secure = tls(query, false);
  if (secure) config.tls = secure;
  const multi = mux(query);
  if (multi) config.multiplex = multi;
  assign(
    config,
    query,
    { globalPadding: 'global_padding', authenticatedLength: 'authenticated_length' },
    boolean,
  );
  assign(config, query, { packetEncoding: 'packet_encoding' });
  return { draft: draft(config, groupId, String(value.ps || '')), warnings: query.warnings() };
}
export function hysteriaBBR(config: Config, query: Query) {
  // sing-quic/hysteria2/client.go selects BBR when sendBPS is zero. Only this
  // exact FinalMask subset is equivalent; unknown masks remain explicit warnings.
  for (const key of ['fm', 'finalmask']) {
    const values = query.values.get(key);
    if (!values || values.length !== 1) continue;
    let mask: Config;
    try {
      mask = object(JSON.parse(values[0]));
    } catch {
      continue;
    }
    const raw = mask.quicParams;
    if (
      !raw ||
      typeof raw !== 'object' ||
      Array.isArray(raw) ||
      Object.keys(mask).some((k) => k !== 'quicParams')
    )
      continue;
    const params = raw as Config;
    if (
      params.congestion !== 'bbr' ||
      Object.keys(params).some((k) => !['congestion', 'debug'].includes(k)) ||
      (params.debug !== undefined && params.debug !== false)
    )
      continue;
    if (
      (config.up_mbps && config.up_mbps !== 0) ||
      (config.down_mbps && config.down_mbps !== 0) ||
      (config.bbr_profile && config.bbr_profile !== 'standard')
    )
      continue;
    query.get(key);
    config.up_mbps = 0;
    config.down_mbps = 0;
    config.bbr_profile = 'standard';
  }
}
