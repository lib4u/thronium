import { get } from './schemaAccess.ts';
import { b, f, json, list, n, select, type Config, type Field, type Label } from './schemaFields.ts';

// Xray stream settings (transport and TLS/Reality) of the structured VLESS form.
export function xrayTransport(config: Config): Field[] {
  const net = get(config, 'streamSettings.network');
  const fields = [
    select('streamSettings.network', 'profiles.transport_14b5ffe', [
      'raw',
      'xhttp',
      'ws',
      'httpupgrade',
      'grpc',
    ]),
  ];
  if (net === 'raw')
    fields.push(json('streamSettings.rawSettings', 'profiles.raw_transport_options_8b1bdd1'));
  if (net === 'grpc')
    fields.push(
      f('streamSettings.grpcSettings.serviceName', 'profiles.service_name_122c35b'),
      f('streamSettings.grpcSettings.authority', 'profiles.authority_1bd64fa'),
      b('streamSettings.grpcSettings.multiMode', 'profiles.multi_mode_6dafe82'),
    );
  if (net === 'ws' || net === 'httpupgrade') {
    const base = net === 'ws' ? 'streamSettings.wsSettings.' : 'streamSettings.httpupgradeSettings.';
    fields.push(
      f(base + 'path', 'profiles.path_ad38caf'),
      f(base + 'host', 'profiles.host_218fdd0'),
      json(base + 'headers', 'profiles.headers_fa8f78f'),
    );
    if (net === 'ws') fields.push(n(base + 'heartbeatPeriod', 'profiles.heartbeat_period_9cc5f96'));
  }
  if (net === 'xhttp') {
    const base = 'streamSettings.xhttpSettings.';
    fields.push(
      f(base + 'host', 'profiles.host_218fdd0'),
      f(base + 'path', 'profiles.path_ad38caf'),
      select(base + 'mode', 'profiles.mode_aa431f5', ['auto', 'packet-up', 'stream-up', 'stream-one']),
      json(base + 'extra.headers', 'profiles.headers_fa8f78f'),
    );
    for (const [key, message] of [
      ['xPaddingBytes', 'profiles.padding_bytes_83c53f0'],
      ['xPaddingKey', 'profiles.padding_key_db56641'],
      ['xPaddingHeader', 'profiles.padding_header_b13a89e'],
      ['sessionIDKey', 'profiles.session_id_key_9d5937f'],
      ['sessionIDTable', 'profiles.session_id_alphabet_ef10e7f'],
      ['sessionIDLength', 'profiles.session_id_length_ca9739e'],
      ['seqKey', 'profiles.sequence_key_fb4d0d7'],
      ['uplinkDataKey', 'profiles.uplink_data_key_1939c26'],
      ['uplinkChunkSize', 'profiles.uplink_chunk_size_4e78ee5'],
      ['scMaxEachPostBytes', 'profiles.maximum_post_bytes_119ff01'],
      ['scMinPostsIntervalMs', 'profiles.minimum_post_interval_ms_f17be85'],
      ['scStreamUpServerSecs', 'profiles.stream_up_server_duration_s_22f4b19'],
    ] as [string, Label][])
      fields.push(f(base + 'extra.' + key, message));
    for (const [key, message, options] of [
      [
        'xPaddingPlacement',
        'profiles.padding_placement_1d5fbd4',
        ['queryInHeader', 'cookie', 'header', 'query'],
      ],
      ['xPaddingMethod', 'profiles.padding_method_e576dea', ['repeat-x', 'tokenish']],
      ['uplinkHTTPMethod', 'profiles.uplink_http_method_67b68fa', ['POST', 'PUT', 'PATCH', 'GET']],
      ['sessionIDPlacement', 'profiles.session_id_placement_74bdbd9', ['path', 'cookie', 'header', 'query']],
      ['seqPlacement', 'profiles.sequence_placement_90e44b7', ['path', 'cookie', 'header', 'query']],
      ['uplinkDataPlacement', 'profiles.uplink_data_placement_c103f7a', ['auto', 'body', 'cookie', 'header']],
    ] as [string, Label, string[]][])
      fields.push(select(base + 'extra.' + key, message, options));
    fields.push(
      b(base + 'extra.xPaddingObfsMode', 'profiles.padding_obfuscation_ae78184'),
      b(base + 'extra.noGRPCHeader', 'profiles.omit_grpc_header_7030048'),
      b(base + 'extra.noSSEHeader', 'profiles.omit_sse_header_529fb6e'),
      n(base + 'extra.scMaxBufferedPosts', 'profiles.maximum_buffered_posts_62c72bf'),
      n(base + 'extra.serverMaxHeaderBytes', 'profiles.maximum_header_bytes_d75a512'),
    );
    for (const [key, message] of [
      ['maxConcurrency', 'profiles.maximum_concurrency_71192b1'],
      ['maxConnections', 'profiles.maximum_connections_4f908dd'],
      ['cMaxReuseTimes', 'profiles.connection_reuse_limit_155fbe2'],
      ['hMaxRequestTimes', 'profiles.request_reuse_limit_edda12e'],
      ['hMaxReusableSecs', 'profiles.reusable_duration_s_b82871b'],
    ] as [string, Label][])
      fields.push(f(base + 'extra.xmux.' + key, message));
    fields.push(
      n(base + 'extra.xmux.hKeepAlivePeriod', 'profiles.http_keepalive_period_987016b', -1),
      json(base + 'extra.downloadSettings', 'profiles.download_settings_04450c0'),
    );
  }
  fields.push(json('streamSettings.finalmask', 'profiles.finalmask_51b40a8'));
  return fields;
}
export function xrayTLS(config: Config): Field[] {
  const security = get(config, 'streamSettings.security');
  const fields = [select('streamSettings.security', 'profiles.security_96ca41f', ['none', 'tls', 'reality'])];
  if (security === 'tls' || security === 'reality') {
    const base = security === 'tls' ? 'streamSettings.tlsSettings.' : 'streamSettings.realitySettings.';
    fields.push(
      f(base + 'serverName', 'profiles.server_name_sni_f265323'),
      f(base + 'fingerprint', 'profiles.fingerprint_3517567'),
    );
    if (security === 'tls')
      fields.push(
        list(base + 'alpn', 'profiles.alpn_b0dc97a'),
        f(base + 'pinnedPeerCertSha256', 'profiles.pinned_certificate_sha_256_71a9d71'),
        f(base + 'verifyPeerCertByName', 'profiles.certificate_name_5d1f19f'),
      );
    else
      fields.push(
        f(base + 'password', 'profiles.public_key_base64url_a1a8cc6'),
        f(base + 'shortId', 'profiles.short_id_7af1042'),
        f(base + 'spiderX', 'profiles.spider_x_b75c035'),
      );
  }
  return fields;
}
export const xrayMuxFields: Field[] = [
  b('mux.enabled', 'profiles.multiplexing_332faa9'),
  n('mux.concurrency', 'profiles.concurrency_b7ffe61', -1),
  n('mux.xudpConcurrency', 'profiles.xudp_concurrency_377892e'),
  select('mux.xudpProxyUDP443', 'profiles.udp_443_policy_805fef6', ['reject', 'allow', 'skip']),
];
