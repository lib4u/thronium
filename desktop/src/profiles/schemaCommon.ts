import { get } from './schemaAccess.ts';
import { b, f, json, list, n, secret, select, type Config, type Field, type Label } from './schemaFields.ts';

/** sing-box V2Ray transports, and those that carry an HTTP host and path. */
export const singBoxTransports = ['http', 'ws', 'quic', 'grpc', 'httpupgrade'];
export const httpTransports = ['http', 'ws', 'httpupgrade'];

// Field sets shared by several sing-box protocol forms.
export const peerFields: Field[] = [
  f('address', 'profiles.peer_address_3022859'),
  n('port', 'profiles.peer_port_67731a7', 1, 65535),
  f('public_key', 'profiles.public_key_d4ae820'),
  secret('pre_shared_key', 'profiles.pre_shared_key_e4a74cd'),
  list('allowed_ips', 'profiles.allowed_ips_cidr_de545d9'),
  f('persistent_keepalive_interval', 'profiles.persistent_keepalive_469c386', 'range'),
  f('reserved', 'profiles.reserved_bytes_c4dbc0c', 'numbers'),
];
const awgLabels: Record<string, Label> = {
  jc: 'profiles.jc_457b726',
  jmin: 'profiles.jmin_6cfa786',
  jmax: 'profiles.jmax_8053dfc',
  s1: 'profiles.s1_2f53849',
  s2: 'profiles.s2_a4e8f01',
  s3: 'profiles.s3_35155b3',
  s4: 'profiles.s4_930b5da',
  h1: 'profiles.h1_18a96bd',
  h2: 'profiles.h2_8965f21',
  h3: 'profiles.h3_87ea28c',
  h4: 'profiles.h4_d8e9bf2',
  i1: 'profiles.i1_d202a58',
  i2: 'profiles.i2_98bbb78',
  i3: 'profiles.i3_b1c4d22',
  i4: 'profiles.i4_0b99c5b',
  i5: 'profiles.i5_a30aa2a',
};
export const awgFields: Field[] = [
  ...['jc', 'jmin', 'jmax', 's1', 's2', 's3', 's4'].map((key) => n('amnezia_wg.' + key, awgLabels[key])),
  ...['h1', 'h2', 'h3', 'h4', 'i1', 'i2', 'i3', 'i4', 'i5'].map((key) =>
    f('amnezia_wg.' + key, awgLabels[key]),
  ),
  secret('amnezia_wg.header_protection_key', 'profiles.header_protection_key_3aa3beb'),
  ...(
    [
      ['content_padding_addition', 'profiles.content_padding_addition_1f22b60'],
      ['rekey_after_time', 'profiles.rekey_after_time_2477993'],
      ['rekey_timeout', 'profiles.rekey_timeout_cfcac44'],
      ['reject_after_time', 'profiles.reject_after_time_0fdcf7b'],
      ['keepalive_timeout', 'profiles.keepalive_timeout_3d5e7d4'],
      ['max_handshake_attempts', 'profiles.maximum_handshake_attempts_c06f7fc'],
    ] as [string, Label][]
  ).map(([path, message]) => f('amnezia_wg.' + path, message, 'range')),
  b('amnezia_wg.random_trailers', 'profiles.random_trailers_e8df28c'),
  b('amnezia_wg.disable_cookies', 'profiles.disable_cookies_6ef8746'),
];
export const dialFields: Field[] = [
  f('bind_interface', 'profiles.bind_to_interface_9f26272'),
  f('inet4_bind_address', 'profiles.ipv4_bind_address_9b62a46'),
  f('inet6_bind_address', 'profiles.ipv6_bind_address_8f7682e'),
  f('connect_timeout', 'profiles.connection_timeout_7377ec9'),
  b('tcp_fast_open', 'profiles.tcp_fast_open_9653922'),
  b('tcp_multi_path', 'profiles.multipath_tcp_463ed7d'),
  b('disable_tcp_keep_alive', 'profiles.disable_tcp_keepalive_0d15ef7'),
  f('tcp_keep_alive', 'profiles.tcp_keepalive_cb40da3'),
  f('tcp_keep_alive_interval', 'profiles.tcp_keepalive_interval_6e2b8f4'),
  b('udp_fragment', 'profiles.udp_fragmentation_e7f0487'),
  f('routing_mark', 'profiles.routing_mark_df7031d', 'mark'),
  b('reuse_addr', 'profiles.reuse_address_4633e61'),
  f('netns', 'profiles.network_namespace_linux_bac4bda'),
  json('domain_resolver', 'profiles.domain_resolver_4975521'),
];
export const muxFields: Field[] = [
  b('multiplex.enabled', 'profiles.multiplexing_332faa9'),
  select('multiplex.protocol', 'profiles.protocol_abb4c67', ['smux', 'yamux', 'h2mux']),
  n('multiplex.max_connections', 'profiles.maximum_connections_4f908dd'),
  n('multiplex.min_streams', 'profiles.minimum_streams_a698382'),
  n('multiplex.max_streams', 'profiles.maximum_streams_3239835'),
  b('multiplex.padding', 'profiles.padding_0f3626f'),
  b('multiplex.brutal.enabled', 'profiles.tcp_brutal_e3dd6bd'),
  n('multiplex.brutal.up_mbps', 'profiles.tcp_brutal_upload_mbps_8e647d2'),
  n('multiplex.brutal.down_mbps', 'profiles.tcp_brutal_download_mbps_3c43970'),
];
export const customFragmentFields: Field[] = [
  {
    ...b('tls_fragment.enabled', 'profiles.tls_fragmentation_custom_a9f1f47'),
    unsetLabel: 'profiles.not_set_7c11b6a',
    hint: 'profiles.applies_to_tls_over_tcp_when_enabled_both_ranges_fd9c61d',
  },
  {
    ...f('tls_fragment.size', 'profiles.custom_fragment_size_bytes_4c0459e', 'string-range'),
    min: 1,
    max: 65535,
    hint: 'profiles.1_65535_bytes_one_number_or_min_max_for_example__8eb5255',
  },
  {
    ...f('tls_fragment.sleep', 'profiles.custom_fragment_delay_ms_f3c6c40', 'string-range'),
    min: 0,
    max: 65535,
    hint: 'profiles.0_65535_ms_one_number_or_min_max_zero_sends_with_57c3618',
  },
];

export const tlsFields: Field[] = [
  b('tls.enabled', 'profiles.tls_49fa570'),
  f('tls.server_name', 'profiles.server_name_sni_f265323'),
  list('tls.alpn', 'profiles.alpn_b0dc97a'),
  b('tls.insecure', 'profiles.skip_certificate_verification_a559e43'),
  b('tls.disable_sni', 'profiles.disable_sni_51aa088'),
  b('tls.utls.enabled', 'profiles.utls_067c1cb'),
  select('tls.utls.fingerprint', 'profiles.utls_fingerprint_c43194e', [
    '',
    'chrome',
    'firefox',
    'edge',
    'safari',
    '360',
    'qq',
    'ios',
    'android',
    'random',
    'randomized',
  ]),
  b('tls.reality.enabled', 'profiles.reality_3644b2d'),
  f('tls.reality.public_key', 'profiles.reality_public_key_49253e5'),
  f('tls.reality.short_id', 'profiles.reality_short_id_f98b171'),
  select('tls.min_version', 'profiles.minimum_tls_version_53a3c25', ['1.0', '1.1', '1.2', '1.3']),
  select('tls.max_version', 'profiles.maximum_tls_version_35da107', ['1.0', '1.1', '1.2', '1.3']),
  list('tls.cipher_suites', 'profiles.cipher_suites_9566644'),
  list('tls.curve_preferences', 'profiles.tls_curves_a517102'),
  list('tls.certificate', 'profiles.ca_certificate_pem_0c71ee8'),
  f('tls.certificate_path', 'profiles.ca_certificate_file_ca0c290'),
  list('tls.certificate_public_key_sha256', 'profiles.pinned_certificate_sha_256_71a9d71'),
  list('tls.client_certificate', 'profiles.client_certificate_pem_5fe95b4'),
  f('tls.client_certificate_path', 'profiles.client_certificate_file_6c02a18'),
  list('tls.client_key', 'profiles.client_key_pem_a908781'),
  f('tls.client_key_path', 'profiles.client_key_file_fc19886'),
  b('tls.ech.enabled', 'profiles.ech_494d829'),
  list('tls.ech.config', 'profiles.ech_configuration_e84d6b4'),
  f('tls.ech.config_path', 'profiles.ech_configuration_file_91f8f75'),
  f('tls.ech.query_server_name', 'profiles.ech_query_server_name'),
  b('tls.fragment', 'profiles.tls_fragmentation_built_in_5b45cb4'),
  f('tls.fragment_fallback_delay', 'profiles.fragment_fallback_delay_8bdb127'),
  b('tls.record_fragment', 'profiles.tls_record_fragmentation_ccae5df'),
  b('tls.tls_tricks.mixedcase_sni', 'profiles.vary_sni_letter_case_98c7a26'),
  b('tls.spoof_enabled', 'profiles.tls_sni_spoofing_12c4bb9'),
  f('tls.spoof', 'profiles.spoof_sni_fda33c5'),
  select('tls.spoof_method', 'profiles.sni_spoofing_method_f93c179', [
    'wrong-sequence',
    'wrong-checksum',
    'wrong-ack',
    'wrong-md5',
    'wrong-timestamp',
  ]),
  f('tls.handshake_timeout', 'profiles.tls_handshake_timeout_90ef385'),
];
// sing-box QUICOptions embeds HTTP2Options: the two timers sit flat in the outbound.
export const quicFields: Field[] = [
  f('idle_timeout', 'profiles.quic_idle_timeout'),
  f('keep_alive_period', 'profiles.quic_keep_alive_period'),
  n('stream_receive_window', 'profiles.stream_receive_window_44ed75b'),
  n('connection_receive_window', 'profiles.connection_receive_window_c6f56c8'),
  n('max_concurrent_streams', 'profiles.maximum_concurrent_streams_7105175'),
  n('initial_packet_size', 'profiles.initial_packet_size_7ae346a'),
  b('disable_path_mtu_discovery', 'profiles.disable_path_mtu_discovery_e73852f'),
];
export const realmFields: Field[] = [
  f('realm.server_url', 'profiles.realm_server_url_f9d488c'),
  secret('realm.token', 'profiles.realm_token_41a75cf'),
  f('realm.realm_id', 'profiles.realm_id_e595d9c'),
  list('realm.stun_servers', 'profiles.stun_servers_34bb7f5'),
  select('realm.ip_version', 'profiles.ip_version_2069f65', [0, 4, 6]),
  b('realm.port_mapping.enabled', 'profiles.port_mapping_9c9c5ce'),
  f('realm.port_mapping.timeout', 'profiles.port_mapping_timeout_6170c58'),
  f('realm.port_mapping.lifetime', 'profiles.port_mapping_lifetime_6b3be9e'),
  json('realm.http_client', 'profiles.http_client_516f788'),
];

export function transportFields(config: Config): Field[] {
  const type = get(config, 'transport.type');
  const fields = [select('transport.type', 'profiles.transport_14b5ffe', ['', ...singBoxTransports])];
  if (type === 'grpc')
    return [
      ...fields,
      f('transport.service_name', 'profiles.service_name_122c35b'),
      f('transport.idle_timeout', 'profiles.idle_timeout_c1bf943'),
      f('transport.ping_timeout', 'profiles.ping_timeout_eff6b51'),
      b('transport.permit_without_stream', 'profiles.ping_without_stream_df5a96f'),
    ];
  if (httpTransports.includes(String(type))) {
    fields.push(
      f('transport.path', 'profiles.path_ad38caf'),
      json('transport.headers', 'profiles.headers_fa8f78f'),
    );
    if (type === 'http')
      fields.push(
        list('transport.host', 'profiles.hosts_c05f9d5'),
        f('transport.method', 'profiles.http_method_5a481dc'),
        f('transport.idle_timeout', 'profiles.idle_timeout_c1bf943'),
        f('transport.ping_timeout', 'profiles.ping_timeout_eff6b51'),
      );
    if (type === 'httpupgrade') fields.push(f('transport.host', 'profiles.host_218fdd0'));
    if (type === 'ws')
      fields.push(
        n('transport.max_early_data', 'profiles.maximum_early_data_1aeab32'),
        f('transport.early_data_header_name', 'profiles.early_data_header_bb721c2'),
      );
  }
  return fields;
}
