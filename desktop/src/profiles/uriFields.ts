// URI parameters of a sing-box outbound, one table per section. Import reads
// them by kind and export writes them in table order, so a key added here is
// understood in both directions.
export type UriKind = 'string' | 'boolean' | 'number' | 'list';
export type UriField = readonly [path: string, key: string, kind: UriKind];

/** `tls` object fields besides the server name, insecure flag, uTLS, Reality and tricks. */
export const tlsFields: readonly UriField[] = [
  ['disable_sni', 'disable_sni', 'boolean'],
  ['fragment', 'tls_fragment', 'boolean'],
  ['record_fragment', 'tls_record_fragment', 'boolean'],
  ['min_version', 'tls_min_version', 'string'],
  ['max_version', 'tls_max_version', 'string'],
  ['certificate_path', 'tls_certificate_path', 'string'],
  ['client_certificate_path', 'tls_client_certificate_path', 'string'],
  ['client_key_path', 'tls_client_key_path', 'string'],
  ['fragment_fallback_delay', 'tls_fragment_fallback_delay', 'string'],
  ['spoof_enabled', 'tls_spoof_enabled', 'boolean'],
  ['spoof', 'tls_spoof', 'string'],
  ['spoof_method', 'tls_spoof_method', 'string'],
  ['alpn', 'alpn', 'list'],
  ['cipher_suites', 'tls_cipher_suites', 'list'],
  ['curve_preferences', 'tls_curve_preferences', 'list'],
  ['certificate', 'tls_certificate', 'list'],
  ['certificate_public_key_sha256', 'tls_certificate_public_key_sha256', 'list'],
  ['client_certificate', 'tls_client_certificate', 'list'],
  ['client_key', 'tls_client_key', 'list'],
];
/** `tls.ech`. */
export const echFields: readonly UriField[] = [
  ['enabled', 'ech_enabled', 'boolean'],
  ['config_path', 'ech_config_path', 'string'],
  ['query_server_name', 'ech_server_name', 'string'],
  ['config', 'ech_config', 'list'],
];
/** `transport` fields besides its type, host and headers. */
export const transportFields: readonly UriField[] = [
  ['path', 'path', 'string'],
  ['method', 'method', 'string'],
  ['service_name', 'serviceName', 'string'],
  ['idle_timeout', 'idle_timeout', 'string'],
  ['ping_timeout', 'ping_timeout', 'string'],
  ['max_early_data', 'max_early_data', 'number'],
  ['early_data_header_name', 'early_data_header_name', 'string'],
];
/** Dial fields of the outbound itself. */
export const dialFields: readonly UriField[] = [
  ['reuse_addr', 'reuse_addr', 'boolean'],
  ['tcp_fast_open', 'tcp_fast_open', 'boolean'],
  ['tcp_multi_path', 'tcp_multi_path', 'boolean'],
  ['udp_fragment', 'udp_fragment', 'boolean'],
  ['connect_timeout', 'connect_timeout', 'string'],
  ['bind_interface', 'bind_interface', 'string'],
  ['inet4_bind_address', 'inet4_bind_address', 'string'],
  ['inet6_bind_address', 'inet6_bind_address', 'string'],
];
/** `multiplex`. */
export const multiplexFields: readonly UriField[] = [
  ['enabled', 'mux', 'boolean'],
  ['protocol', 'mux_protocol', 'string'],
  ['padding', 'mux_padding', 'boolean'],
  ['max_connections', 'mux_max_connections', 'number'],
  ['min_streams', 'mux_min_streams', 'number'],
  ['max_streams', 'mux_max_streams', 'number'],
  ['brutal.enabled', 'brutal_enabled', 'boolean'],
  ['brutal.up_mbps', 'brutal_up_mbps', 'number'],
  ['brutal.down_mbps', 'brutal_down_mbps', 'number'],
];
/** QUIC options of the outbound itself. */
export const quicFields: readonly UriField[] = [
  ['idle_timeout', 'quic_idle_timeout', 'string'],
  ['keep_alive_period', 'quic_keep_alive_period', 'string'],
  ['stream_receive_window', 'quic_stream_receive_window', 'number'],
  ['connection_receive_window', 'quic_connection_receive_window', 'number'],
  ['max_concurrent_streams', 'quic_max_concurrent_streams', 'number'],
  ['initial_packet_size', 'quic_initial_packet_size', 'number'],
  ['disable_path_mtu_discovery', 'quic_disable_path_mtu_discovery', 'boolean'],
];
