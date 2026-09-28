import { get } from './schemaAccess.ts';
import { udpNatFields } from './schemaVpn.ts';
import {
  address,
  b,
  bandwidth,
  congestion,
  credentials,
  f,
  json,
  list,
  n,
  packetEncoding,
  password,
  port,
  secret,
  select,
  serverPorts,
  uot,
  uuid,
  type Definition,
  type Field,
  type Label,
} from './schemaFields.ts';
import type { Draft } from '../api';
import { defaults } from '../shared/api/generated/defaults.ts';

// Protocol definitions of the profile editor. Field sets live in schemaCommon,
// schemaVpn and schemaXray; tabs in schemaSections; value access in schemaAccess.
// JSON paths are the wire configuration's keys, not the Qt form's widget IDs.
// Sources: Throne src/configs/{outbounds,common} and the pinned sing-box option/*.go.
export * from './schemaFields.ts';
export * from './schemaAccess.ts';
export { sections } from './schemaSections.ts';
export { awgFields, peerFields } from './schemaCommon.ts';

const make = (id: string, title: Label, main: Field[], extra: Partial<Definition> = {}): Definition => ({
  id,
  label: title,
  kind: 'sing-box-outbound',
  seed: { type: id, server: '', server_port: 443 },
  main: [address, port, ...main],
  ...extra,
});

export const definitions: Definition[] = [
  make(
    'vless',
    'profiles.vless_1e1f851',
    [uuid, select('flow', 'profiles.flow_5c9c5bf', ['', 'xtls-rprx-vision']), packetEncoding],
    {
      transport: true,
      tls: true,
      mux: true,
    },
  ),
  {
    id: 'xrayvless',
    label: 'profiles.vless_xray_a68914b',
    kind: 'xray-outbound',
    seed: {
      protocol: 'vless',
      settings: { address: '', port: 443, id: '', encryption: 'none' },
      streamSettings: { network: 'raw', security: 'none' },
    },
    main: [
      f('settings.address', 'profiles.server_address_57ff2f5'),
      n('settings.port', 'profiles.port_651531e', 1, 65535),
      secret('settings.id', 'profiles.uuid_624b8e1'),
      f('settings.encryption', 'profiles.encryption_7352e72'),
      select('settings.flow', 'profiles.flow_5c9c5bf', ['', 'xtls-rprx-vision']),
    ],
    transport: true,
    tls: true,
    mux: true,
  },
  make(
    'vmess',
    'profiles.vmess_99bda5a',
    [
      uuid,
      select('security', 'profiles.cipher_494ca3d', [
        'auto',
        'none',
        'zero',
        'aes-128-gcm',
        'chacha20-poly1305',
      ]),
      n('alter_id', 'profiles.alter_id_7449fcf'),
      packetEncoding,
      b('global_padding', 'profiles.global_padding_e661a16'),
      b('authenticated_length', 'profiles.authenticated_length_95fd7f0'),
    ],
    { transport: true, tls: true, mux: true },
  ),
  make('trojan', 'profiles.trojan_ca482b1', [password], {
    seed: { type: 'trojan', server: '', server_port: 443, tls: { enabled: true } },
    transport: true,
    tls: true,
    mux: true,
  }),
  make(
    'shadowsocks',
    'profiles.shadowsocks_38d6939',
    [
      select('method', 'profiles.cipher_494ca3d', [
        '2022-blake3-aes-128-gcm',
        '2022-blake3-aes-256-gcm',
        '2022-blake3-chacha20-poly1305',
        'none',
        'aes-128-gcm',
        'aes-192-gcm',
        'aes-256-gcm',
        'chacha20-ietf-poly1305',
        'xchacha20-ietf-poly1305',
        'aes-128-ctr',
        'aes-192-ctr',
        'aes-256-ctr',
        'aes-128-cfb',
        'aes-192-cfb',
        'aes-256-cfb',
        'rc4-md5',
        'chacha20-ietf',
        'xchacha20',
      ]),
      password,
      f('plugin', 'profiles.plugin_5c3da89'),
      f('plugin_opts', 'profiles.plugin_options_f4450f7'),
      uot,
    ],
    { mux: true },
  ),
  make(
    'socks',
    'profiles.socks_5fc66c8',
    [select('version', 'profiles.version_0b69619', ['4', '4a', '5']), ...credentials, uot],
    {
      seed: { type: 'socks', server: '', server_port: 1080, version: '5' },
    },
  ),
  make(
    'http',
    'profiles.http_968d938',
    [...credentials, f('path', 'profiles.path_ad38caf'), json('headers', 'profiles.headers_fa8f78f')],
    {
      tls: true,
    },
  ),
  make(
    'hysteria',
    'profiles.hysteria_c1e81a5',
    [
      secret('auth_str', 'profiles.authentication_string_866f56c'),
      secret('auth', 'profiles.authentication_base64_0f2ad23'),
      secret('obfs', 'profiles.obfuscation_password_9660418'),
      serverPorts,
      f('hop_interval', 'profiles.hop_interval_9a6be51'),
      ...bandwidth,
      n('recv_window_conn', 'profiles.receive_window_per_connection'),
      n('recv_window', 'profiles.receive_window'),
      b('disable_mtu_discovery', 'profiles.disable_mtu_discovery'),
    ],
    {
      seed: { type: 'hysteria', server: '', server_port: 443, tls: { enabled: true } },
      tls: true,
      quic: true,
    },
  ),
  make(
    'hysteria2',
    'profiles.hysteria_2_1f9eec4',
    [
      password,
      select('obfs.type', 'profiles.obfuscation_a015f93', ['', 'salamander', 'gecko']),
      secret('obfs.password', 'profiles.obfuscation_password_9660418'),
      serverPorts,
      f('hop_interval', 'profiles.minimum_hop_interval_042c5c2'),
      f('hop_interval_max', 'profiles.maximum_hop_interval_52685fa'),
      ...bandwidth,
      select('bbr_profile', 'profiles.bbr_profile_593aff4', ['standard', 'conservative', 'aggressive']),
      b('disable_chrome_parrot', 'profiles.disable_chrome_parrot_a827bf7'),
    ],
    {
      seed: { type: 'hysteria2', server: '', server_port: 443, tls: { enabled: true } },
      tls: true,
      quic: true,
    },
  ),
  make(
    'tuic',
    'profiles.tuic_a4276c6',
    [
      uuid,
      password,
      congestion,
      select('udp_relay_mode', 'profiles.udp_relay_mode_e5f12f9', ['native', 'quic']),
      b('udp_over_stream', 'profiles.udp_over_stream_b7bf411'),
      b('zero_rtt_handshake', 'profiles.0_rtt_handshake_3e7f86c'),
      f('heartbeat', 'profiles.heartbeat_interval_e755417'),
    ],
    { seed: { type: 'tuic', server: '', server_port: 443, tls: { enabled: true } }, tls: true, quic: true },
  ),
  make(
    'anytls',
    'profiles.anytls_b60eb15',
    [
      password,
      f('idle_session_check_interval', 'profiles.idle_session_check_interval_08410c5'),
      f('idle_session_timeout', 'profiles.idle_session_timeout_d95cd73'),
      n('min_idle_session', 'profiles.minimum_idle_sessions_7e15485'),
    ],
    { seed: { type: 'anytls', server: '', server_port: 443, tls: { enabled: true } }, tls: true },
  ),
  make(
    'trusttunnel',
    'profiles.trusttunnel_56ae95f',
    [
      ...credentials,
      b('health_check', 'profiles.health_check_2c0a812'),
      b('quic', 'profiles.quic_80622dc'),
      select('quic_congestion_control', 'profiles.quic_congestion_control_9a34e60', ['bbr', 'cubic', 'reno']),
    ],
    { seed: { type: 'trusttunnel', server: '', server_port: 443, tls: { enabled: true } }, tls: true },
  ),
  ...['wireguard', 'amneziawg'].map((id) =>
    make(id, id === 'wireguard' ? 'profiles.wireguard_c200a0e' : 'profiles.amneziawg_ff97f13', [], {
      seed: {
        type: 'wireguard',
        address: [],
        private_key: '',
        peers: [],
        ...(id === 'amneziawg' ? { amnezia_wg: {} } : {}),
      },
      main: [
        list('address', 'profiles.tunnel_addresses_cidr_82cd48a'),
        secret('private_key', 'profiles.private_key_0b13591'),
        n('mtu', 'profiles.mtu_aeb4832', 1, 65535),
        n('listen_port', 'profiles.listen_port_c3b99d5', 0, 65535),
        b('system', 'profiles.system_interface_b778c71'),
        f('name', 'profiles.interface_name_d39d347'),
        n('workers', 'profiles.workers_4d390a2'),
        f('udp_timeout', 'profiles.udp_timeout_846623f'),
        ...udpNatFields,
      ],
    }),
  ),
  make(
    'mieru',
    'profiles.mieru_9ac4377',
    [
      ...credentials,
      select('transport', 'profiles.transport_14b5ffe', ['TCP', 'UDP']),
      serverPorts,
      select('multiplexing', 'profiles.multiplexing_332faa9', [
        'MULTIPLEXING_DEFAULT',
        'MULTIPLEXING_OFF',
        'MULTIPLEXING_LOW',
        'MULTIPLEXING_MIDDLE',
        'MULTIPLEXING_HIGH',
      ]),
      f('traffic_pattern', 'profiles.traffic_pattern_4f0b4f9'),
    ],
    { seed: { type: 'mieru', server: '', server_port: 443, transport: 'TCP' } },
  ),
  make(
    'snell',
    'profiles.snell_32de31c',
    [
      select('version', 'profiles.version_0b69619', [4, 6]),
      secret('psk', 'profiles.pre_shared_key_e4a74cd'),
      secret('userkey', 'profiles.user_key_284ab88'),
      b('reuse', 'profiles.connection_reuse_addecab'),
      select('network', 'profiles.network_d897ccc', ['', 'tcp', 'udp']),
    ],
    { seed: { type: 'snell', server: '', server_port: 443, version: 4 } },
  ),
  make(
    'naive',
    'profiles.naive_59360d1',
    [
      ...credentials,
      uot,
      b('quic', 'profiles.quic_80622dc'),
      select('quic_congestion_control', 'profiles.quic_congestion_control_9a34e60', [
        'bbr',
        'bbr2',
        'cubic',
        'reno',
      ]),
    ],
    { seed: { type: 'naive', server: '', server_port: 443, tls: { enabled: true } }, tls: true },
  ),
  make('juicity', 'profiles.juicity_eda34dd', [uuid, password], {
    seed: { type: 'juicity', server: '', server_port: 443, tls: { enabled: true } },
    tls: true,
  }),
  make(
    'shadowtls',
    'profiles.shadowtls_06ebf6b',
    [select('version', 'profiles.version_0b69619', [1, 2, 3]), password],
    {
      seed: { type: 'shadowtls', server: '', server_port: 443, version: 3, tls: { enabled: true } },
      tls: true,
    },
  ),
  make(
    'ssh',
    'profiles.ssh_16f2435',
    [
      f('user', 'profiles.user_db0bfe9'),
      password,
      list('private_key', 'profiles.private_key_pem_6a2158b'),
      f('private_key_path', 'profiles.private_key_file_053054c'),
      secret('private_key_passphrase', 'profiles.key_passphrase_379232f'),
      list('host_key', 'profiles.host_keys_980b45b'),
      list('host_key_algorithms', 'profiles.host_key_algorithms_0c7f7aa'),
      f('client_version', 'profiles.client_version_3ec77ea'),
    ],
    { seed: { type: 'ssh', server: '', server_port: 22 } },
  ),
  make(
    'openvpn',
    'profiles.openvpn_d417481',
    [
      ...credentials,
      select('mode', 'profiles.mode_aa431f5', ['tls', 'static_key']),
      select('network', 'profiles.network_d897ccc', ['udp', 'udp4', 'udp6', 'tcp', 'tcp4', 'tcp6']),
      select('auth_retry', 'profiles.authentication_retry_f791cf5', ['none', 'nointeract', 'interact']),
      f('static_challenge', 'profiles.static_challenge_66ef2a8'),
      b('static_challenge_echo', 'profiles.show_challenge_answer_418b9b0'),
    ],
    {
      seed: {
        type: 'openvpn-client',
        server: '',
        server_port: 1194,
        mode: 'tls',
        network: 'udp',
        tls: { remote_certificate_tls: 'server' },
      },
      tls: true,
    },
  ),
  make('openconnect', 'profiles.openconnect_f928185', [], {
    seed: { type: 'openconnect', server: '', flavor: 'anyconnect' },
    main: [
      f('server', 'profiles.server_url_c8464b4'),
      select('flavor', 'profiles.vpn_protocol_ddbcb9a', [
        'anyconnect',
        'gp',
        'fortinet',
        'f5',
        'pulse',
        'nc',
      ]),
      ...credentials,
      f('auth_group', 'profiles.authentication_group_b1595c6'),
      secret('cookie', 'profiles.cookie_7821cc9'),
    ],
    tls: true,
  }),
  make('tailscale', 'profiles.tailscale_7e7efa0', [], {
    seed: { type: 'tailscale' },
    main: [
      secret('auth_key', 'profiles.authentication_key_05d77cd'),
      f('hostname', 'profiles.hostname_1b5e544'),
      f('control_url', 'profiles.control_server_url_35bd192'),
      f('state_directory', 'profiles.state_directory_32081b5'),
      b('ephemeral', 'profiles.ephemeral_device_2075117'),
      b('accept_routes', 'profiles.accept_routes_b8e1c2e'),
      f('exit_node', 'profiles.exit_node_5e8d87d'),
      b('exit_node_allow_lan_access', 'profiles.allow_lan_with_exit_node_77d1118'),
      list('advertise_routes', 'profiles.advertised_routes_ced801b'),
      b('advertise_exit_node', 'profiles.advertise_exit_node_baef664'),
    ],
  }),
  make('direct', 'profiles.direct_b171b89', [], {
    label: 'profiles.direct_cc7ab89',
    seed: { type: 'direct' },
    main: [],
  }),
  {
    id: 'extracore',
    kind: 'external-core',
    label: 'profiles.external_core_b50818f',
    seed: {
      type: 'extracore',
      socks_address: '127.0.0.1',
      socks_port: 1080,
      extra_core_path: '',
      extra_core_args: '',
      extra_core_conf: '',
      no_logs: true,
    },
    main: [],
  },
  {
    id: 'chain',
    kind: 'chain',
    label: 'profiles.proxy_chain_cd43b63',
    seed: { type: 'chain', hops: [''] },
    main: [],
  },
  {
    id: 'autoselector',
    kind: 'auto-selector',
    label: 'profiles.automatic_selection_6b40a66',
    seed: defaults.poolProfile,
    main: [],
  },
  ...(
    [
      ['custom', 'sing-box-outbound', 'profiles.custom_outbound_sing_box_4b6b974'],
      ['customfull', 'sing-box-config', 'profiles.complete_configuration_sing_box_03f2ba4'],
      ['customxray', 'xray-outbound', 'profiles.custom_outbound_xray_972bb44'],
      ['customxrayfull', 'xray-config', 'profiles.complete_configuration_xray_5f35e86'],
    ] as const
  ).map(([id, kind, message]): Definition => ({ id, kind, label: message, seed: {}, main: [] })),
];

export function identify(draft?: Pick<Draft, 'kind' | 'config'>): string {
  if (!draft) return 'vless';
  if (draft.kind === 'chain') return 'chain';
  if (draft.kind === 'auto-selector') return 'autoselector';
  if (draft.kind === 'external-core') return 'extracore';
  if (draft.kind === 'sing-box-config') return 'customfull';
  if (draft.kind === 'xray-config') return 'customxrayfull';
  if (draft.kind === 'xray-outbound') {
    const vnext = get(draft.config, 'settings.vnext');
    const users = get(draft.config, 'settings.vnext.0.users');
    const single = Array.isArray(vnext) && vnext.length === 1 && Array.isArray(users) && users.length === 1;
    return draft.config.protocol === 'vless' && (vnext === undefined || single) ? 'xrayvless' : 'customxray';
  }
  if (draft.config.type === 'wireguard') return draft.config.amnezia_wg ? 'amneziawg' : 'wireguard';
  if (draft.config.type === 'openvpn-client') return 'openvpn';
  return definitions.find((d) => d.id === draft.config.type && d.kind === draft.kind)?.id || 'custom';
}
