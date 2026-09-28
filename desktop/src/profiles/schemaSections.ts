import { get } from './schemaAccess.ts';
import {
  awgFields,
  customFragmentFields,
  dialFields,
  muxFields,
  quicFields,
  realmFields,
  tlsFields,
  transportFields,
} from './schemaCommon.ts';
import { b, f, n, select, type Config, type Definition, type Section } from './schemaFields.ts';
import { openconnectAdvanced, openvpnAdvanced, vpnTLS } from './schemaVpn.ts';
import { xrayMuxFields, xrayTLS, xrayTransport } from './schemaXray.ts';

// Editor tabs of one protocol definition for the current configuration.
export function sections(def: Definition, config: Config): Section[] {
  const result: Section[] = [{ id: 'main', label: 'profiles.general_012bafa', fields: [...def.main] }];
  if (def.id === 'xrayvless' && Array.isArray(get(config, 'settings.vnext'))) {
    result[0].fields = def.main.map((field) => ({
      ...field,
      path: ['settings.address', 'settings.port'].includes(field.path)
        ? field.path.replace('settings.', 'settings.vnext.0.')
        : field.path.replace('settings.', 'settings.vnext.0.users.0.'),
    }));
  }
  if (def.id.startsWith('custom') || def.id === 'chain' || def.id === 'extracore') return result;
  if (def.id === 'autoselector')
    return [
      ...result,
      {
        id: 'health',
        label: 'profiles.health_checks_d81930d',
        fields: [
          f('url', 'profiles.test_url_through_members_4ad6b8c'),
          f('connectivity_url', 'profiles.direct_connectivity_url_321a884'),
          f('interval', 'profiles.active_tier_interval_f27ba43'),
          f('bench_interval', 'profiles.reserve_tier_interval_036bb80'),
          f('watch_interval', 'profiles.selected_member_interval_4080eea'),
          f('timeout', 'profiles.probe_timeout_39e89ca'),
          n('concurrency', 'profiles.parallel_checks_d717ffd', 1, 64),
          n('active_size', 'profiles.active_tier_size_5cbbe02', 1, 500),
          n('sampling', 'profiles.samples_retained_ed4ae0d', 2, 60),
          n('expected', 'profiles.ready_members_67002f8', 1, 500),
          n('tolerance', 'profiles.switch_tolerance_ms_c50b20a', 0, 65535),
          f('max_rtt', 'profiles.maximum_rtt_4eb70cb'),
          n('dial_retries', 'profiles.connection_retries_f14c8ae', 0, 5),
          b('interrupt_exist_connections', 'profiles.interrupt_connections_on_switch_4a7c0c1'),
        ],
      },
      {
        id: 'balance',
        label: 'profiles.balancing_8140850',
        fields: [
          b('balance', 'profiles.enable_balancing_441c796'),
          select('balance_mode', 'profiles.balancing_mode_4395e7a', ['rotate', 'connection']),
          f('balance_interval', 'profiles.rotation_interval_74d3ab0'),
        ],
      },
    ];
  const xray = def.kind === 'xray-outbound';
  if (def.id === 'snell')
    result[0].fields.push(
      ...(get(config, 'version') === 6
        ? [select('mode', 'profiles.mode_aa431f5', ['default', 'unshaped', 'unsafe-raw'])]
        : [
            select('obfs_mode', 'profiles.obfuscation_a015f93', ['none', 'http', 'tls']),
            f('obfs_host', 'profiles.obfuscation_host_a2ec7b3'),
          ]),
    );
  if (def.id === 'hysteria2' && !get(config, 'obfs.type'))
    result[0].fields = result[0].fields.filter((f) => f.path !== 'obfs.password');
  if (def.id === 'hysteria2' && get(config, 'obfs.type') === 'gecko')
    result[0].fields.push(
      n('obfs.min_packet_size', 'profiles.minimum_packet_size_14617ce'),
      n('obfs.max_packet_size', 'profiles.maximum_packet_size_ddca04f'),
    );
  if (def.transport)
    result.push({
      id: 'transport',
      label: 'profiles.transport_14b5ffe',
      fields: xray ? xrayTransport(config) : transportFields(config),
    });
  if (def.tls)
    result.push({
      id: 'tls',
      label: 'profiles.tls_reality_9e08f39',
      fields: xray
        ? xrayTLS(config)
        : ['openvpn', 'openconnect'].includes(def.id)
          ? vpnTLS(def.id === 'openconnect')
          : def.quic
            ? tlsFields
            : [...tlsFields, ...customFragmentFields],
    });
  if (['wireguard', 'amneziawg'].includes(def.id))
    result.push(
      { id: 'peers', label: 'profiles.peers_1ae7673', fields: [] },
      { id: 'amnezia', label: 'profiles.amneziawg_ff97f13', fields: awgFields },
    );
  if (def.id === 'hysteria2')
    result.push({ id: 'realm', label: 'profiles.realm_nat_dfe4459', fields: realmFields });
  if (def.mux)
    result.push({
      id: 'mux',
      label: 'profiles.multiplexing_332faa9',
      fields: xray ? xrayMuxFields : muxFields,
    });
  if (['openvpn', 'openconnect'].includes(def.id))
    result.push({
      id: 'vpn',
      label: 'profiles.vpn_settings_887c817',
      fields: def.id === 'openvpn' ? openvpnAdvanced : openconnectAdvanced,
    });
  if (def.quic) result.push({ id: 'quic', label: 'profiles.quic_80622dc', fields: quicFields });
  if (!xray && def.id !== 'tailscale')
    result.push({ id: 'advanced', label: 'profiles.advanced_cb38134', fields: dialFields });
  return result;
}
