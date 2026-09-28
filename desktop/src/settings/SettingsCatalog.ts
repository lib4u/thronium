import { languages, translate, isMessageKey, type MessageKey } from '../shared/i18n/index.ts';
import type * as Wire from '../shared/api/generated/commands';
import catalog from '../../contracts/settings.catalog.json';
import { appliesHere, platform, type Platform } from '../shared/platform.ts';
export type Values = Wire.SettingsValues;

export type Conflict = { section: string; previous: Values; values: Values; fields: string[] };

export type Field = {
  id: string;
  section: string;
  label: MessageKey;
  default: unknown;
  kind: string;
  group: string;
  min?: number;
  max?: number;
  options?: string[];
  preference?: string;
  hint?: MessageKey;
  dependsOn?: string;
  dependsValue?: unknown;
  disabledWhen?: { field: string; values: unknown[] };
  subgroup?: string;
  platforms?: string[];
  /** What differs on one system: its default, the choices it offers and how it is described. */
  byPlatform?: Partial<Record<Platform, Pick<Field, 'options' | 'label' | 'hint' | 'default'>>>;
};

/** Settings shown on this system, as this system describes them; values of the others stay stored untouched. */
export const fields = (catalog as Field[])
  .filter((f) => appliesHere(f.platforms))
  .map((f) => ({ ...f, ...f.byPlatform?.[platform] }));
/** Sections a running connection uses directly; they are read-only until it stops. */
export const runtimeSections = ['inbound', 'tun'];
/** Interface font size the design is drawn at; the catalog default. Other sizes scale from it. */
export const BASE_FONT_SIZE = Number(fields.find((f) => f.id === 'font_size')?.default ?? 12);
/** Font size choices offered besides the current value. */
export const FONT_SIZE_PRESETS = [10, 12, 15, 18, 21, 24];

export const messageSearch = (key?: string) =>
  key && isMessageKey(key) ? languages.map(({ code }) => translate(code, key)).join(' ') : key || '';

export const sections = [
  [
    'appearance',
    'palette',
    'settings.interface_0196774',
    'settings.appearance_interface_scale_and_server_list_e3b44d0',
  ],
  [
    'inbound',
    'laptop',
    'settings.local_and_system_proxy_f2447c8',
    'settings.socks_http_system_proxy_and_authentication_dd4cefe',
  ],
  [
    'tun',
    'shield-check',
    'settings.tun_bc726db',
    'settings.virtual_interface_excluded_networks_and_recovery_e12e024',
  ],
  ['dns', 'globe', 'settings.dns_212189c', 'settings.servers_resolution_hosts_fakeip_and_cache_b504d94'],
  [
    'intercept',
    'route',
    'settings.interception_and_warp_4737028',
    'settings.traffic_interception_and_additional_routes_d887c52',
  ],
  [
    'network',
    'globe',
    'settings.application_network_e6dc080',
    'settings.network_access_for_downloads_and_updates_137158d',
  ],
  [
    'subscriptions',
    'link',
    'settings.subscriptions_dd3688b',
    'settings.updates_user_agent_and_subscription_defaults_96819ec',
  ],
  ['testing', 'activity', 'settings.tests_876deaa', 'settings.http_s_tcp_icmp_timeouts_and_speed_0291884'],
  [
    'logging',
    'file',
    'settings.logs_and_statistics_9bfd9e3',
    'settings.core_verbosity_filters_and_traffic_collection_1612edf',
  ],
  ['core', 'server', 'settings.cores_and_api_c6b785f', 'settings.default_core_api_dashboard_and_ntp_131972f'],
  [
    'presets',
    'sliders',
    'settings.connection_presets_1676aab',
    'settings.inherited_mux_tls_http_2_and_quic_parameters_c02b875',
  ],
  [
    'system',
    'command',
    'settings.system_and_shortcuts_045878b',
    'settings.window_tray_startup_and_keyboard_shortcuts_c5bc577',
  ],
  ['security', 'lock', 'settings.security_73d081a', 'settings.certificates_and_trust_stores_3e9599c'],
  [
    'backup',
    'hard-drive',
    'settings.backup_f007fa6',
    'settings.save_and_restore_profiles_and_application_settin_3b9fb3b',
  ],
  [
    'otp',
    'lock',
    'settings.authenticator_e3dd902',
    'settings.totp_and_hotp_entries_codes_and_import_efadc26',
  ],
] as const;

const legacyIds: Record<string, string> = {
  language: 'settings-language',
  theme: 'settings-theme',
  connection_mode: 'connection-mode',
  inbound_socks_port: 'proxy-port',
  vless_core: 'vless-core',
  test_url: 'probe-url',
  url_test_timeout_ms: 'probe-timeout',
  vpn_mtu: 'tun-mtu',
  vpn_implementation: 'tun-stack',
  vpn_ipv6: 'tun-ipv6',
  vpn_strict_route: 'tun-strict',
  tun_dns_hijack: 'tun-dns',
  tun_request_permission: 'tun-permission',
  tun_auto_reconnect: 'tun-reconnect',
  vpn_private_ranges: 'tun-excludes',
  close_behavior: 'close-behavior',
};

export const inputId = (f: Field) => legacyIds[f.id] || `setting-${f.id}`;

// Where a section or group has a preferred order; values the catalog adds later
// follow in catalog order, so a new group or subgroup always shows.
const groupOrder: Record<string, readonly string[]> = {
  core: ['main', 'clash', 'api', 'singbox', 'xray', 'ntp', 'geodata', 'advanced'],
  appearance: ['main', 'server-list', 'advanced'],
};
const subgroupOrder: Record<string, readonly string[]> = {
  singbox: ['singbox-tcp', 'singbox-cache', 'singbox-mux'],
  xray: ['main', 'mux', 'xray-tcp', 'xray-policy', 'xray-api', 'geodata'],
};
const ordered = (preferred: readonly string[] = [], present: string[]) => {
  const unique = [...new Set(present)];
  const first = preferred.filter((value) => unique.includes(value));
  return [...first, ...unique.filter((value) => !first.includes(value))];
};
/** The groups of a section, in display order. */
export const sectionGroups = (section: string) =>
  ordered(
    groupOrder[section],
    fields.filter((f) => f.section === section).map((f) => f.group),
  );
/** The subgroups of a group, in display order. */
export const subgroups = (group: string) =>
  ordered(
    subgroupOrder[group],
    fields.filter((f) => f.group === group && f.subgroup).map((f) => f.subgroup!),
  );

export const groups: Record<string, MessageKey> = {
  singbox: 'settings.sing_box_0a9fa03',
  'singbox-tcp': 'settings.tcp_and_udp_0c48ee0',
  'singbox-cache': 'settings.persistent_cache_18bdc15',
  'singbox-mux': 'settings.additional_mux_limits_f581a88',
  xray: 'settings.xray_febe2d0',
  'xray-tcp': 'settings.tcp_connections_ff9d33d',
  'xray-policy': 'settings.connection_limits_73fd917',
  'xray-api': 'settings.xray_statistics_api_bbbeba0',
  ping: 'settings.ping_3bae600',
  'server-list': 'settings.server_list_9476f13',
  accessibility: 'settings.accessibility_4b6ad1b',
  tray: 'settings.tray_icons_0b8729d',
  confirmations: 'settings.confirmations_e2499a4',
  main: 'settings.general_012bafa',
  advanced: 'settings.additional_parameters_fdb5ee0',
  authentication: 'settings.proxy_authentication_1872b2c',
  filters: 'settings.include_exclude_filters_76e34bf',
  statistics: 'settings.statistics_62a2b8c',
  clash: 'settings.clash_api_6332968',
  api: 'settings.sing_box_api_4741ee9',
  ntp: 'settings.time_synchronization_f7457d0',
  mux: 'settings.multiplexing_332faa9',
  tls: 'settings.tls_49fa570',
  http2: 'settings.http_2_ae20775',
  quic: 'settings.quic_80622dc',
  speed: 'settings.speed_test_8e386fe',
  periodic: 'settings.periodic_checks',
  file: 'settings.log_file_4a0d313',
  hwid: 'settings.device_identification_813a521',
  geodata: 'settings.geodata_and_rule_sets_9d77018',
  updates: 'settings.application_updates_588cc39',
  hotkeys: 'settings.global_shortcuts_0d2c337',
  'dns-server': 'settings.local_dns_server_5f23db9',
  redirect: 'settings.redirect_inbound_2f41553',
  warp: 'settings.warp_792cca3',
  blocking: 'settings.blocking_3c60f20',
};

export const options: Record<string, MessageKey> = {
  latency: 'settings.periodic_kind_latency',
  reconcile: 'settings.subscription_reconcile',
  recreate: 'settings.subscription_recreate',
  resolvconf: 'settings.resolvconf_openresolv_46c644d',
  resolved: 'settings.systemd_resolved_99a7f7a',
  interface: 'settings.system_dns_interface',
  default: 'settings.system_default_1cae5df',
  enabled: 'settings.enabled_dde9969',
  disabled: 'settings.disabled_202f2f6',
  quarter: 'settings.mask_a_quarter_20bdd54',
  half: 'settings.mask_half_4de4af6',
  reject: 'settings.reject_d9709ea',
  allow: 'settings.allow_through_mux_20f0ee1',
  skip: 'settings.use_protocol_transport_37ff396',
  http: 'settings.http_s_through_profile_91616a6',
  tcp: 'settings.tcp_server_port_44f8dec',
  icmp: 'settings.icmp_server_response_935cc26',
  full: 'settings.download_upload_ea2f646',
  download: 'settings.download_a2cab08',
  upload: 'settings.upload_8a5fd65',
  simple: 'settings.download_file_1dc677a',
  created: 'settings.created_time_7819229',
  destination: 'settings.destination_0c1a89b',
  process: 'settings.process_817a3ed',
  light: 'settings.light_171d8a5',
  dark: 'settings.dark_cf975e3',
  system: 'settings.follow_system_theme_bc0792d',
  local: 'settings.local_proxy_99d500a',
  'system-proxy': 'settings.system_proxy_1c515b5',
  tun: 'settings.tun_bc726db',
  quit: 'settings.quit_application_66c2dc8',
  background: 'settings.keep_in_tray_d9f07ec',
  'built-in': 'settings.built_in_c6c9e54',
  custom: 'settings.custom_95418de',
  direct: 'settings.direct_cc7ab89',
  proxy: 'settings.selected_server_1797ac9',
};

export const encode = (field: Field, value: unknown) =>
  field.kind === 'json'
    ? JSON.stringify(value, null, 2)
    : field.kind === 'list'
      ? (value as string[]).join('\n')
      : field.kind === 'number'
        ? String(value)
        : value;

export const decode = (field: Field, value: unknown) =>
  field.kind === 'json'
    ? JSON.parse(String(value))
    : field.kind === 'list'
      ? String(value)
          .split('\n')
          .map((v) => v.trim())
          .filter(Boolean)
      : field.kind === 'number'
        ? /^-?\d+$/.test(String(value))
          ? Number(value)
          : NaN
        : value;
