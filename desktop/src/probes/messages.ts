import {
  formatDateTime,
  formatSpeedPair,
  millisecondQuantity,
  quantityText,
  type Quantity,
} from '../shared/i18n/format.ts';
import { sourceLanguage, translate, type Language } from '../shared/i18n/index.ts';
import { errorCode } from '../shared/api/errors.ts';
import type { Measurement, ProbeBatch } from '../api';
const messages = {
  title: 'diagnostics.latency_test_43dd6e7',
  'connected-only': 'diagnostics.vpn_connected_no_http_response_eac115f',
  'auth-required': 'diagnostics.vpn_sign_in_required_3600a5c',
  connectedCount: 'diagnostics.vpn_without_http_response_6867293',
  authCount: 'diagnostics.sign_in_required_5da19c4',
  authShort: 'diagnostics.sign_in_1c7eaeb',
  probe_vpn_otp_binding_required: 'diagnostics.probe_vpn_otp_binding_required',
  probe_vpn_otp_manual_only: 'diagnostics.probe_vpn_otp_manual_only',
  probe_vpn_otp_failed: 'diagnostics.probe_vpn_otp_failed',
  probe_vpn_auth_unsupported: 'diagnostics.this_vpn_authentication_method_is_not_supported__d79e8cf',
  probe_vpn_context_unsupported: 'diagnostics.vpn_url_testing_is_available_for_an_individual_o_f1ccca9',
  probe_endpoint_context_unsupported: 'diagnostics.wireguard_endpoint_context_unsupported',
  probe_vpn_diagnostic_failed: 'diagnostics.the_vpn_is_connected_but_the_measurement_failed__499ac18',
  probe_vpn_connected_only: 'diagnostics.the_vpn_connected_but_the_website_did_not_respon_657cce1',
  probe_cleanup_failed: 'diagnostics.the_test_could_not_finish_stopping_another_test__67a8924',
  probe_vpn_auth_required: 'diagnostics.vpn_authentication_is_required_check_the_saved_c_bfc880c',
  autoHint: 'diagnostics.auto_http_s_tcp_icmp_stopping_at_the_first_succe_00d487a',
  probe_auto_failed: 'diagnostics.none_of_the_methods_received_a_successful_respon_164cfc9',
  probe_auto_unsupported: 'diagnostics.no_test_method_is_available_for_this_profile_75c89f3',
  firstHop: 'diagnostics.first_server_in_chain_98515b1',
  httpHint: 'diagnostics.http_method_hint',
  tcpHint: 'diagnostics.tcp_direct_connection_to_the_server_port_without_bb6ae8b',
  icmpHint: 'diagnostics.icmp_direct_echo_request_to_the_server_a_working_2d0a79a',
  settings: 'diagnostics.ping_3bae600',
  settingsHint: 'diagnostics.the_test_buttons_in_the_library_use_these_settin_77e8d1f',
  method: 'diagnostics.test_method_e5d1fef',
  nextRun: 'diagnostics.changes_apply_to_the_next_test_run_2728429',
  save: 'diagnostics.save_9cd85bd',
  saved: 'diagnostics.ping_settings_saved_40b1f5c',
  saveFailed: 'diagnostics.could_not_save_ping_settings_5fa43ef',
  openSettings: 'diagnostics.ping_settings_cbefb1d',
  running: 'diagnostics.testing_latency_2583a07',
  periodic: 'diagnostics.journal_source_periodic',
  finished: 'diagnostics.testing_finished_fb4deb9',
  failedCount: 'diagnostics.failed_e8221ef',
  probe_invalid_timeout: 'diagnostics.timeout_range',
  hint: 'diagnostics.tests_an_http_s_response_through_each_profile_se_9db6b20',
  limits: 'diagnostics.individual_openvpn_and_openconnect_profiles_with_3a88b28',
  lifetime: 'diagnostics.results_last_until_the_app_exits_and_are_invalid_39d538b',
  url: 'diagnostics.test_url_d88be96',
  timeout: 'diagnostics.request_timeout_ms_a04072f',
  start: 'diagnostics.test_7807b5e',
  visible: 'diagnostics.test_this_list_8904774',
  cancel: 'diagnostics.stop_testing_d221e2a',
  close: 'diagnostics.close_c9a286c',
  clear: 'diagnostics.clear_results_7cdb8ab',
  selected: 'diagnostics.selected_profiles_4d4379a',
  completed: 'diagnostics.completed_d053d8f',
  empty: 'diagnostics.no_tests_have_run_yet_d725699',
  queued: 'diagnostics.queued_8af393a',
  testing: 'diagnostics.testing_eb87f6f',
  ok: 'diagnostics.reachable_4209c06',
  error: 'diagnostics.failed_462dea0',
  cancelled: 'diagnostics.cancelled_2f9561b',
  stale: 'diagnostics.profile_changed_5cab20c',
  unsupported: 'diagnostics.not_supported_yet_fa3c72b',
  probe_busy: 'diagnostics.wait_for_the_current_test_or_stop_it_1155074',
  probe_invalid_options: 'diagnostics.selection_and_timeout_range',
  probe_invalid_url: 'diagnostics.enter_an_http_s_url_without_credentials_or_a_fra_d741f4c',
  probe_timeout: 'diagnostics.the_server_did_not_respond_within_the_timeout_2a0eabc',
  probe_dns_failed: 'diagnostics.could_not_resolve_the_server_address_20bf714',
  probe_connection_refused: 'diagnostics.the_server_refused_the_tcp_connection_to_this_po_10c69ac',
  probe_unreachable: 'diagnostics.the_server_is_unreachable_using_this_method_1c36079',
  probe_icmp_no_reply: 'diagnostics.no_icmp_reply_the_server_or_network_may_block_ec_b7f84cd',
  probe_icmp_unavailable: 'diagnostics.icmp_is_unavailable_on_this_system_or_blocked_by_0b0ff78',
  probe_direct_unavailable: 'diagnostics.could_not_use_a_direct_network_interface_for_the_aa71dc0',
  probe_tcp_inapplicable: 'diagnostics.tcp_is_not_applicable_this_profile_uses_udp_9644f25',
  probe_target_ambiguous: 'diagnostics.the_configuration_has_multiple_possible_servers__3e872cf',
  probe_target_missing: 'diagnostics.no_server_address_or_tcp_port_was_found_in_the_c_8bc6b4c',
  probe_tls_failed: 'diagnostics.tls_certificate_verification_failed_f8d9ac8',
  probe_core_failed: 'diagnostics.could_not_start_the_test_core_b7de8f1',
  probe_configuration_failed: 'diagnostics.the_core_could_not_start_the_test_configuration_98e6cef',
  probe_failed: 'diagnostics.could_not_complete_the_test_d9d4d57',
  probe_cancelled: 'diagnostics.testing_was_cancelled_6d5d739',
  probe_stale: 'diagnostics.the_configuration_changed_or_the_profile_was_del_df7e448',
  probe_full_config_unsupported: 'diagnostics.this_full_json_uses_background_services_special__fb16328',
  geodata_missing: 'diagnostics.download_geodata_in_xray_settings_first_4385632',
  geodata_invalid: 'diagnostics.the_geodata_cache_is_invalid_update_it_in_xray_s_0063fa1',
  geodata_too_large: 'diagnostics.geodata_exceeds_the_size_limit_7b4a17d',
  geodata_write_failed: 'diagnostics.could_not_prepare_a_private_geodata_copy_for_the_00f180d',
  geodata_external_file_unsupported: 'diagnostics.http_testing_uses_cached_geoip_geosite_categorie_d49772f',
  probe_unsupported: 'diagnostics.url_testing_has_not_been_migrated_for_this_profi_6a749fe',
} as const;
export const isProbeError = (key: string) =>
  key.startsWith('probe_') && Object.prototype.hasOwnProperty.call(messages, key);
export type { Language };
export const tr = (key: keyof typeof messages, language: Language) => translate(language, messages[key]);
export function message(
  error: unknown,
  language: Language,
  fallback: 'probe_failed' | 'saveFailed' = 'probe_failed',
) {
  const key = errorCode(error);
  return key in messages ? tr(key as keyof typeof messages, language) : tr(fallback, language);
}
export const active = (status: string) => status === 'queued' || status === 'testing';
export const methodName = (method: string, language: Language = sourceLanguage) =>
  method === 'auto'
    ? translate(language, 'diagnostics.auto_5a5e92f')
    : method === 'tcp'
      ? 'TCP'
      : method === 'icmp'
        ? 'ICMP'
        : 'HTTP(S)';
/** Whether a latency method requests the test URL (the others only open a TCP connection or ping). */
export const usesTestUrl = (method: string) => method === 'auto' || method === 'http';
export const methodHint = (method: string, language: Language) =>
  tr(
    method === 'auto'
      ? 'autoHint'
      : method === 'tcp'
        ? 'tcpHint'
        : method === 'icmp'
          ? 'icmpHint'
          : 'httpHint',
    language,
  );
// The engine names what a batch measured; the view only labels it.
export const kindName = (kind: ProbeBatch['kind'], language: Language) =>
  kind === 'ip'
    ? translate(language, 'settings.check_ip_and_country_c9490f9')
    : kind === 'speed'
      ? translate(language, 'settings.test_speed_38ae742')
      : tr('title', language);
// The auto-select sweep is the quick pool's own mechanism: the library's ping
// banner and group progress never show it, and rows never read it.
export const libraryBatch = (batch: ProbeBatch | null | undefined) =>
  batch && batch.source !== 'auto-select' ? batch : null;
// IP and speed batches are read from the batch itself; rows keep latency otherwise.
export const batchEntry = (batch: ProbeBatch | null | undefined, id: string) =>
  batch && batch.kind && batch.kind !== 'latency' ? batch.entries.find((e) => e.profileId === id) : undefined;
function pending(m: Measurement | null | undefined) {
  return m && active(m.status) ? '…' : m?.status === 'error' ? '×' : '—';
}
/** The latency value and, for automatic checks, the method that produced it. */
export function latencyParts(
  m: Measurement | null | undefined,
  language: Language,
): { quantity: Quantity; method?: string } {
  if (m?.status === 'connected-only') return { quantity: { value: 'VPN' } };
  if (m?.status === 'auth-required') return { quantity: { value: tr('authShort', language) } };
  if (m?.status !== 'ok' || m.latencyMs === null) return { quantity: { value: pending(m) } };
  return {
    quantity: millisecondQuantity(m.latencyMs === 0 ? '<1' : m.latencyMs, language),
    method: m.method === 'auto' ? methodName(m.effectiveMethod, language) : undefined,
  };
}
export function latency(m: Measurement | null | undefined, language: Language) {
  const { quantity, method } = latencyParts(m, language);
  const value = quantityText(quantity);
  return method ? `${value} · ${method}` : value;
}
export function result(m: Measurement | null | undefined, language: Language) {
  if (m?.status !== 'ok') return pending(m);
  if (m.kind === 'ip') return `${m.countryCode || '?'} · ${m.ip || '—'}`;
  if (m.kind === 'speed') return formatSpeedPair(m.download, m.upload, language);
  return latency(m, language);
}
/** How a pool's measured member was chosen, as a parenthesised suffix. */
export function memberOrigin(origin: Measurement['memberOrigin'] | undefined, language: Language) {
  return origin ? ` (${translate(language, `settings.member_origin_${origin}`)})` : '';
}
export function tooltip(m: Measurement | null | undefined, language: Language) {
  if (m && m.kind && m.kind !== 'latency')
    return (
      `${kindName(m.kind, language)} · ${tr(m.status, language)}${m.at ? ` · ${formatDateTime(new Date(m.at * 1000), language)}` : ''}${m.error ? `: ${message(m.error, language)}` : ''}${m.transport ? `\n${m.transport}` : ''}` +
      (m.memberName
        ? ` · ${translate(language, 'settings.measured_member')}: ${m.memberName}${memberOrigin(m.memberOrigin, language)}`
        : '')
    );
  return m
    ? `${tr('title', language)} · ${methodName(m.method, language)}${m.method === 'auto' ? ` → ${methodName(m.effectiveMethod, language)}` : ''} · ${tr(m.status, language)}${m.firstHop ? ` · ${tr('firstHop', language)}` : ''}${m.at ? ` · ${formatDateTime(new Date(m.at * 1000), language)}` : ''}${m.error ? `: ${message(m.error, language)}` : ''}\n${methodHint(m.effectiveMethod || m.method, language)}${m.method === 'auto' ? (m.attempts || []).map((a) => `\n${methodName(a.method, language)}: ${a.error ? message(a.error, language) : tr(a.status, language)}`).join('') : ''}`
    : tr('empty', language);
}
