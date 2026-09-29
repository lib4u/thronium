import { formatDateTime } from '../shared/i18n/format.ts';
import type { MessageKey, Language } from '../shared/i18n/index.ts';
import { plural, translate } from '../shared/i18n/index.ts';
import { errorCode } from '../shared/api/errors.ts';
import type { Group, SubscriptionJob, SubscriptionUsage } from '../api';
export const messageKeys = {
  subscription_invalid_name_rules: 'subscriptions.name_rules_invalid',
  subscription_invalid_renamed_name: 'subscriptions.renamed_name_invalid',
  subscription_filtered_empty: 'subscriptions.the_name_filters_excluded_every_server_the_group_e12871e',

  dragGroup: 'subscriptions.drag_to_reorder_groups_d5d8a76',
  collapse: 'subscriptions.collapse_group_52aea2e',
  expand: 'subscriptions.expand_group_17cad69',
  groupMenu: 'subscriptions.group_actions_f889218',
  groupProbe: 'subscriptions.test_this_group_a358042',
  manualSchedule: 'subscriptions.manual_updates_aac5051',
  announcement: 'subscriptions.announcement_547d880',
  more: 'subscriptions.show_more_e724fc1',
  less: 'subscriptions.show_less_5c1ab87',
  emptyGroup: 'subscriptions.no_connections_in_this_group_b8ac138',
  emptySubscription: 'subscriptions.no_servers_downloaded_yet_335d3a6',
  emptySubscriptionHint: 'subscriptions.the_subscription_address_is_saved_load_its_serve_2d54a6a',
  loadServers: 'subscriptions.load_servers_0181305',
  importingServers: 'subscriptions.importing_servers_eb660c1',
  continueImport: 'subscriptions.continue_import_9fc9f5b',
  updates: 'subscriptions.subscription_updates_99609fc',
  updateAll: 'subscriptions.update_all_subscriptions_61332a1',
  queueHint: 'subscriptions.updates_run_one_at_a_time_changed_configurations_ad930b9',
  cancelQueue: 'subscriptions.cancel_queue_c93e3df',
  pending: 'subscriptions.in_progress_4bda0db',
  finished: 'subscriptions.finished_7286114',
  clearHistory: 'subscriptions.clear_history_d389fa3',
  emptyQueue: 'subscriptions.no_updates_in_this_session_yet_ddd8bb1',
  queued: 'subscriptions.queued_8af393a',
  downloading: 'subscriptions.downloading_5408313',
  geodata: 'subscriptions.job_geodata',
  checking: 'subscriptions.job_configuration_check',
  checkingHint: 'subscriptions.job_configuration_check_hint',
  'needs-review': 'subscriptions.review_needed_41a616a',
  error: 'subscriptions.failed_462dea0',
  cancelled: 'subscriptions.cancelled_2f9561b',
  scheduled: 'subscriptions.scheduled_update_6a0a4dc',
  manualUpdate: 'subscriptions.manual_update_e8e75fe',
  reviewUpdate: 'subscriptions.review_subscription_775f30b',
  retained: 'subscriptions.kept_by_subscription_settings_aa377c7',
  protectedEntries: 'subscriptions.connected_profiles_or_removed_routing_targets_we_47be56a',
  autoUpdate: 'subscriptions.update_automatically_229b23c',
  interval: 'subscriptions.interval_minutes_07ecb15',
  scheduleHint: 'subscriptions.runs_while_thronium_is_open_overdue_updates_resu_44e7f5a',
  every: 'subscriptions.every_c0d8037',
  invalid_subscription_interval: 'subscriptions.interval_invalid',
  subscription_group_busy: 'subscriptions.this_group_is_being_updated_wait_or_cancel_the_u_11f4e4e',
  subscription_queue_full: 'subscriptions.queue_full',
  subscription_storage_error: 'subscriptions.could_not_save_the_update_state_check_the_data_d_0787a24',
  subscription_worker_interrupted: 'subscriptions.the_update_was_interrupted_by_a_reload_or_restar_3d226f4',
  subscription_untransferred_parameters:
    'subscriptions.some_parameters_cannot_be_transferred_review_and_ec40226',
  subscription_configuration_rejected:
    'subscriptions.the_core_rejected_a_changed_configuration_saved__288f630',
  subscription_update_failed: 'subscriptions.the_update_failed_saved_profiles_were_preserved_65db0ee',
  subscription_profiles_rejected: 'subscriptions.profiles_rejected',
  subscription_provider_routing_failed: 'subscriptions.provider_routing_failed',
  subscription_validation_required: 'subscriptions.changed_configurations_must_pass_validation_befo_4b22107',
  subscription_job_cancelled: 'subscriptions.this_update_was_cancelled_or_interrupted_884d18f',
  subscription_job_state: 'subscriptions.the_update_is_no_longer_ready_for_this_action_c2a4d13',
  groups: 'subscriptions.groups_6af1c99',
  local: 'subscriptions.local_group_a5ec848',
  subscription: 'subscriptions.subscription_aa89acd',
  add: 'subscriptions.new_group_fc193dc',
  edit: 'subscriptions.edit_0fd5c3c',
  save: 'subscriptions.save_group_0ee0c43',
  cancel: 'subscriptions.cancel_bf4c449',
  close: 'subscriptions.close_c9a286c',
  back: 'subscriptions.back_to_groups_cf420f9',
  name: 'subscriptions.name_5163a2e',
  url: 'subscriptions.subscription_url_dc7ed9c',
  reveal: 'subscriptions.show_url_a2d5dc6',
  advanced: 'subscriptions.download_settings_b0d1230',
  userAgent: 'subscriptions.user_agent_dfdca2e',
  headers: 'subscriptions.additional_http_headers_json_a198092',
  viaProxy: 'subscriptions.download_through_the_active_connection_105b051',
  sourceHint: 'subscriptions.source_hint',
  detach: 'subscriptions.turning_off_the_subscription_keeps_its_profiles__7e88cd7',
  up: 'subscriptions.move_up_ba006bb',
  down: 'subscriptions.move_down_6d8a2ea',
  remove: 'subscriptions.delete_group_74a2ef2',
  deleteHint: 'subscriptions.profiles_will_move_to_personal_and_keep_their_se_4143978',
  deleteProfiles: 'subscriptions.also_delete_the_profiles_in_this_group_635dc34',
  deleteWarning: 'subscriptions.connected_profiles_and_profiles_used_in_routing__5c809af',
  update: 'subscriptions.update_subscription_7db2023',
  load: 'subscriptions.load_subscription_4746ab0',
  reload: 'subscriptions.load_again_46a23f3',
  loading: 'subscriptions.loading_d08c833',
  reviewHint: 'subscriptions.review_the_changes_before_applying_manually_adde_a14ef2b',
  apply: 'subscriptions.apply_changes_dcb08c4',
  applying: 'subscriptions.applying_0869f18',
  added: 'subscriptions.added_7df4b8b',
  updated: 'subscriptions.updated_68715c1',
  unchanged: 'subscriptions.unchanged_163f4db',
  kept: 'subscriptions.kept_dc9c3aa',
  removed: 'subscriptions.removed_07b6cc6',
  skipped: 'subscriptions.skipped_5a000ad',
  warned: 'subscriptions.with_warnings_6bd13e4',
  running: 'subscriptions.currently_connected_update_after_disconnecting_54222fd',
  routing: 'subscriptions.used_in_routing_3ea910c',
  chain: 'subscriptions.used_in_a_chain_or_automatic_pool_9c9c809',
  never: 'subscriptions.not_updated_yet_437fbae',
  last: 'subscriptions.updated_5d0416f',
  usage: 'subscriptions.traffic_ecada28',
  subscriptionTraffic: 'subscriptions.subscription_traffic_0d4e141',
  unlimitedShort: 'subscriptions.unlimited_1641964',
  expires: 'subscriptions.expires_3ab8631',
  unlimited: 'subscriptions.no_traffic_limit_139a8ea',
  invalidResponse: 'subscriptions.the_response_contains_errors_no_changes_can_be_a_1f35646',
  empty: 'subscriptions.no_profiles_found_in_the_response_d2c5e27',
  checksPassed: 'subscriptions.all_configurations_passed_core_validation_190b0a7',
  invalid_subscription_url: 'subscriptions.use_an_http_s_url_without_embedded_login_passwor_98a56ab',
  invalid_subscription_headers: 'subscriptions.headers_must_be_a_json_object_of_string_values_c_dbcdd56',
  invalid_group: 'subscriptions.group_name_invalid',
  group_not_found: 'subscriptions.this_group_no_longer_exists_7cde6c2',
  protected_group: 'subscriptions.personal_cannot_be_deleted_54deff6',
  invalid_group_order: 'subscriptions.the_group_cannot_be_moved_further_2cf64e1',
  subscription_missing: 'subscriptions.this_group_has_no_subscription_dc876fb',
  subscription_network_error: 'subscriptions.could_not_download_the_subscription_check_the_ad_19a7fe7',
  subscription_timeout: 'subscriptions.the_subscription_server_did_not_respond_in_time_1291494',
  subscription_http_error: 'subscriptions.the_subscription_server_returned_an_error_8d6cb85',
  subscription_cancelled: 'subscriptions.download_cancelled_47fa2a8',
  subscription_redirect_error: 'subscriptions.the_subscription_redirect_is_invalid_or_unsafe_f4e7452',
  subscription_too_large: 'subscriptions.subscription_too_large',
  subscription_empty: 'subscriptions.the_subscription_server_returned_an_empty_respon_fc828a8',
  subscription_invalid_text: 'subscriptions.the_response_must_be_utf_8_text_77ec60b',
  subscription_proxy_unavailable: 'subscriptions.connect_a_profile_with_a_local_http_proxy_or_dis_662e08f',
  subscription_download_busy: 'subscriptions.another_download_is_still_running_try_again_shor_cea87cd',
  subscription_changed: 'subscriptions.the_group_profiles_or_connection_changed_load_th_c522490',
  subscription_expired: 'subscriptions.this_preview_expired_load_the_subscription_again_fe03609',
  subscription_preview_required: 'subscriptions.review_the_subscription_before_applying_it_fe73d4c',
  subscription_invalid_profiles: 'subscriptions.subscription_profile_count',
} satisfies Record<string, MessageKey>;
export type { Language };
export const tr = (key: keyof typeof messageKeys, lang: Language) => translate(lang, messageKeys[key]);
export function message(e: unknown, lang: Language, fallback: (e: unknown) => string) {
  const code = errorCode(e);
  if (Object.prototype.hasOwnProperty.call(messageKeys, code))
    return tr(code as keyof typeof messageKeys, lang);
  if (/^subscription_http_\d{3}$/.test(code))
    return translate(lang, 'subscriptions.subscription_server_returned_http_d625152') + code.slice(-3);
  return fallback(e);
}
export { formatBytes as bytes } from '../shared/i18n/format.ts';
import { formatBytes as bytes } from '../shared/i18n/format.ts';
const date = (n: number, lang: Language) => {
  const d = new Date(n * 1000);
  return Number.isNaN(d.getTime()) ? '—' : formatDateTime(d, lang);
};
/** Traffic a subscription reports as used, or null when it reports neither direction. */
export const usedTraffic = (usage: SubscriptionUsage | null | undefined) =>
  !usage || (usage.upload === null && usage.download === null)
    ? null
    : (usage.upload ?? 0) + (usage.download ?? 0);
/** An automatic update interval: whole hours as hours, anything else in minutes. */
export const intervalText = (minutes: number, lang: Language) =>
  minutes % 60 === 0
    ? plural(lang, 'subscriptions.every_hours', minutes / 60)
    : plural(lang, 'subscriptions.every_minutes', minutes);
export function usageText(usage: SubscriptionUsage | null | undefined, lang: Language) {
  if (!usage) return '';
  const used = usedTraffic(usage);
  return [
    used !== null
      ? `${tr('usage', lang)}: ${bytes(used, lang)}${usage.total ? ` / ${bytes(usage.total, lang)}` : ''}`
      : usage.total
        ? `${tr('usage', lang)}: — / ${bytes(usage.total, lang)}`
        : '',
    usage.total === 0 ? tr('unlimited', lang) : '',
    usage.expire ? `${tr('expires', lang)}: ${date(usage.expire, lang)}` : '',
  ]
    .filter(Boolean)
    .join(' · ');
}
/** A job's stage; while geodata or the configuration check runs, how many servers it covers. */
export const jobText = (job: SubscriptionJob, lang: Language) =>
  tr(job.status, lang) +
  ((job.status === 'geodata' || job.status === 'checking') && job.total
    ? ` · ${plural(lang, 'subscriptions.job_servers', job.total)}`
    : '');
export const updatedText = (g: Group, lang: Language) =>
  g.updatedAt ? `${tr('last', lang)}: ${date(g.updatedAt, lang)}` : tr('never', lang);
