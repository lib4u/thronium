import type { MessageKey } from '../shared/i18n/index.ts';
import { translate, translateOptional } from '../shared/i18n/index.ts';
import { errorCode } from '../shared/api/errors.ts';
const messages: Record<string, MessageKey> = {
  vpn_otp_binding_invalid: 'connection.the_otp_binding_data_could_not_be_read_reload_th_7d3c3ee',
  vpn_otp_profile_unsupported: 'connection.automatic_otp_is_available_for_individual_openvp_f547d50',
  vpn_otp_platform_unsupported: 'connection.automatic_hotp_is_currently_supported_only_on_li_10dd3eb',
  vpn_otp_start_placeholder_unsupported:
    'connection.otp_substitution_in_credentials_at_connection_st_6db264e',
  vpn_otp_form_shadowed: 'connection.the_form_has_overlapping_fixed_values_and_otp_te_81c1a67',
  vpn_otp_form_cache_unsupported: 'connection.this_otp_template_targets_a_field_that_may_be_fi_45e71eb',
  vpn_otp_binding_changed: 'connection.the_profile_or_binding_changed_reload_the_saved__878744a',
  vpn_otp_binding_save_failed: 'connection.could_not_confirm_that_the_binding_was_saved_rel_c3aa0f8',
  vpn_otp_missing: 'connection.the_selected_otp_entry_no_longer_exists_choose_a_0803da4',
  otp_missing: 'connection.the_otp_entry_no_longer_exists_4c393db',
  otp_changed: 'connection.the_otp_entry_changed_reload_its_current_version_750c91e',
  otp_in_use: 'connection.this_otp_entry_is_used_by_a_vpn_profile_remove_i_46309eb',
  vpn_otp_retry_limited: 'connection.automatic_otp_attempts_have_stopped_complete_aut_674d184',
  vpn_otp_counter_exhausted: 'connection.the_hotp_counter_has_reached_its_limit_complete__d7ed1b2',
  vpn_otp_code_spent: 'connection.vpn_otp_code_spent',
  vpn_otp_save_failed: 'connection.could_not_save_the_hotp_counter_no_automatic_cod_09d2d5b',
  vpn_otp_manual_required: 'connection.this_request_needs_a_manual_response_de150a4',
  vpn_otp_auto_disabled: 'connection.automatic_otp_has_stopped_for_this_connection_re_ea0673e',
  vpn_otp_start_unsupported: 'connection.vpn_otp_start_unsupported',
  vpn_otp_start_mode_required: 'connection.vpn_otp_start_mode_required',
  vpn_otp_start_stale: 'connection.vpn_otp_start_stale',
  vpn_otp_start_context_unsupported: 'connection.vpn_otp_start_context_unsupported',
  vpn_otp_start_retry_unsupported: 'connection.vpn_otp_start_retry_unsupported',
  vpn_otp_start_mode_unsupported: 'connection.vpn_otp_start_mode_unsupported',
  vpn_otp_start_background_unsupported: 'connection.vpn_otp_start_background_unsupported',
};

export function vpnOtpError(error: unknown, language: string) {
  const code = errorCode(error);
  const value = Object.prototype.hasOwnProperty.call(messages, code) ? messages[code] : undefined;
  return (
    translateOptional(language, value) ||
    translate(language, 'connection.could_not_update_the_otp_binding_4324986')
  );
}

export function isVpnOtpError(code: string) {
  return Object.prototype.hasOwnProperty.call(messages, code);
}
