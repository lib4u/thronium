import type { MessageKey } from '../shared/i18n/index.ts';
import { translate } from '../shared/i18n/index.ts';
import { errorCode } from '../shared/api/errors.ts';
import type * as Wire from '../shared/api/generated/commands';
import type { VpnStatus } from '../api';

export type CredentialRequest = Wire.VpnCredentialRequest;
export type CredentialView = Wire.VpnCredentials;

export function credentialsKey(request: CredentialRequest): string {
  return JSON.stringify([request.sessionId, request.endpointTag]);
}

export function isCurrentCredentials(status: VpnStatus, request: CredentialRequest): boolean {
  return (
    status.sessionId === request.sessionId &&
    status.endpoints.some(
      (endpoint) =>
        endpoint.tag === request.endpointTag &&
        endpoint.state === 'error' &&
        endpoint.authFailed &&
        !endpoint.challengeId,
    )
  );
}

export function validCredentials(username: string, password: string): boolean {
  const size = (value: string) => new TextEncoder().encode(value).length;
  return (
    !!(username || password) &&
    [username, password].every(
      (value) => !value.includes('\0') && !value.includes('{otp}') && size(value) <= 4096,
    )
  );
}

const messages: Record<string, MessageKey> = {
  vpn_credentials_unsupported: 'connection.this_connection_does_not_support_temporary_usern_534d197',
  vpn_credentials_proxy_cleanup_failed: 'connection.could_not_finish_stopping_the_previous_connectio_679d62b',
  system_proxy_changed: 'connection.the_system_proxy_was_changed_outside_thronium_re_12ee009',
  system_proxy_recovery_failed: 'connection.could_not_verify_or_restore_the_system_proxy_set_ad32b14',
  system_proxy_incompatible: 'connection.the_system_proxy_settings_do_not_match_this_conn_792bb74',
  system_proxy_busy: 'connection.another_thronium_instance_controls_the_system_pr_7033832',
  system_proxy_not_writable: 'connection.the_system_proxy_settings_cannot_be_changed_rest_180e9dc',
  system_proxy_read_failed: 'connection.could_not_read_the_current_system_proxy_settings_e34ca60',
  system_proxy_journal_failed: 'connection.could_not_finish_restoring_the_system_proxy_2dd6fc6',
  system_proxy_unavailable: 'connection.the_system_proxy_is_unavailable_in_this_environm_b820f03',
  vpn_credentials_managed_unsupported: 'connection.the_current_core_does_not_support_retrying_vpn_s_1acb27c',
  tun_recovery_failed: 'connection.could_not_confirm_that_the_previous_vpn_connecti_5d0e833',
  vpn_credentials_configuration_unsupported:
    'connection.this_profile_uses_a_cookie_token_or_predefined_f_7ca2ac4',
  vpn_credentials_unavailable: 'connection.retrying_sign_in_is_currently_unavailable_for_th_852970e',
  vpn_credentials_stale: 'connection.the_connection_changed_open_the_sign_in_dialog_f_18a147d',
  vpn_credentials_expired: 'connection.this_sign_in_request_expired_reload_it_to_try_ag_eb59ce9',
  vpn_credentials_invalid: 'connection.credentials_invalid',
  vpn_credentials_check_failed: 'connection.the_new_credentials_could_not_be_checked_b5cb9be',
  vpn_credentials_restart_failed: 'connection.the_connection_could_not_be_restarted_with_these_29e1e65',
  connection_restored: 'connection.the_new_attempt_failed_the_previous_connection_s_f921341',
  connection_restore_failed: 'connection.the_new_attempt_and_recovery_both_failed_connect_0706c2a',
};

export function credentialsError(error: unknown, language: string): string {
  const code = errorCode(error);
  const value = Object.prototype.hasOwnProperty.call(messages, code) ? messages[code] : undefined;
  return translate(language, value || 'connection.the_sign_in_request_could_not_be_completed_7843817');
}
