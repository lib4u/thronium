import { translate } from '../shared/i18n/index.ts';
import { errorCode } from '../shared/api/errors.ts';
import { isVpnOtpError, vpnOtpError } from './vpnOtpMessages.ts';
const keys = {
  title: 'connection.vpn_title',
  endpoints: 'connection.vpn_endpoints',
  open: 'connection.vpn_open',
  otp_ready: 'connection.vpn_otp_ready',
  otp_waiting: 'connection.vpn_otp_waiting',
  otp_manual: 'connection.vpn_otp_manual',
  otp_disabled: 'connection.vpn_otp_disabled',
  otp_limited: 'connection.vpn_otp_limited',
  otp_error: 'connection.vpn_otp_error',
  otp_start: 'connection.vpn_otp_start',
  pending: 'connection.vpn_pending',
  connecting: 'connection.vpn_connecting',
  connected: 'connection.vpn_connected',
  error: 'connection.vpn_error',
  unknown: 'connection.vpn_unknown',
  notice: 'connection.vpn_notice',
  waiting: 'connection.vpn_waiting',
  failed: 'connection.vpn_failed',
  submit: 'connection.vpn_submit',
  cancel: 'connection.vpn_cancel',
  close: 'connection.vpn_close',
  reload: 'connection.vpn_reload',
  username: 'connection.vpn_username',
  password: 'connection.vpn_password',
  secret: 'connection.vpn_secret',
  expires: 'connection.vpn_expires',
  tunnel_details: 'connection.vpn_tunnel_details',
  tunnel_server: 'connection.vpn_tunnel_server',
  tunnel_network: 'connection.vpn_tunnel_network',
  tunnel_cipher: 'connection.vpn_tunnel_cipher',
  tunnel_mtu: 'connection.vpn_tunnel_mtu',
  tunnel_since: 'connection.vpn_tunnel_since',
  tunnel_ipv4: 'connection.vpn_tunnel_ipv4',
  tunnel_ipv6: 'connection.vpn_tunnel_ipv6',
  tunnel_dns: 'connection.vpn_tunnel_dns',
  tunnel_routes: 'connection.vpn_tunnel_routes',
  tunnel_excluded: 'connection.vpn_tunnel_excluded',
  tunnel_domains: 'connection.vpn_tunnel_domains',
  tunnel_all_domains: 'connection.vpn_tunnel_all_domains',
  expired: 'connection.vpn_expired',
  unavailable: 'connection.vpn_unavailable',
  unsupported: 'connection.vpn_unsupported',
  browserUnsupported: 'connection.vpn_browserUnsupported',
  openBrowser: 'connection.vpn_openBrowser',
  browserHint: 'connection.vpn_browserHint',
  closeHint: 'connection.vpn_closeHint',
  cancelled: 'connection.vpn_cancelled',
  vpn_auth_stale: 'connection.vpn_vpn_auth_stale',
  vpn_auth_expired: 'connection.vpn_vpn_auth_expired',
  vpn_auth_invalid_response: 'connection.vpn_vpn_auth_invalid_response',
  vpn_endpoint_error: 'connection.vpn_vpn_endpoint_error',
  vpn_challenge_stale: 'connection.vpn_vpn_challenge_stale',
  vpn_challenge_expired: 'connection.vpn_vpn_challenge_expired',
  vpn_auth_invalid: 'connection.vpn_vpn_auth_invalid',
  vpn_auth_unsupported: 'connection.vpn_vpn_auth_unsupported',
  vpn_auth_managed_unsupported: 'connection.vpn_vpn_auth_managed_unsupported',
  vpn_status_unavailable: 'connection.vpn_vpn_status_unavailable',
  vpn_status_unsupported: 'connection.vpn_vpn_status_unsupported',
  vpn_auth_failed: 'connection.vpn_vpn_auth_failed',
  vpn_auth_submit_failed: 'connection.vpn_vpn_auth_submit_failed',
  vpn_auth_cancel_failed: 'connection.vpn_vpn_auth_cancel_failed',
  vpn_auth_url_invalid: 'connection.vpn_vpn_auth_url_invalid',
  vpn_browser_open_failed: 'connection.vpn_vpn_browser_open_failed',
} as const;

export type VpnText = keyof typeof keys;
export function vpnText(key: VpnText, language: string) {
  return translate(language, keys[key]);
}
export function vpnError(error: unknown, language: string) {
  const code = errorCode(error);
  if (isVpnOtpError(code)) return vpnOtpError(code, language);
  // RPC failures may contain server text or credentials. Only display known codes.
  return Object.prototype.hasOwnProperty.call(keys, code)
    ? vpnText(code as VpnText, language)
    : vpnText('unavailable', language);
}
