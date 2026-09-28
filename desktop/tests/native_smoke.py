"""WebDriver test of the installed Linux webview and real Rust/Go backend.

Start tauri-driver in an isolated XDG_DATA_HOME, then run this script.
Loopback traffic and private GNOME keyfile settings only; no user proxy, DNS or TUN changes.
"""
import argparse
import base64
import http.client
import json
import pathlib
import socket
import time
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument('--driver', default='http://127.0.0.1:4446')
parser.add_argument('--application', default=str(pathlib.Path(__file__).resolve().parents[1] / 'src-tauri/target/debug/Thronium'))
parser.add_argument('--session')
parser.add_argument('--subscriptions-only', action='store_true')
parser.add_argument('--queue-only', action='store_true')
parser.add_argument('--probes-only', action='store_true')
parser.add_argument('--periodic-probes-only', action='store_true')
parser.add_argument('--vpn-probes-only', action='store_true')
parser.add_argument('--profile-order-only', action='store_true')
parser.add_argument('--profile-edit-only', action='store_true')
parser.add_argument('--ws-early-data-only', action='store_true')
parser.add_argument('--httpupgrade-early-data-only', action='store_true')
parser.add_argument('--bulk-only', action='store_true')
parser.add_argument('--transfer-only', action='store_true')
parser.add_argument('--share-only', action='store_true')
parser.add_argument('--archive-export-only', action='store_true')
parser.add_argument('--resources-only', action='store_true')
parser.add_argument('--legacy-backup-only', action='store_true')
parser.add_argument('--legacy-icons-only', action='store_true')
parser.add_argument('--legacy-local-resources-only', action='store_true')
parser.add_argument('--legacy-endpoints-only', action='store_true')
parser.add_argument('--subscription-happ-only', action='store_true')
parser.add_argument('--routing-source-only', action='store_true')
parser.add_argument('--legacy-wg-only', action='store_true')
parser.add_argument('--wireguard-live-only', action='store_true')
parser.add_argument('--wireguard-topology-only', action='store_true')
parser.add_argument('--awg-live-only', action='store_true')
parser.add_argument('--awg-migration-only', action='store_true')
parser.add_argument('--legacy-selector-only', action='store_true')
parser.add_argument('--selector-export-only', action='store_true')
parser.add_argument('--otp-only', action='store_true')
parser.add_argument('--legacy-otp-only', action='store_true')
parser.add_argument('--legacy-settings-only', action='store_true')
parser.add_argument('--legacy-basic-settings-only', action='store_true')
parser.add_argument('--legacy-runtime-settings-only', action='store_true')
parser.add_argument('--legacy-hotkeys-only', action='store_true')
parser.add_argument('--external-core-only', action='store_true')
parser.add_argument('--legacy-external-core-only', action='store_true')
parser.add_argument('--nested-routing-only', action='store_true')
parser.add_argument('--inline-ruleset-only', action='store_true')
parser.add_argument('--routing-resources-only', action='store_true')
parser.add_argument('--otp-migration-only', action='store_true')
parser.add_argument('--legacy-routing-only', action='store_true')
parser.add_argument('--legacy-quic-dns-only', action='store_true')
parser.add_argument('--rfd-dialogs-only', action='store_true')
parser.add_argument('--subscription-hwid-only', action='store_true')
parser.add_argument('--tray-catalog-only', action='store_true')
parser.add_argument('--core-recovery-only', action='store_true')
parser.add_argument('--system-proxy-recovery-only', action='store_true')
parser.add_argument('--profile-tls-only', action='store_true')
parser.add_argument('--vpn-auth-only', action='store_true')
parser.add_argument('--vpn-auth-managed-only', action='store_true')
parser.add_argument('--vpn-credentials-only', action='store_true')
parser.add_argument('--vpn-credentials-managed-only', action='store_true')
parser.add_argument('--vpn-credentials-system-proxy-only', action='store_true')
parser.add_argument('--vpn-policy-only', action='store_true')
parser.add_argument('--legacy-vpn-bindings-only', action='store_true')
parser.add_argument('--vpn-otp-binding-only', action='store_true')
parser.add_argument('--vpn-otp-layout-only', action='store_true')
parser.add_argument('--vpn-otp-binding-managed-only', action='store_true')
parser.add_argument('--subscription-names-only', action='store_true')
parser.add_argument('--group-chains-only', action='store_true')
parser.add_argument('--diagnostics-only', action='store_true')
parser.add_argument('--logs-only', action='store_true')
parser.add_argument('--chains-only', action='store_true')
parser.add_argument('--library-only', action='store_true')
parser.add_argument('--library-maintenance-only', action='store_true')
parser.add_argument('--traffic-stats-only', action='store_true')
parser.add_argument('--throne-directory-only', action='store_true')
parser.add_argument('--secrets-only', action='store_true')
parser.add_argument('--openvpn-pending-only', action='store_true')
parser.add_argument('--vpn-restart-only', action='store_true')
parser.add_argument('--openconnect-cstp-only', action='store_true')
parser.add_argument('--fakeip-batch-only', action='store_true')
parser.add_argument('--selectors-only', action='store_true')
parser.add_argument('--auto-select-simple-only', action='store_true')
parser.add_argument('--dynamic-selectors-only', action='store_true')
parser.add_argument('--selector-country-only', action='store_true')
parser.add_argument('--selector-ranking-only', action='store_true')
parser.add_argument('--selector-warm-only', action='store_true')
parser.add_argument('--selector-history-only', action='store_true')
parser.add_argument('--selector-limit-only', action='store_true')
parser.add_argument('--selector-pool-cap-only', action='store_true')
parser.add_argument('--selector-saved-order-only', action='store_true')
parser.add_argument('--selector-measurements-only', action='store_true')
parser.add_argument('--selector-preflight-only', action='store_true')
parser.add_argument('--selector-subscription-only', action='store_true')
parser.add_argument('--selector-rebuild-only', action='store_true')
parser.add_argument('--selector-health-only', action='store_true')
parser.add_argument('--backups-only', action='store_true')
parser.add_argument('--tray-only', action='store_true')
parser.add_argument('--tray-routing-only', action='store_true')
parser.add_argument('--tray-otp-only', action='store_true')
parser.add_argument('--tray-controls-only', action='store_true')
parser.add_argument('--tray-system-only', action='store_true')
parser.add_argument('--instance-only', action='store_true')
parser.add_argument('--window-only', action='store_true')
parser.add_argument('--groups-only', action='store_true')
parser.add_argument('--modals-only', action='store_true')
parser.add_argument('--rules-only', action='store_true')
parser.add_argument('--routing-catalog-only', action='store_true')
parser.add_argument('--settings-only', action='store_true')
parser.add_argument('--warp-registration-only', action='store_true')
parser.add_argument('--dashboard-only', action='store_true')
parser.add_argument('--geodata-assets-only', action='store_true')
parser.add_argument('--geodata-history-only', action='store_true')
parser.add_argument('--legacy-geodata-only', action='store_true')
parser.add_argument('--legacy-warp-only', action='store_true')
parser.add_argument('--legacy-network-only', action='store_true')
parser.add_argument('--full-xray-probes-only', action='store_true')
parser.add_argument('--full-xray-diagnostics-only', action='store_true')
parser.add_argument('--full-sing-diagnostics-only', action='store_true')
parser.add_argument('--speedtest-full-only', action='store_true')
parser.add_argument('--vpn-diagnostics-only', action='store_true')
parser.add_argument('--wireguard-diagnostics-only', action='store_true')
parser.add_argument('--trusttunnel-only', action='store_true')
parser.add_argument('--tun-endpoint-only', action='store_true')
parser.add_argument('--portable-only', action='store_true')
parser.add_argument('--os-links-only', action='store_true')
parser.add_argument('--qr-only', action='store_true')
parser.add_argument('--add-only', action='store_true')
parser.add_argument('--dropdown-only', action='store_true')
parser.add_argument('--group-drag-only', action='store_true')
parser.add_argument('--system-proxy-only', action='store_true')
parser.add_argument('--kde-proxy-only', action='store_true')
parser.add_argument('--connection-only', action='store_true')
parser.add_argument('--vless-only', action='store_true')
parser.add_argument('--tun-only', action='store_true')
parser.add_argument('--tun-reconnect-only', action='store_true')
parser.add_argument('--groups-live-file')
parser.add_argument('--live-subscription-file')
parser.add_argument('--artifacts', default='/tmp/thronium-native-results')
args = parser.parse_args()
artifacts = pathlib.Path(args.artifacts)
artifacts.mkdir(parents=True, exist_ok=True)
checks = []
closed_session = False


def raw_request(method, path, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(args.driver + path, data, {'Content-Type': 'application/json'}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=40) as response:
            value = json.load(response)['value']
    except urllib.error.HTTPError as error:
        raise RuntimeError(error.read().decode()) from error
    if isinstance(value, dict) and 'error' in value:
        raise RuntimeError(value)
    return value


def request(method, path, payload=None):
    from native_transport import execute, read, refresh
    if path.endswith(('/execute/sync', '/execute/async')):
        return execute(raw_request, method, path, payload)
    if method == 'POST' and path.endswith('/refresh'):
        return refresh(raw_request, method, path, payload)
    if method == 'GET': return read(raw_request, method, path, payload)
    return raw_request(method, path, payload)


session = args.session or request('POST', '/session', {'capabilities': {'alwaysMatch': {'tauri:options': {'application': args.application}}}})['sessionId']
base = '/session/' + session


def js(script, *values):
    return request('POST', base + '/execute/sync', {'script': script, 'args': list(values)})


def command(name, payload=None):
    result = request('POST', base + '/execute/async', {'script': '''
const done=arguments[arguments.length-1];
window.__TAURI_INTERNALS__.invoke('app_command',{name:arguments[0],payload:arguments[1]})
.then(value=>done({ok:true,value})).catch(error=>done({ok:false,error}));
''', 'args': [name, payload or {}]})
    if not result['ok']:
        raise RuntimeError(result['error'])
    return result.get('value')


def wait_for(script, timeout=10):
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        try:
            if js(script):
                return
        except (http.client.RemoteDisconnected, urllib.error.URLError):
            # Retry only this read-only observation; never replay a mutation.
            pass
        time.sleep(.1)
    raise AssertionError('Timed out: ' + script)


def element(selector):
    return request('POST', base + '/element', {'using': 'css selector', 'value': selector})['element-6066-11e4-a52e-4f735466cecf']


def click(selector):
    # Find and press in one script: the one-second snapshot poll may re-render
    # the element between a separate existence check and the click. Unlike
    # wait_for, a lost response is not retried, so a press is never repeated.
    start = time.monotonic()
    while time.monotonic() - start < 10:
        if js('const el=document.querySelector(arguments[0]);if(!el||el.matches(":disabled"))return false;el.click();return true', selector):
            return
        time.sleep(.1)
    raise AssertionError('Timed out: click ' + selector)


def select(selector, value):
    wait_for('return (()=>{const el=document.querySelector(' + json.dumps(selector) + ');return el&&!el.matches(":disabled")})()')
    js("const el=document.querySelector(arguments[0]);el.value=arguments[1];el.dispatchEvent(new Event('change',{bubbles:true}));", selector, value)


def fill(selector, text):
    wait_for('return (()=>{const el=document.querySelector(' + json.dumps(selector) + ');return el&&!el.matches(":disabled")})()')
    js('''const el=document.querySelector(arguments[0]);
if(!el||el.matches(':disabled'))throw new Error('The field is not available for input');
const proto=el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
Object.getOwnPropertyDescriptor(proto,'value').set.call(el,arguments[1]);
el.dispatchEvent(new Event('input',{bubbles:true}));
el.dispatchEvent(new Event('change',{bubbles:true}));''', selector, text)


def check(condition, name):
    assert condition, name
    checks.append(name)
    print('PASS', name, flush=True)


def screenshot(name):
    # GTK can throttle animation frames after a native dialog yields focus.
    # DOM/layout assertions are separate; do not hang an artifact capture on rAF.
    request('POST', base + '/execute/async', {'script': 'const done=arguments[arguments.length-1];let finished=false;const finish=()=>{if(!finished){finished=true;done(null);}};requestAnimationFrame(()=>requestAnimationFrame(finish));setTimeout(finish,500);', 'args': []})
    from native_screenshot import capture
    capture(artifacts / (name + '.png'))


try:
    wait_for('return !!document.querySelector(".add-connection")')
    if args.legacy_endpoints_only or args.subscription_happ_only or args.legacy_local_resources_only or args.profile_edit_only or args.legacy_network_only or args.legacy_warp_only or args.legacy_geodata_only or args.vpn_diagnostics_only or args.wireguard_diagnostics_only or args.trusttunnel_only or args.tun_endpoint_only or args.geodata_history_only or args.speedtest_full_only or args.full_sing_diagnostics_only or args.full_xray_diagnostics_only or args.full_xray_probes_only or args.portable_only or args.os_links_only or args.geodata_assets_only or args.dashboard_only or args.warp_registration_only or args.selector_subscription_only or args.selector_rebuild_only or args.selector_preflight_only or args.selector_measurements_only or args.selector_saved_order_only or args.selector_pool_cap_only or args.selector_health_only or args.selector_limit_only or args.selector_history_only or args.selector_warm_only or args.selector_ranking_only or args.selector_country_only or args.wireguard_topology_only or args.wireguard_live_only or args.awg_live_only or args.awg_migration_only or args.httpupgrade_early_data_only or args.ws_early_data_only or args.profile_order_only or args.vpn_probes_only or args.legacy_vpn_bindings_only or args.vpn_policy_only or args.vpn_credentials_system_proxy_only or args.vpn_otp_layout_only or args.vpn_credentials_managed_only or args.vpn_credentials_only or args.vpn_otp_binding_managed_only or args.vpn_otp_binding_only or args.vpn_auth_managed_only or args.vpn_auth_only or args.profile_tls_only or args.system_proxy_recovery_only or args.core_recovery_only or args.tray_catalog_only or args.subscription_hwid_only or args.legacy_quic_dns_only or args.rfd_dialogs_only or args.routing_resources_only or args.inline_ruleset_only or args.nested_routing_only or args.legacy_external_core_only or args.tray_controls_only or args.tray_system_only or args.external_core_only or args.legacy_basic_settings_only or args.legacy_runtime_settings_only or args.legacy_hotkeys_only or args.legacy_settings_only or args.tray_otp_only or args.otp_migration_only or args.legacy_otp_only or args.selector_export_only or args.otp_only or args.legacy_selector_only or args.legacy_routing_only or args.legacy_wg_only or args.routing_catalog_only or args.legacy_backup_only or args.legacy_icons_only or args.routing_source_only or args.resources_only or args.archive_export_only or args.tray_routing_only or args.dynamic_selectors_only or args.diagnostics_only or args.group_chains_only or args.subscription_names_only or args.share_only or args.settings_only or args.vless_only or args.rules_only or args.tun_reconnect_only or args.qr_only or args.tun_only or args.connection_only or args.add_only or args.dropdown_only or args.group_drag_only or args.system_proxy_only or args.kde_proxy_only or args.subscriptions_only or args.queue_only or args.probes_only or args.periodic_probes_only or args.bulk_only or args.transfer_only or args.logs_only or args.chains_only or args.library_only or args.library_maintenance_only or args.traffic_stats_only or args.throne_directory_only or args.secrets_only or args.openvpn_pending_only or args.vpn_restart_only or args.openconnect_cstp_only or args.fakeip_batch_only or args.selectors_only or args.auto_select_simple_only or args.backups_only or args.tray_only or args.instance_only or args.window_only or args.groups_only or args.modals_only or args.groups_live_file or args.live_subscription_file:
        if args.profile_edit_only:
            from profile_edit_ui import run
            run(globals())
        elif args.legacy_network_only:
            from legacy_network_ui import run
            run(globals())
        elif args.legacy_warp_only:
            from legacy_warp_ui74 import run
            run(globals())
        elif args.legacy_geodata_only:
            from legacy_geodata_ui73 import run
            run(globals())
        elif args.vpn_diagnostics_only:
            from vpn_diagnostics_ui72 import run
            run(globals())
        elif args.wireguard_diagnostics_only:
            from wireguard_diagnostics_ui import run
            run(globals())
        elif args.trusttunnel_only:
            from trusttunnel_ui import run
            run(globals())
        elif args.tun_endpoint_only:
            from tun_endpoint_ui import run
            run(globals())
        elif args.speedtest_full_only:
            from speedtest_full_ui import run
            run(globals())
        elif args.full_sing_diagnostics_only:
            from full_sing_diagnostics_ui import run
            run(globals())
        elif args.full_xray_diagnostics_only:
            from full_xray_diagnostics_ui import run
            run(globals())
        elif args.full_xray_probes_only:
            from full_xray_probes_ui import run
            run(globals())
        elif args.portable_only:
            from portable_ui import run
            run(globals())
        elif args.os_links_only:
            from os_links_ui import run
            run(globals())
        elif args.geodata_history_only:
            from geodata_history_ui import run
            run(globals())
        elif args.geodata_assets_only:
            from geodata_assets_ui import run
            run(globals())
        elif args.dashboard_only:
            from dashboard_ui import run
            run(globals())
        elif args.warp_registration_only:
            from warp_registration_ui import run
            run(globals())
        elif args.selector_subscription_only:
            from selector_subscription_ui import run
            run(globals())
        elif args.selector_rebuild_only:
            from selector_rebuild_ui import run
            run(globals())
        elif args.selector_preflight_only:
            from selector_preflight_ui import run
            run(globals())
        elif args.live_subscription_file:
            from subscription_live import run
            run(globals(), args.live_subscription_file)
        elif args.tun_reconnect_only:
            from tun_reconnect_ui import run
            run(globals())
        elif args.otp_migration_only:
            from otp_migration_ui import run
            run(globals())
        elif args.routing_resources_only:
            from routing_resources_ui import run
            run(globals())
        elif args.inline_ruleset_only:
            from inline_ruleset_ui import run
            run(globals())
        elif args.nested_routing_only:
            from nested_routing_ui import run
            run(globals())
        elif args.legacy_external_core_only:
            from legacy_external_core_ui import run
            run(globals())
        elif args.external_core_only:
            from external_core_ui import run
            run(globals())
        elif args.legacy_basic_settings_only:
            from legacy_basic_settings_ui import run
            run(globals())
        elif args.legacy_runtime_settings_only:
            from legacy_runtime_settings_ui import run
            run(globals())
        elif args.legacy_hotkeys_only:
            from legacy_hotkeys_ui import run
            run(globals())
        elif args.legacy_settings_only:
            from legacy_settings_ui import run
            run(globals())
        elif args.legacy_otp_only:
            from legacy_otp_ui import run
            run(globals())
        elif args.otp_only:
            from otp_ui import run
            run(globals())
        elif args.selector_export_only:
            from selector_export_ui import run
            run(globals())
        elif args.legacy_selector_only:
            from legacy_selector_ui import run
            run(globals())
        elif args.routing_source_only:
            from routing_source_ui import run
            run(globals())
        elif args.legacy_local_resources_only:
            from legacy_local_resources_ui import run, run_profiles
            run(globals())
            run_profiles(globals())
        elif args.legacy_endpoints_only:
            from legacy_endpoints_ui import run
            run(globals())
        elif args.subscription_happ_only:
            from subscription_happ_ui import run
            run(globals())
        elif args.legacy_icons_only:
            from legacy_icons_ui import run
            run(globals())
        elif args.legacy_backup_only:
            from legacy_backup_ui import run
            run(globals())
        elif args.legacy_quic_dns_only:
            from legacy_quic_dns_ui import run
            run(globals())
        elif args.rfd_dialogs_only:
            from rfd_dialogs_ui import run
            run(globals())
        elif args.legacy_routing_only:
            from legacy_routing_ui import run
            run(globals())
        elif args.auto_select_simple_only:
            from auto_select_simple_ui import run
            run(globals())
        elif args.awg_migration_only:
            from awg_migration_ui import run
            run(globals())
        elif args.awg_live_only:
            from awg_live_ui import run
            run(globals())
        elif args.wireguard_topology_only:
            from wireguard_topology_ui import run
            run(globals())
        elif args.wireguard_live_only:
            from wireguard_live_ui import run
            run(globals())
        elif args.legacy_wg_only:
            from legacy_wg_ui import run
            run(globals())
        elif args.resources_only:
            from resources_ui import run
            run(globals())
        elif args.archive_export_only:
            from archive_export_ui import run
            run(globals())
        elif args.tray_controls_only:
            from tray_controls_ui import run
            run(globals())
        elif args.tray_system_only:
            from tray_system_ui import run
            run(globals())
        elif args.tray_otp_only:
            from tray_otp_ui import run
            run(globals())
        elif args.tray_routing_only:
            from tray_routing_ui import run
            run(globals())
        elif args.selector_health_only:
            from selector_health_ui import run
            run(globals())
        elif args.selector_measurements_only:
            from selector_measurements_ui import run
            run(globals())
        elif args.selector_saved_order_only:
            from selector_saved_order_ui import run
            run(globals())
        elif args.selector_pool_cap_only:
            from selector_pool_cap_ui import run
            run(globals())
        elif args.selector_limit_only:
            from selector_limit_ui import run
            run(globals())
        elif args.selector_history_only:
            from selector_history_ui import run
            run(globals())
        elif args.selector_warm_only:
            from selector_warm_ui import run
            run(globals())
        elif args.selector_ranking_only:
            from selector_ranking_ui import run
            run(globals())
        elif args.selector_country_only:
            from selector_country_ui import run
            run(globals())
        elif args.dynamic_selectors_only:
            from dynamic_selectors_ui import run
            run(globals())
        elif args.diagnostics_only:
            from diagnostics_ui import run
            run(globals())
        elif args.group_chains_only:
            from group_chains_ui import run
            run(globals())
        elif args.httpupgrade_early_data_only:
            from ws_early_data_ui import run
            run(globals(), 'httpupgrade')
        elif args.ws_early_data_only:
            from ws_early_data_ui import run
            run(globals())
        elif args.profile_order_only:
            from profile_order_ui import run
            run(globals())
        elif args.vpn_probes_only:
            from vpn_probes_ui import run
            run(globals())
        elif args.legacy_vpn_bindings_only:
            from legacy_vpn_binding_ui import run
            run(globals())
        elif args.vpn_policy_only:
            from vpn_policy_ui import run
            run(globals())
        elif args.vpn_credentials_system_proxy_only:
            from vpn_credentials_system_proxy_ui import run
            run(globals())
        elif args.vpn_credentials_managed_only:
            from vpn_credentials_managed_ui import run
            run(globals())
        elif args.vpn_credentials_only:
            from vpn_credentials_ui import run
            run(globals())
        elif args.vpn_otp_binding_managed_only:
            from vpn_otp_binding_managed_ui import run
            run(globals())
        elif args.vpn_otp_layout_only:
            from vpn_otp_layout_ui import run
            run(globals())
        elif args.vpn_otp_binding_only:
            from vpn_otp_binding_ui import run
            run(globals())
        elif args.vpn_auth_managed_only:
            from vpn_auth_managed_ui import run
            run(globals())
        elif args.vpn_auth_only:
            from vpn_auth_ui import run
            run(globals())
        elif args.profile_tls_only:
            from profile_tls_ui import run
            run(globals())
        elif args.system_proxy_recovery_only:
            from system_proxy_recovery_ui import run
            run(globals())
        elif args.core_recovery_only:
            from core_recovery_ui import run
            run(globals())
        elif args.tray_catalog_only:
            from tray_catalog_ui import run
            run(globals())
        elif args.subscription_hwid_only:
            from subscription_hwid_ui import run
            run(globals())
        elif args.subscription_names_only:
            from subscription_names_ui import run
            run(globals())
        elif args.share_only:
            from share_ui import run
            run(globals())
        elif args.vless_only:
            from vless_ui import run
            run(globals())
        elif args.tun_only:
            from tun_ui import run
            run(globals())
        elif args.connection_only:
            from session_ui import run as run_session
            run_session(globals())
            from connection_ui import run
            run(globals())
        elif args.kde_proxy_only:
            from kde_proxy_ui import run
            run(globals())
        elif args.system_proxy_only:
            from system_proxy_ui import run
            run(globals())
        elif args.group_drag_only:
            from group_drag_ui import run
            run(globals())
        elif args.dropdown_only:
            from dropdown_ui import run
            run(globals())
        elif args.qr_only:
            from qr_import_ui import run
            run(globals())
        elif args.add_only:
            from add_dialog_ui import run
            run(globals())
        elif args.settings_only:
            from settings_ui import run
            run(globals())
        elif args.routing_catalog_only:
            from routing_catalog_ui import run
            run(globals())
        elif args.rules_only:
            from routing_rule_ui import run
            run(globals())
        elif args.modals_only:
            from modals_ui import run
            run(globals())
        elif args.groups_only or args.groups_live_file:
            from grouped_library_ui import run, live
            if args.groups_live_file: live(globals(), args.groups_live_file)
            else: run(globals())
        elif args.window_only:
            from window_ui import run, close
            run(globals())
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0)); port = listener.getsockname()[1]
            command('preferences', {**command('snapshot')['preferences'], 'inboundPort': port})
            profile = command('saveProfile', {'name': 'Window direct', 'groupId': 'personal', 'kind': 'sing-box-outbound', 'config': {'type': 'direct'}})['id']
            command('connect', {'id': profile})
            close(globals(), port)
        elif args.instance_only:
            from instance_ui import run
            run(globals())
        elif args.tray_only:
            from tray_ui import run
            run(globals(), quitting=True)
        elif args.backups_only:
            from backups_ui import run
            run(globals())
        elif args.selectors_only:
            from selectors_ui import run
            run(globals())
        elif args.library_only:
            from library_ui import run
            run(globals())
        elif args.library_maintenance_only:
            from library_maintenance_ui import run
            run(globals())
        elif args.traffic_stats_only:
            from traffic_stats_ui import run
            run(globals())
        elif args.throne_directory_only:
            from throne_directory_ui import run
            run(globals())
        elif args.secrets_only:
            from secrets_ui import run
            run(globals())
        elif args.openvpn_pending_only:
            from openvpn_pending_ui import run
            run(globals())
        elif args.vpn_restart_only:
            from vpn_restart_ui import run
            run(globals())
        elif args.openconnect_cstp_only:
            from openconnect_cstp_ui import run
            run(globals())
        elif args.fakeip_batch_only:
            from fakeip_batch_ui import run
            run(globals())
        elif args.chains_only:
            from chains_ui import run
            run(globals())
        elif args.logs_only:
            from logs_ui import run
            run(globals())
        elif args.transfer_only:
            from transfer_ui import run
            run(globals())
        elif args.bulk_only:
            from bulk_ui import run as run_bulk
            run_bulk(globals())
        elif args.periodic_probes_only:
            from periodic_probes_ui import run
            run(globals())
        elif args.probes_only:
            from probes_ui import run as run_probes
            run_probes(globals())
        else:
            if not args.queue_only:
                from subscription_ui import run
                run(globals())
            from subscription_queue_ui import run as run_queue
            run_queue(globals())
        (artifacts / 'results.json').write_text(json.dumps({'checks': checks, 'count': len(checks), 'backend': 'real Tauri + ThroneCore', 'network': 'user-supplied subscription and public HTTPS' if args.live_subscription_file or args.groups_live_file else 'isolated Linux network namespace' if args.tun_reconnect_only else 'loopback only'}, ensure_ascii=False, indent=2))
        print('TOTAL', len(checks))
        if not closed_session: request('DELETE', base)
        closed_session = True
        raise SystemExit(0)
    from group_drag_ui import run as run_group_drag
    run_group_drag(globals())
    from dropdown_ui import run as run_dropdown
    run_dropdown(globals())
    from add_dialog_ui import run as run_add
    run_add(globals())
    from window_ui import run as run_window
    run_window(globals())
    snapshot = command('snapshot')
    check(snapshot['profiles'] == [], 'new installation has no fabricated profiles')
    check(snapshot['phase'] == 'disconnected', 'new installation starts disconnected')
    check(snapshot['coreAvailable'], 'bundled full ThroneCore found')
    check(js('return window.isTauri'), 'actual Tauri webview')

    # Assign an unused loopback port, then exercise the UI rather than calling saveProfile.
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        proxy_port = listener.getsockname()[1]
    command('preferences', {**snapshot['preferences'], 'inboundPort': proxy_port})
    click('.add-connection'); click('#add-choice-advanced')
    js("const el=document.querySelector('#profile-type');el.value='direct';el.dispatchEvent(new Event('change',{bubbles:true}));")
    fill('#profile-name', 'UI native direct')
    click('.modal-footer .button.secondary')
    wait_for('return !!document.querySelector(".desktop-success")')
    check(True, 'editor validates configuration with real core')
    click('button[form="profile-editor"]')
    wait_for('return document.querySelectorAll(".connection-row").length===1 && !document.querySelector("dialog")')
    saved = command('snapshot')['profiles'][0]
    check(saved['name'] == 'UI native direct', 'profile saved by editor')
    click('.power-button')
    wait_for('return !document.body.classList.contains("disconnected")')
    check(command('snapshot')['running'] == saved['id'], 'Connect button starts real core')
    with socket.create_connection(('127.0.0.1', proxy_port), timeout=2):
        pass
    check(True, 'real local proxy port is listening')
    with socket.socket() as origin:
        origin.settimeout(3)
        origin.bind(('127.0.0.1', 0))
        origin.listen()
        address = '127.0.0.1:' + str(origin.getsockname()[1])
        with socket.create_connection(('127.0.0.1', proxy_port), timeout=3) as client:
            client.sendall(f'CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n'.encode())
            upstream, _ = origin.accept()
            with upstream:
                upstream.settimeout(3)
                check(b'200' in client.recv(1024), 'real HTTP tunnel established')
                client.sendall(b'thronium-test')
                check(upstream.recv(1024) == b'thronium-test', 'UI connection forwards bytes to local server')
                upstream.sendall(b'ack')
                check(client.recv(1024) == b'ack', 'UI connection receives real bytes')
                click('.primary-nav button:nth-child(3)')
                wait_for('return !!document.querySelector("[data-close-connection]")')
                live = command('snapshot')
                check(any(c['destination'] == address for c in live['connections']), 'diagnostics displays real destination')
                check(live['trafficUp'] > 0 and live['trafficDown'] > 0, 'session traffic is measured by the core')
                screenshot('diagnostics-live')
                click('[data-close-connection]')
                try:
                    ended = client.recv(1024) == b''
                except ConnectionResetError:
                    ended = True
                check(ended, 'Close connection button closes the real socket')
    click('.primary-nav button:first-child')
    click('.power-button')
    wait_for('return document.body.classList.contains("disconnected")')
    check(command('snapshot')['running'] is None, 'Disconnect button stops core')
    probe = socket.socket()
    try:
        check(probe.connect_ex(('127.0.0.1', proxy_port)) != 0, 'disconnect closes proxy port')
    finally:
        probe.close()

    click('.favorite-button')
    wait_for('return document.querySelector(".favorite-button").getAttribute("aria-pressed")==="true"')
    check(command('snapshot')['profiles'][0]['favorite'], 'favorite stored by backend')
    click('.desktop-language')
    wait_for('return document.documentElement.lang==="en"')
    check(js('return document.querySelector(".pane-heading h1").textContent') == 'Your connection', 'English language')
    click('.topbar-actions .icon-button')
    wait_for('return document.documentElement.dataset.theme==="dark"')
    check(command('snapshot')['preferences']['theme'] == 'dark', 'dark theme persisted')
    screenshot('connection-dark-en')

    request('POST', base + '/refresh', {})
    wait_for('return !!document.querySelector(".connection-row")')
    wait_for('return document.documentElement.lang==="en"')
    check(js('return document.documentElement.dataset.theme') == 'dark', 'theme and language survive reload')
    check(command('snapshot')['profiles'][0]['id'] == saved['id'], 'profile survives reload')

    # All protocol editors must render in the real WebKit webview. Core validation
    # of generated configurations is separately covered by test:profile-core.
    click('.add-connection'); click('#add-choice-advanced')
    types = js('return Array.from(document.querySelectorAll("#profile-type option"), el=>el.value)')
    for protocol in types:
        select('#profile-type', protocol)
        tabs = js('return Array.from(document.querySelectorAll("[data-profile-tab]"), el=>el.dataset.profileTab)')
        for tab in tabs:
            click('[data-profile-tab="' + tab + '"]')
            check(js('return document.querySelector("#profile-content").textContent.trim().length>0'), f'editor renders {protocol} / {tab}')
    select('#profile-type', 'vless')
    click('[data-profile-tab="transport"]')
    select('[data-field="transport.type"]', 'ws')
    fill('[data-field="transport.path"]', '/keep-websocket')
    fill('[data-field="transport.headers"]', '{invalid')
    select('[data-field="transport.type"]', 'grpc')
    fill('[data-field="transport.service_name"]', 'grpc-service')
    select('[data-field="transport.type"]', 'ws')
    check(js('return document.querySelector(arguments[0]).value', '[data-field="transport.path"]') == '/keep-websocket', 'switching transport restores WebSocket values')
    check(js('return document.querySelector(arguments[0]).value', '[data-field="transport.headers"]') == '{invalid', 'switching transport retains incomplete JSON input')
    fill('[data-field="transport.headers"]', '{"Host":["example.test"]}')
    click('[data-profile-tab="json"]')
    config = json.loads(js('return document.querySelector("#profile-json").value'))
    check('service_name' not in config['transport'], 'WebSocket configuration excludes gRPC-only fields')
    click('.modal-head .icon-button')
    check(js('return !!document.querySelector(".editor-discard")'), 'unsaved editor changes are protected on close')
    click('.editor-discard .button.secondary')
    select('#profile-type', 'xrayvless')
    fill('#profile-name', 'Native XHTTP')
    fill('[data-field="settings.address"]', '127.0.0.1')
    fill('[data-field="settings.id"]', 'bf422fe4-1a5c-4b64-bc33-43c18a1b9dd1')
    click('[data-profile-tab="transport"]')
    select('[data-field="streamSettings.network"]', 'xhttp')
    fill('[data-field="streamSettings.xhttpSettings.path"]', '/native-test')
    select('[data-field="streamSettings.xhttpSettings.mode"]', 'stream-one')
    click('[data-profile-tab="tls"]')
    select('[data-field="streamSettings.security"]', 'reality')
    pair = command('generateWgKeys')
    reality_key = base64.urlsafe_b64encode(base64.b64decode(pair['publicKey'])).decode().rstrip('=')
    fill('[data-field="streamSettings.realitySettings.serverName"]', 'example.test')
    fill('[data-field="streamSettings.realitySettings.fingerprint"]', 'chrome')
    fill('[data-field="streamSettings.realitySettings.password"]', reality_key)
    fill('[data-field="streamSettings.realitySettings.shortId"]', 'ab12')
    click('[data-profile-tab="transport"]')
    check(js('return document.querySelector(arguments[0]).value', '[data-field="streamSettings.xhttpSettings.path"]') == '/native-test', 'XHTTP fields survive switching TLS tabs')
    check(js('return document.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight'), 'long editor keeps action buttons visible')
    screenshot('editor-xhttp-en')
    click('.modal-footer .button.secondary')
    wait_for('return !!document.querySelector(".desktop-success")')
    check(True, 'native XHTTP/Reality form validates against actual Xray')
    click('button[form="profile-editor"]')
    wait_for('return !document.querySelector("dialog")')
    xray = next(p for p in command('snapshot')['profiles'] if p['name'] == 'Native XHTTP')
    actual = command('profile', {'id': xray['id']})['config']
    check(actual['streamSettings']['realitySettings']['password'] == reality_key, 'Xray key saved by structured editor')

    click('.add-connection'); click('#add-choice-advanced')
    select('#profile-type', 'amneziawg')
    fill('#profile-name', 'Native AWG')
    fill('[data-field="address"]', '10.44.0.2/32')
    click('.editor-keygen .button')
    wait_for('return !!document.querySelector(".editor-keygen input[readonly]")')
    own_public_key = js('return document.querySelector(".editor-keygen input[readonly]").value')
    check(len(base64.b64decode(own_public_key)) == 32, 'WireGuard key generation uses the real core')
    click('[data-profile-tab="peers"]')
    click('#profile-content > .button')
    fill('[data-field="peers.0.address"]', '127.0.0.1')
    fill('[data-field="peers.0.public_key"]', pair['publicKey'])
    click('[data-profile-tab="amnezia"]')
    fill('[data-field="amnezia_wg.h1"]', '1-100')
    fill('[data-field="amnezia_wg.h2"]', '101-200')
    fill('[data-field="amnezia_wg.h3"]', '201-300')
    fill('[data-field="amnezia_wg.h4"]', '301-400')
    fill('[data-field="amnezia_wg.rekey_after_time"]', '100-110')
    click('.modal-footer .button.secondary')
    wait_for('return !!document.querySelector(".desktop-success")')
    check(True, 'native AWG fields validate with WireGuard endpoint')
    click('[data-profile-tab="json"]')
    raw = json.loads(js('return document.querySelector("#profile-json").value'))
    raw['amnezia_wg']['future_option'] = 7
    fill('#profile-json', json.dumps(raw))
    click('[data-profile-tab="amnezia"]')
    fill('[data-field="amnezia_wg.rekey_after_time"]', '120-110')
    click('button[form="profile-editor"]')
    check(js('return !!document.querySelector("dialog") && !!document.querySelector("[aria-invalid=true]")'), 'invalid AWG interval cannot be saved')
    click('[data-profile-tab="peers"]')
    click('[data-profile-tab="amnezia"]')
    check(js('return document.querySelector(arguments[0]).value', '[data-field="amnezia_wg.rekey_after_time"]') == '120-110', 'invalid field input survives tab navigation')
    fill('[data-field="amnezia_wg.rekey_after_time"]', '110-120')
    click('[data-profile-tab="peers"]')
    check(js('return document.querySelector(arguments[0]).value', '[data-field="peers.0.address"]') == '127.0.0.1', 'peer fields survive AWG and JSON tabs')
    click('[data-profile-tab="amnezia"]')
    screenshot('editor-awg-en')
    click('button[form="profile-editor"]')
    wait_for('return !document.querySelector("dialog")')
    awg_profile = next(p for p in command('snapshot')['profiles'] if p['name'] == 'Native AWG')
    actual = command('profile', {'id': awg_profile['id']})['config']
    check(actual['amnezia_wg']['future_option'] == 7, 'editing known fields preserves unknown AWG parameters')
    check(actual['amnezia_wg']['rekey_after_time'] == '110-120', 'AWG range retains string representation')
    check(len(base64.b64decode(actual['private_key'])) == 32, 'generated private key survives native persistence')

    # Snapshot contains metadata only; the explicit editor fetch retains complete AWG JSON.
    awg = {'type': 'wireguard', 'private_key': 'sentinel-only-not-a-real-key', 'amnezia_wg': {'h1': '10-20', 'random_trailers': True, 'future_option': 7}, 'peers': []}
    awg_id = command('saveProfile', {'name': 'AWG roundtrip', 'kind': 'sing-box-outbound', 'groupId': 'personal', 'config': awg})['id']
    check(command('profile', {'id': awg_id})['config'] == awg, 'all AWG fields survive native persistence')
    check('sentinel-only' not in json.dumps(command('snapshot')), 'profile list does not receive private key')
    check(js('return Object.keys(localStorage).length===0'), 'webview localStorage is not used for credentials')

    # Real batch import: review, selection, group choice, core validation and atomic persistence.
    command('addGroup', {'name': 'Imported profiles'})
    import_group = next(g['id'] for g in command('snapshot')['groups'] if g['name'] == 'Imported profiles')
    wait_for('return document.querySelector(".group-strip select").options.length===3')
    select('.group-strip select', import_group)
    click('.add-connection'); click('#add-choice-link')
    check(js('return document.querySelector("#import-group").value') == import_group, 'import defaults to the current group')
    fill('#import-source', 'socks5://user:password@127.0.0.1:1080#Imported%20SOCKS\nunsupported://secret@host\nvless://bf422fe4-1a5c-4b64-bc33-43c18a1b9dd1@127.0.0.1:443?security=tls#Unselected')
    click('#import-review')
    check(js('return document.querySelectorAll("[data-import-row]").length') == 3, 'import review retains both valid and invalid lines')
    check(js('return document.querySelectorAll("[data-import-row]")[1].textContent.includes("not supported")'), 'import reports the unsupported line')
    click('[data-import-row="3"] .import-select')
    fill('[data-import-row="1"] .import-name', 'Imported SOCKS renamed')
    click('[data-import-check="1"]')
    wait_for('return !!document.querySelector(".import-valid")')
    check(True, 'import preview validates a real configuration with core')
    screenshot('import-review-en')
    before_import = len(command('snapshot')['profiles'])
    click('#import-save')
    wait_for('return !document.querySelector("dialog")')
    imported = command('snapshot')
    check(len(imported['profiles']) == before_import + 1, 'only the selected import entry is saved')
    imported_profile = next(p for p in imported['profiles'] if p['name'] == 'Imported SOCKS renamed')
    check(imported_profile['groupId'] == import_group, 'import saves the chosen destination group')
    check(command('profile', {'id': imported_profile['id']})['config']['password'] == 'password', 'imported credentials survive native storage')
    check(imported['running'] is None, 'import does not start a connection')
    select('.group-strip select', 'all')
    click('.add-connection'); click('#add-choice-link')
    wg_source = '[Interface]\nPrivateKey = ' + actual['private_key'] + '\nAddress = 10.44.0.2/32\nDNS = 1.1.1.1\nJc = 3\nJmin = 40\nJmax = 70\n[Peer]\nPublicKey = ' + actual['peers'][0]['public_key'] + '\nEndpoint = [::1]:51820\nAllowedIPs = 0.0.0.0/0\n'
    click('#import-tab-file')
    # The same HTML file input used by a user; dispatch a File because WebKit's upload command is unavailable.
    js("const input=document.querySelector('#import-file');const transfer=new DataTransfer();transfer.items.add(new File([arguments[0]],'Imported AWG.conf',{type:'text/plain'}));input.files=transfer.files;input.dispatchEvent(new Event('change',{bubbles:true}));", wg_source)
    wait_for('return !!document.querySelector(".import-read-success")')
    click('#import-review')
    check(js('return document.querySelector("#import-save").disabled'), 'unapplied WireGuard DNS directive requires review')
    check(js('return document.querySelector(".import-warnings").textContent.includes("DNS")'), 'unapplied directive is identified by name')
    click('#import-acknowledge')
    click('[data-import-check="1"]')
    wait_for('return !!document.querySelector(".import-valid")')
    check(True, 'imported AWG file passes real core validation')
    click('#import-save')
    wait_for('return !document.querySelector("dialog")')
    imported_awg = next(p for p in command('snapshot')['profiles'] if p['name'] == 'Imported AWG')
    check(command('profile', {'id': imported_awg['id']})['config']['peers'][0]['address'] == '::1', 'file import persists the IPv6 peer')
    request('POST', base + '/refresh', {})
    wait_for('return Array.from(document.querySelectorAll(".row-server-info strong")).some(el=>el.textContent.includes("Imported AWG"))')
    check(True, 'imported profiles survive a webview reload')
    check(js('return Object.keys(localStorage).length===0'), 'import does not persist credentials in localStorage')

    # Routing page uses saved models and actual core validation; no demonstration rules.
    click('.primary-nav button:nth-child(2)')
    wait_for('return !!document.querySelector("#route-profile-select")')
    check(command('routing')['profiles'][0]['rules'] == [], 'routing starts without fabricated rules')
    click('#route-add-rule')
    fill('#rule-name', 'Native route')
    fill('[data-route-field="domain_suffix"]', 'example.test')
    click('#rule-add-condition')
    select('[data-route-condition="1"]', 'process_name')
    fill('[data-route-field="process_name"]', 'firefox')
    select('.route-rule-modal .route-target', 'direct')
    click('.route-advanced summary')
    fill('[data-route-field="override_port"]', '70000')
    select('#rule-action', 'reject')
    select('#rule-action', 'route')
    check(js('return document.querySelector(arguments[0]).value', '[data-route-field="override_port"]') == '70000', 'switching rule actions retains invalid unfinished input')
    click('#rule-save')
    check(js('return !!document.querySelector("dialog") && !!document.querySelector("[aria-invalid=true]")'), 'invalid rule action value blocks saving')
    fill('[data-route-field="override_port"]', '')
    select('#rule-action', 'bypass')
    check(js("return !!document.querySelector('[data-route-field=override_port]') && !document.querySelector('[data-route-field=bind_interface]')"), 'bypass offers route options supported by the core')
    select('#rule-action', 'route')
    wait_for('return document.querySelector("#rule-action").value==="route" && document.querySelector(".route-rule-modal .route-target").value==="direct"')
    screenshot('routing-rule-editor-en')
    click('#rule-save')
    wait_for('return !document.querySelector("dialog") && document.querySelectorAll("[data-edit-rule]").length===1')
    routing = command('routing')
    rule_id = routing['profiles'][0]['rules'][0]['id']
    check(routing['profiles'][0]['rules'][0]['config']['process_name'] == ['firefox'], 'structured routing saves multiple typed conditions')
    check(routing['profiles'][0]['rules'][0]['config']['action'] == 'route' and routing['profiles'][0]['rules'][0]['config']['outbound'] == 'direct', 'switching rule actions restores and saves the chosen destination')
    click('#route-local')
    click('#rule-save')
    wait_for('return !document.querySelector("dialog") && document.querySelectorAll("[data-edit-rule]").length===2')
    local_rule = command('routing')['profiles'][0]['rules'][-1]
    click('[data-rule-up="' + local_rule['id'] + '"]')
    wait_for('return document.querySelector("[data-edit-rule]").dataset.editRule===' + json.dumps(local_rule['id']))
    check(command('routing')['profiles'][0]['rules'][0]['id'] == local_rule['id'], 'routing priority changes in native storage')
    click('[data-toggle-rule="' + rule_id + '"]')
    wait_for('return Array.from(document.querySelectorAll("[data-toggle-rule]")).some(el=>el.dataset.toggleRule===' + json.dumps(rule_id) + '&&el.getAttribute("aria-pressed")=="false")')
    check(not command('routing')['profiles'][0]['rules'][1]['enabled'], 'routing switch disables the stored rule')
    click('[data-route-tab="simple"]')
    fill('#simple-rules', 'suffix:local.test\nprocessName:terminal')
    click('#route-json-save')
    wait_for('return !document.querySelector("#route-json-save").disabled')
    check(len(command('routing')['profiles'][0]['rules']) == 4, 'simple routing list adds entries without replacing custom rules')
    fill('#simple-rules', 'badprefix:example.test')
    click('#route-json-save')
    wait_for('return !!document.querySelector(".desktop-inline-error")')
    check(len(command('routing')['profiles'][0]['rules']) == 4, 'invalid simple list leaves routing unchanged')
    fill('#simple-rules', 'suffix:local.test\nprocessName:terminal')
    click('[data-route-tab="dns"]')
    click('#dns-add-server')
    select('#resource-type', 'hosts')
    fill('#resource-tag', 'native-hosts')
    fill('#resource-predefined', 'resource.test 127.0.0.1')
    click('#resource-check')
    wait_for('return !!document.querySelector(".resource-modal .resource-notice")')
    check(True, 'structured hosts entries validate through the real core')
    screenshot('dns-hosts-editor-en')
    click('#resource-save')
    wait_for('return !document.querySelector("dialog")')
    dns_resource = command('routing')['profiles'][0]['dns']
    check(dns_resource['servers'][1]['predefined'] == {'resource.test': ['127.0.0.1']}, 'hosts form saves real addresses')
    check(dns_resource['rules'][0]['preferred_by'] == ['native-hosts'], 'hosts creation installs a matching DNS rule')
    click('[data-resource-edit="server:1"]')
    fill('#resource-tag', 'renamed-hosts')
    click('#resource-save')
    wait_for('return !document.querySelector("dialog")')
    check(command('routing')['profiles'][0]['dns']['rules'][0]['server'] == 'renamed-hosts', 'renaming a DNS server repairs its DNS rules')
    click('[data-resource-delete="server:1"]')
    click('#resource-delete-confirm')
    wait_for('return !!document.querySelector("dialog [role=alert]")')
    check(len(command('routing')['profiles'][0]['dns']['servers']) == 2, 'referenced DNS server cannot be deleted')
    click('.modal-head .icon-button')
    click('#dns-options')
    click('[data-resource-tab="cache"]')
    fill('#resource-cache_capacity', '768')
    select('#resource-optimistic-enabled', 'true')
    fill('#resource-optimistic-timeout', '20s')
    click('#resource-save')
    wait_for('return !document.querySelector("dialog")')
    check(command('routing')['profiles'][0]['dns']['cache_capacity'] == 768, 'structured DNS cache options persist')
    check(command('routing')['profiles'][0]['dns']['optimistic'] == {'enabled': True, 'timeout': '20s'}, 'optimistic cache serializes its object options')
    click('#dns-add-server')
    select('#resource-type', 'https')
    fill('#resource-tag', 'draft-https')
    fill('#resource-server', '127.0.0.1')
    click('[data-resource-tab="tls"]')
    fill('#resource-headers', '{unfinished')
    click('[data-resource-tab="main"]')
    select('#resource-type', 'udp')
    fill('#resource-tag', 'shared-name')
    select('#resource-type', 'https')
    check(js('return document.querySelector("#resource-tag").value') == 'shared-name', 'changing DNS type keeps the latest shared name')
    click('[data-resource-tab="tls"]')
    check(js('return document.querySelector("#resource-headers").value') == '{unfinished', 'unfinished HTTP headers survive DNS type switches')
    click('#resource-save')
    check(bool(js('return document.querySelector("dialog [role=alert]")')), 'invalid DNS fields block saving')
    click('.modal-head .icon-button')
    check(bool(js('return document.querySelector("#resource-discard")')), 'closing a modified DNS editor requires discarding its draft')
    click('#resource-discard')
    click('#dns-add-server')
    select('#resource-type', 'fakeip')
    fill('#resource-tag', 'native-fake')
    click('#resource-save')
    wait_for('return !document.querySelector("dialog")')
    dns_resource = command('routing')['profiles'][0]['dns']
    check(dns_resource['servers'][-1]['inet4_range'] == '198.18.0.0/15' and dns_resource['rules'][-1]['server'] == 'native-fake', 'FakeIP form saves ranges and a final A / AAAA rule')
    click('[data-resource-delete="rule:1"]')
    click('#resource-delete-confirm')
    wait_for('return !document.querySelector("dialog")')
    click('[data-resource-delete="server:2"]')
    click('#resource-delete-confirm')
    wait_for('return !document.querySelector("dialog")')
    check(len(command('routing')['profiles'][0]['dns']['servers']) == 2, 'unused DNS server can be removed after its rule')
    click('#dns-add-rule')
    fill('#resource-domain_suffix', 'blocked.test')
    click('[data-resource-tab="action"]')
    select('#resource-action', 'predefined')
    fill('#resource-answer', 'blocked.test. 60 IN A 127.0.0.2')
    select('#resource-action', 'reject')
    select('#resource-action', 'predefined')
    check(js('return document.querySelector("#resource-answer").value') == 'blocked.test. 60 IN A 127.0.0.2', 'DNS action switches restore separate parameter drafts')
    select('#resource-action', 'reject')
    click('#resource-save')
    wait_for('return !document.querySelector("dialog")')
    check(command('routing')['profiles'][0]['dns']['rules'][-1] == {'domain_suffix': ['blocked.test'], 'action': 'reject'}, 'DNS rule save omits parameters from a different action')
    click('[data-dns-rule-up="1"]')
    wait_for('return !document.querySelector("#dns-add-rule").disabled')
    check(command('routing')['profiles'][0]['dns']['rules'][0]['action'] == 'reject', 'DNS rule order changes in native storage')
    click('#dns-resolve-domains')
    wait_for('return !document.querySelector("#dns-add-rule").disabled')
    check(command('routing')['profiles'][0]['rules'][0]['config'] == {'action': 'resolve'}, 'DNS helper adds an explicit resolve rule before routing')
    command('connect', {'id': saved['id']})
    with socket.socket() as origin:
        origin.settimeout(5)
        origin.bind(('127.0.0.1', 0))
        origin.listen()
        address = 'resource.test:' + str(origin.getsockname()[1])
        with socket.create_connection(('127.0.0.1', proxy_port), timeout=5) as client:
            client.sendall(f'CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n'.encode())
            upstream, _ = origin.accept()
            with upstream:
                check(b'200' in client.recv(1024), 'hosts entered in the DNS form resolve a real proxy connection')
                client.sendall(b'dns-form-test')
                check(upstream.recv(1024) == b'dns-form-test', 'form-generated DNS and routing forward real bytes')
    command('disconnect')
    click('[data-route-tab="rules"]')
    resolve_id = command('routing')['profiles'][0]['rules'][0]['id']
    click(f'[data-delete-rule="{resolve_id}"]')
    click('#route-delete-confirm')
    wait_for('return !document.querySelector("dialog")')
    click('[data-route-tab="sets"]')
    click('#ruleset-add')
    select('#resource-type', 'inline')
    fill('#resource-tag', 'native-set')
    fill('#resource-rules', '[{"domain_suffix":["example.test"]}]')
    click('#resource-save')
    wait_for('return !document.querySelector("dialog")')
    check(command('routing')['profiles'][0]['route']['rule_set'][0]['rules'] == [{'domain_suffix': ['example.test']}], 'structured inline rule set passes core validation and saves')
    click('[data-route-tab="dns"]')
    click('#dns-add-rule')
    fill('#resource-rule_set', 'native-set')
    click('#resource-save')
    wait_for('return !document.querySelector("dialog")')
    click('[data-route-tab="sets"]')
    click('[data-resource-edit="set:0"]')
    fill('#resource-tag', 'renamed-set')
    click('#resource-save')
    wait_for('return !document.querySelector("dialog")')
    check(command('routing')['profiles'][0]['dns']['rules'][-1]['rule_set'] == ['renamed-set'], 'renaming a rule set repairs DNS references')
    click('[data-resource-delete="set:0"]')
    click('#resource-delete-confirm')
    wait_for('return !!document.querySelector("dialog [role=alert]")')
    check(len(command('routing')['profiles'][0]['route']['rule_set']) == 1, 'rule-set deletion protects DNS references')
    click('.modal-head .icon-button')
    screenshot('rule-sets-en')
    click('[data-route-tab="dns"]')
    screenshot('dns-servers-en')
    click('[data-resource-view="json"]')
    fill('#route-json', '{unfinished')
    click('[data-route-tab="rules"]')
    click('[data-route-tab="dns"]')
    click('[data-resource-view="json"]')
    check(js('return document.querySelector("#route-json").value') == '{unfinished', 'unfinished DNS JSON survives page-tab switches')
    click('[data-resource-view="fields"]')
    check(bool(js('return document.querySelector("#resource-json-discard")')), 'switching from edited DNS JSON to forms protects unsaved input')
    click('#resource-json-discard')
    click('[data-resource-view="json"]')
    dns = {'servers': [{'type': 'local', 'tag': 'dns-direct'}, {'type': 'hosts', 'tag': 'test-hosts', 'predefined': {'routing.test': '127.0.0.1'}}], 'final': 'dns-direct', 'cache_capacity': 512}
    fill('#route-json', json.dumps(dns))
    click('#route-json-save')
    wait_for('return !document.querySelector("#route-json-save").disabled')
    check(command('routing')['profiles'][0]['dns'] == dns, 'DNS and hosts settings persist after real core validation')
    click('[data-route-tab="sets"]')
    click('[data-resource-view="json"]')
    rule_sets = [{'type': 'inline', 'tag': 'native-set', 'rules': [{'domain_suffix': ['blocked.test']}]}]
    fill('#route-json', json.dumps(rule_sets))
    click('#route-json-save')
    wait_for('return !document.querySelector("#route-json-save").disabled')
    check(command('routing')['profiles'][0]['route']['rule_set'] == rule_sets, 'rule-set JSON is validated and persisted')
    click('[data-route-tab="raw"]')
    before_route = command('routing')
    fill('#route-json', '{invalid')
    click('#route-json-save')
    check(command('routing') == before_route, 'invalid routing JSON cannot change stored state')
    click('#route-profiles')
    fill('#route-profile-name', 'Work routing')
    click('#route-profile-save')
    wait_for('return document.querySelector("#route-profile-name").value===""')
    work_route = next(p for p in command('routing')['profiles'] if p['name'] == 'Work routing')
    click('.modal-footer .button.primary')
    select('#route-profile-select', work_route['id'])
    wait_for('return !document.querySelector("#route-profile-select").disabled')
    check(command('routing')['active'] == work_route['id'], 'routing profile selection persists')
    click('[data-route-tab="rules"]')
    check(js('return document.querySelectorAll("[data-edit-rule]").length') == 0, 'routing profile has its own isolated rule list')
    command('connect', {'id': saved['id']})
    click('[data-routing-mode="direct"]')
    wait_for('return !!document.querySelector("#route-apply")')
    check(command('snapshot')['routing']['pending'], 'saved routing changes are marked pending during a live connection')
    click('#route-apply')
    wait_for('return !document.querySelector("#route-apply")')
    check(not command('snapshot')['routing']['pending'] and command('snapshot')['running'] == saved['id'], 'Apply reconnects the same profile with the saved routing')
    command('disconnect')
    select('#route-profile-select', 'default')
    wait_for('return !document.querySelector("#route-profile-select").disabled')
    click('[data-route-tab="rules"]')
    screenshot('routing-rules-en')
    request('POST', base + '/refresh', {})
    wait_for('return !!document.querySelector(".add-connection")')
    click('.primary-nav button:nth-child(2)')
    wait_for('return !!document.querySelector("#route-profile-select")')
    check(len(command('routing')['profiles'][0]['rules']) == 4, 'routing data survives a webview reload')
    request('POST', base + '/window/rect', {'width': 390, 'height': 844})
    check(js('return document.documentElement.scrollWidth<=innerWidth'), 'routing page fits a narrow native window')
    click('#route-add-rule')
    check(js('return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth'), 'routing editor fits a narrow native window')
    screenshot('routing-editor-narrow')
    click('.modal-head .icon-button')
    click('[data-route-tab="dns"]')
    check(js('return document.documentElement.scrollWidth<=innerWidth'), 'DNS forms fit a narrow native window')
    click('#dns-add-server')
    select('#resource-type', 'hosts')
    check(js('return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth'), 'DNS resource editor fits a narrow native window')
    check(js('return document.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight'), 'narrow DNS editor keeps its save button visible')
    screenshot('dns-editor-narrow')
    click('.modal-head .icon-button')
    click('#resource-discard')

    click('.primary-nav button:nth-child(1)')

    request('POST', base + '/window/rect', {'width': 768, 'height': 900})
    check(js('return document.documentElement.scrollWidth<=innerWidth'), 'native webview at tablet width has no page overflow')
    request('POST', base + '/window/rect', {'width': 390, 'height': 844})
    check(js('return document.documentElement.scrollWidth<=innerWidth'), 'native webview at narrow width has no page overflow')
    click('.add-connection'); click('#add-choice-advanced')
    check(js('return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth'), 'editor fits narrow native window')
    check(js('return document.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight'), 'narrow editor keeps action buttons visible')
    screenshot('editor-narrow')
    click('.modal-head .icon-button')
    click('.add-connection'); click('#add-choice-link')
    fill('#import-source', 'socks://127.0.0.1:1080#Narrow%20import')
    click('#import-review')
    check(js('return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth'), 'import preview fits the narrow native window')
    check(js('return document.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight'), 'narrow import keeps save and cancel visible')
    screenshot('import-narrow')
    click('.modal-head .icon-button')
    request('POST', base + '/window/rect', {'width': 1280, 'height': 860})
    click('.desktop-language')
    wait_for('return document.documentElement.lang==="ru"')
    click('.topbar-actions .icon-button')
    wait_for('return document.documentElement.dataset.theme==="light"')
    screenshot('connection-light-ru')
    click('.primary-nav button:nth-child(2)')
    wait_for('return !!document.querySelector("#route-profile-select")')
    check(js('return document.querySelector("#route-add-rule").textContent.includes("Добавить правило")'), 'routing page uses Russian labels')
    screenshot('routing-rules-ru')
    click('[data-route-tab="dns"]')
    check(js('return document.querySelector("#dns-add-server").textContent.includes("Добавить сервер")'), 'DNS resource page uses Russian labels')
    screenshot('dns-servers-ru')
    click('#dns-options')
    click('[data-resource-tab="cache"]')
    check(js('return document.querySelector(".editor-content").textContent.includes("Записей в кэше")'), 'DNS cache editor uses Russian labels')
    click('.modal-head .icon-button')

    click('.primary-nav button:nth-child(1)')
    click('.add-connection'); click('#add-choice-link')
    check(js('return document.querySelector("#modal-title").textContent') == 'Новое подключение', 'unified add dialog uses Russian labels')
    check(js('return !!document.querySelector("#import-tab-file")&&!document.querySelector("#import-file")'), 'file import is available on its own tab without an extra native button')
    check(js('const s=document.querySelector("#import-source");return s.getBoundingClientRect().height>=90 && s.getBoundingClientRect().height<=110 && getComputedStyle(s).resize==="vertical"'), 'compact import source remains readable and can be resized vertically')
    screenshot('import-source-ru')
    click('.modal-head .icon-button')
    from modals_ui import run as run_modals
    run_modals(globals())
    from subscription_ui import run
    run(globals())
    from grouped_library_ui import run as run_groups
    run_groups(globals())
    from subscription_queue_ui import run as run_queue
    run_queue(globals())
    from probes_ui import run as run_probes
    run_probes(globals())
    from tun_ui import run as run_tun
    run_tun(globals())
    from connection_ui import run as run_connection
    run_connection(globals())
    from system_proxy_ui import run as run_system_proxy
    run_system_proxy(globals())
    from bulk_ui import run as run_bulk
    run_bulk(globals())
    from transfer_ui import run as run_transfer
    run_transfer(globals())
    from logs_ui import run as run_logs
    run_logs(globals())
    from chains_ui import run as run_chains
    run_chains(globals())
    from library_ui import run as run_library
    run_library(globals())
    from selectors_ui import run as run_selectors
    run_selectors(globals())
    from backups_ui import run as run_backups
    run_backups(globals())
    from tray_ui import run as run_tray
    run_tray(globals())
    from instance_ui import run as run_instance
    run_instance(globals())
    command('connect', {'id': saved['id']})
    from window_ui import close as close_window
    close_window(globals(), proxy_port)
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        with socket.socket() as probe:
            if probe.connect_ex(('127.0.0.1', proxy_port)) != 0:
                break
        time.sleep(.1)
    else:
        raise AssertionError('Local proxy stayed open after application exit')
    check(True, 'closing native window stops the core and closes its proxy port')
    (artifacts / 'results.json').write_text(json.dumps({'checks': checks, 'count': len(checks), 'backend': 'real Tauri + ThroneCore', 'network': 'loopback only'}, ensure_ascii=False, indent=2))
    print('TOTAL', len(checks))
finally:
    if not closed_session:
        try:
            if not args.live_subscription_file and not args.groups_live_file:
                screenshot('failure')
        except Exception:
            pass
        request('DELETE', base)
