#!/usr/bin/env python3
"""Start an isolated Linux WebKitGTK driver and exercise the real application."""
import argparse
import http.client
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

desktop = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--artifacts', default=str(desktop / 'test-results/native'))
parser.add_argument('--application', help='Use a preserved test build')
parser.add_argument('--subscriptions-only', action='store_true')
parser.add_argument('--legacy-endpoints-only', action='store_true')
parser.add_argument('--subscription-happ-only', action='store_true')
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
parser.add_argument('--private-tray-bus', action='store_true', help='Isolate the session bus for tray host lifecycle fixtures')
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
parser.add_argument('--live-subscription-file', help='Opt-in live check: read the URL from a private file, omit credentials from reports')
args = parser.parse_args()
(pathlib.Path(args.artifacts) / 'results.json').unlink(missing_ok=True)
for name in ('tauri-driver', 'WebKitWebDriver'):
    if not shutil.which(name):
        raise SystemExit(f'{name} is required; see docs/DEVELOPMENT.md')
if not os.environ.get('DISPLAY'):
    raise SystemExit('A running X display is required. Run inside xvfb-run on headless Linux.')


def port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


with tempfile.TemporaryDirectory(prefix='thronium-native-test-') as directory:
    root = pathlib.Path(directory)
    driver_port, native_port = port(), port()
    while native_port == driver_port:
        native_port = port()
    url = f'http://127.0.0.1:{driver_port}'
    env = {**os.environ, 'XDG_DATA_HOME': str(root / 'data'), 'XDG_CONFIG_HOME': str(root / 'config'),
           'XDG_CACHE_HOME': str(root / 'cache'), 'GDK_BACKEND': 'x11',
           'MESA_SHADER_CACHE_DISABLE': 'true',
           'GSETTINGS_BACKEND': 'keyfile', 'XDG_CURRENT_DESKTOP': 'GNOME'}
    if args.kde_proxy_only:
        (root / 'config-defaults').mkdir()
        env.update(XDG_CURRENT_DESKTOP='KDE', KDE_SESSION_VERSION='6', XDG_CONFIG_DIRS=str(root / 'config-defaults'))
    private_bus = None
    # Use the display session's live accessibility bus, rather than a stale
    # X11 root-window address or a daemon activated with disposable XDG paths.
    from gi.repository import Gio
    display_bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
    env['AT_SPI_BUS_ADDRESS'] = display_bus.call_sync('org.a11y.Bus', '/org/a11y/bus', 'org.a11y.Bus', 'GetAddress', None, None, Gio.DBusCallFlags.NONE, 2000, None).unpack()[0]
    owned_bus = env.get('_THRONIUM_TEST_BUS')
    if args.private_tray_bus and not (owned_bus and owned_bus == env.get('DBUS_SESSION_BUS_ADDRESS')):
        # Share only accessibility with the display session. Activating another
        # at-spi daemon from a private D-Bus is blocked on some SELinux desktops.
        address = 'unix:path=' + str(root / 'session-bus')
        private_bus = subprocess.Popen(['dbus-daemon', '--session', '--nofork', '--print-address=1', '--address=' + address], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if not private_bus.stdout.readline().strip():
            raise RuntimeError('Private session bus did not start')
        env.update(DBUS_SESSION_BUS_ADDRESS=address, _THRONIUM_TEST_BUS=address)
    dconf_fixture = None
    if os.environ.get('_THRONIUM_PROXY_BACKEND') == 'dconf':
        assert args.system_proxy_only, 'The private dconf fixture is scoped to --system-proxy-only'
        sys.path.insert(0,str(desktop/'tests'))
        from private_dconf_fixture import PrivateDconf
        dconf_fixture=PrivateDconf(root,env,args.artifacts)
    diagnostics_fixture = None
    country_cleanup = None
    if args.selector_subscription_only or args.selector_rebuild_only or args.selector_preflight_only or args.diagnostics_only or args.selector_country_only or args.selector_ranking_only or args.selector_warm_only or args.selector_history_only or args.selector_limit_only or args.selector_pool_cap_only or args.selector_measurements_only or args.selector_saved_order_only or args.selector_health_only:
        sys.path.insert(0,str(desktop/'tests'))
        if args.selector_subscription_only or args.selector_rebuild_only or args.selector_preflight_only or args.selector_measurements_only or args.selector_warm_only or args.selector_health_only:
            from selector_warm_fixture import Fixture
        elif args.selector_ranking_only or args.selector_limit_only or args.selector_pool_cap_only or args.selector_saved_order_only:
            from selector_ranking_fixture import Fixture
        elif args.selector_country_only or args.selector_history_only or args.selector_limit_only or args.selector_pool_cap_only or args.selector_saved_order_only:
            from selector_country_fixture import Fixture
        else:
            from diagnostics_fixture import Fixture
        diagnostics_fixture=Fixture(root/'diagnostics')
        env.update(SSL_CERT_FILE=str(diagnostics_fixture.cert),_THRONIUM_DIAGNOSTICS_FIXTURE=str(diagnostics_fixture.path))
    qr_fixture = None
    if args.qr_only:
        if not args.private_tray_bus: raise RuntimeError('Use --qr-only --private-tray-bus')
        env['_THRONIUM_QR_FIXTURE'] = str(root / 'qr-portal')
        qr_fixture = subprocess.Popen([sys.executable, str(desktop / 'tests/qr_portal_fixture.py'), env['_THRONIUM_QR_FIXTURE']], env=env, stdout=subprocess.PIPE, text=True)
        if qr_fixture.stdout.readline().strip() != 'ready': raise RuntimeError('Private QR portal did not start')
    with (root / 'driver.log').open('w+') as log:
        driver = subprocess.Popen(['tauri-driver', '--native-driver', shutil.which('WebKitWebDriver'),
                                   '--port', str(driver_port), '--native-port', str(native_port)],
                                  env=env, stdout=log, stderr=log)
        try:
            for _ in range(100):
                if driver.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(log.read())
                try:
                    with urllib.request.urlopen(url + '/status', timeout=1):
                        break
                except (urllib.error.URLError, http.client.HTTPException, TimeoutError):
                    time.sleep(.1)
            else:
                raise RuntimeError('WebDriver did not start')
            subprocess.run([sys.executable, str(desktop / 'tests/native_smoke.py'), '--driver', url,
                            '--artifacts', args.artifacts] + (['--application', args.application] if args.application else []) + (['--subscriptions-only'] if args.subscriptions_only else []) + (['--legacy-endpoints-only'] if args.legacy_endpoints_only else []) + (['--subscription-happ-only'] if args.subscription_happ_only else []) + (['--queue-only'] if args.queue_only else []) + (['--probes-only'] if args.probes_only else []) + (['--periodic-probes-only'] if args.periodic_probes_only else []) + (['--vpn-probes-only'] if args.vpn_probes_only else []) + (['--profile-order-only'] if args.profile_order_only else []) + (['--profile-edit-only'] if args.profile_edit_only else []) + (['--ws-early-data-only'] if args.ws_early_data_only else []) + (['--httpupgrade-early-data-only'] if args.httpupgrade_early_data_only else []) + (['--bulk-only'] if args.bulk_only else []) + (['--transfer-only'] if args.transfer_only else []) + (['--share-only'] if args.share_only else []) + (['--archive-export-only'] if args.archive_export_only else []) + (['--resources-only'] if args.resources_only else []) + (['--legacy-backup-only'] if args.legacy_backup_only else []) + (['--legacy-icons-only'] if args.legacy_icons_only else []) + (['--legacy-local-resources-only'] if args.legacy_local_resources_only else []) + (['--routing-source-only'] if args.routing_source_only else []) + (['--legacy-wg-only'] if args.legacy_wg_only else []) + (['--wireguard-live-only'] if args.wireguard_live_only else []) + (['--wireguard-topology-only'] if args.wireguard_topology_only else []) + (['--awg-live-only'] if args.awg_live_only else []) + (['--awg-migration-only'] if args.awg_migration_only else []) + (['--legacy-selector-only'] if args.legacy_selector_only else []) + (['--selector-export-only'] if args.selector_export_only else []) + (['--otp-only'] if args.otp_only else []) + (['--legacy-otp-only'] if args.legacy_otp_only else []) + (['--legacy-settings-only'] if args.legacy_settings_only else []) + (['--legacy-basic-settings-only'] if args.legacy_basic_settings_only else []) + (['--legacy-runtime-settings-only'] if args.legacy_runtime_settings_only else []) + (['--legacy-hotkeys-only'] if args.legacy_hotkeys_only else []) + (['--external-core-only'] if args.external_core_only else []) + (['--legacy-external-core-only'] if args.legacy_external_core_only else []) + (['--nested-routing-only'] if args.nested_routing_only else []) + (['--inline-ruleset-only'] if args.inline_ruleset_only else []) + (['--routing-resources-only'] if args.routing_resources_only else []) + (['--otp-migration-only'] if args.otp_migration_only else []) + (['--legacy-routing-only'] if args.legacy_routing_only else []) + (['--legacy-quic-dns-only'] if args.legacy_quic_dns_only else []) + (['--rfd-dialogs-only'] if args.rfd_dialogs_only else []) + (['--subscription-hwid-only'] if args.subscription_hwid_only else []) + (['--tray-catalog-only'] if args.tray_catalog_only else []) + (['--core-recovery-only'] if args.core_recovery_only else []) + (['--system-proxy-recovery-only'] if args.system_proxy_recovery_only else []) + (['--profile-tls-only'] if args.profile_tls_only else []) + (['--vpn-auth-only'] if args.vpn_auth_only else []) + (['--vpn-auth-managed-only'] if args.vpn_auth_managed_only else []) + (['--vpn-credentials-only'] if args.vpn_credentials_only else []) + (['--vpn-credentials-managed-only'] if args.vpn_credentials_managed_only else []) + (['--vpn-credentials-system-proxy-only'] if args.vpn_credentials_system_proxy_only else []) + (['--vpn-policy-only'] if args.vpn_policy_only else []) + (['--legacy-vpn-bindings-only'] if args.legacy_vpn_bindings_only else []) + (['--vpn-otp-binding-only'] if args.vpn_otp_binding_only else []) + (['--vpn-otp-layout-only'] if args.vpn_otp_layout_only else []) + (['--vpn-otp-binding-managed-only'] if args.vpn_otp_binding_managed_only else []) + (['--subscription-names-only'] if args.subscription_names_only else []) + (['--group-chains-only'] if args.group_chains_only else []) + (['--diagnostics-only'] if args.diagnostics_only else []) + (['--logs-only'] if args.logs_only else []) + (['--chains-only'] if args.chains_only else []) + (['--library-only'] if args.library_only else []) + (['--library-maintenance-only'] if args.library_maintenance_only else []) + (['--traffic-stats-only'] if args.traffic_stats_only else []) + (['--throne-directory-only'] if args.throne_directory_only else []) + (['--secrets-only'] if args.secrets_only else []) + (['--openvpn-pending-only'] if args.openvpn_pending_only else []) + (['--vpn-restart-only'] if args.vpn_restart_only else []) + (['--openconnect-cstp-only'] if args.openconnect_cstp_only else []) + (['--fakeip-batch-only'] if args.fakeip_batch_only else []) + (['--selectors-only'] if args.selectors_only else []) + (['--auto-select-simple-only'] if args.auto_select_simple_only else []) + (['--dynamic-selectors-only'] if args.dynamic_selectors_only else []) + (['--selector-country-only'] if args.selector_country_only else []) + (['--selector-ranking-only'] if args.selector_ranking_only else []) + (['--selector-warm-only'] if args.selector_warm_only else []) + (['--selector-history-only'] if args.selector_history_only else []) + (['--selector-limit-only'] if args.selector_limit_only else []) + (['--selector-pool-cap-only'] if args.selector_pool_cap_only else []) + (['--selector-saved-order-only'] if args.selector_saved_order_only else []) + (['--selector-measurements-only'] if args.selector_measurements_only else []) + (['--selector-preflight-only'] if args.selector_preflight_only else []) + (['--selector-subscription-only'] if args.selector_subscription_only else []) + (['--selector-rebuild-only'] if args.selector_rebuild_only else []) + (['--selector-health-only'] if args.selector_health_only else []) + (['--backups-only'] if args.backups_only else []) + (['--tray-only'] if args.tray_only else []) + (['--tray-routing-only'] if args.tray_routing_only else []) + (['--tray-otp-only'] if args.tray_otp_only else []) + (['--tray-controls-only'] if args.tray_controls_only else []) + (['--tray-system-only'] if args.tray_system_only else []) + (['--instance-only'] if args.instance_only else []) + (['--window-only'] if args.window_only else []) + (['--groups-only'] if args.groups_only else []) + (['--modals-only'] if args.modals_only else []) + (['--rules-only'] if args.rules_only else []) + (['--routing-catalog-only'] if args.routing_catalog_only else []) + (['--settings-only'] if args.settings_only else []) + (['--portable-only'] if args.portable_only else []) + (['--os-links-only'] if args.os_links_only else []) + (['--dashboard-only'] if args.dashboard_only else []) + (['--geodata-assets-only'] if args.geodata_assets_only else []) + (['--geodata-history-only'] if args.geodata_history_only else []) + (['--legacy-geodata-only'] if args.legacy_geodata_only else []) + (['--legacy-warp-only'] if args.legacy_warp_only else []) + (['--legacy-network-only'] if args.legacy_network_only else []) + (['--full-xray-probes-only'] if args.full_xray_probes_only else []) + (['--full-xray-diagnostics-only'] if args.full_xray_diagnostics_only else []) + (['--full-sing-diagnostics-only'] if args.full_sing_diagnostics_only else []) + (['--speedtest-full-only'] if args.speedtest_full_only else []) + (['--vpn-diagnostics-only'] if args.vpn_diagnostics_only else []) + (['--wireguard-diagnostics-only'] if args.wireguard_diagnostics_only else []) + (['--trusttunnel-only'] if args.trusttunnel_only else []) + (['--tun-endpoint-only'] if args.tun_endpoint_only else []) + (['--warp-registration-only'] if args.warp_registration_only else []) + (['--qr-only'] if args.qr_only else []) + (['--add-only'] if args.add_only else []) + (['--dropdown-only'] if args.dropdown_only else []) + (['--group-drag-only'] if args.group_drag_only else []) + (['--system-proxy-only'] if args.system_proxy_only else []) + (['--kde-proxy-only'] if args.kde_proxy_only else []) + (['--connection-only'] if args.connection_only else []) + (['--vless-only'] if args.vless_only else []) + (['--tun-only'] if args.tun_only else []) + (['--tun-reconnect-only'] if args.tun_reconnect_only else []) + (['--groups-live-file', args.groups_live_file] if args.groups_live_file else []) + (['--live-subscription-file', args.live_subscription_file] if args.live_subscription_file else []), check=True, timeout=360, env=env)
        finally:
            driver.terminate()
            try:
                driver.wait(timeout=5)
            except subprocess.TimeoutExpired:
                driver.kill()
                driver.wait()
            log.flush()
            artifacts = pathlib.Path(args.artifacts)
            artifacts.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / 'driver.log', artifacts / 'driver.log')
            if diagnostics_fixture:
                country_cleanup = diagnostics_fixture.close()
                if args.selector_subscription_only or args.selector_rebuild_only or args.selector_preflight_only or args.selector_country_only or args.selector_ranking_only or args.selector_warm_only or args.selector_history_only or args.selector_limit_only or args.selector_pool_cap_only or args.selector_measurements_only or args.selector_saved_order_only or args.selector_health_only:
                    import json
                    (artifacts/'country-fixture-cleanup.json').write_text(json.dumps(country_cleanup,indent=2)+'\n')
            if qr_fixture:
                qr_fixture.terminate(); qr_fixture.wait(timeout=5)
            if dconf_fixture:
                dconf_fixture.close()
            if private_bus:
                private_bus.terminate()
                private_bus.wait(timeout=5)

if args.selector_subscription_only or args.selector_rebuild_only or args.selector_preflight_only or args.selector_country_only or args.selector_ranking_only or args.selector_warm_only or args.selector_history_only or args.selector_limit_only or args.selector_pool_cap_only or args.selector_measurements_only or args.selector_saved_order_only or args.selector_health_only:
    assert country_cleanup and country_cleanup['serviceThreadsReaped'] and country_cleanup['serverSocketsClosed'] and country_cleanup['socketCount']==0 and country_cleanup['active']==0 and country_cleanup['streamCount']==0, country_cleanup
