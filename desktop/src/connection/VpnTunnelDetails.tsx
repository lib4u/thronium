import { formatDateTime } from '../shared/i18n/format.ts';
import type * as Wire from '../shared/api/generated/commands';
import { vpnText } from './vpnMessages';

/**
 * Qt's endpoint details: what the server told the core about the tunnel it
 * built. Every value comes from the server, so a row appears only when there is
 * something to show.
 */
export default function VpnTunnelDetails({ tunnel, language }: { tunnel: Wire.VpnTunnel; language: string }) {
  const t = (key: Parameters<typeof vpnText>[0]) => vpnText(key, language);
  const rows: [string, string][] = [
    [t('tunnel_server'), tunnel.server],
    [t('tunnel_network'), tunnel.network],
    [t('tunnel_cipher'), tunnel.cipher],
    [t('tunnel_mtu'), tunnel.mtu > 0 ? String(tunnel.mtu) : ''],
    [
      t('tunnel_since'),
      tunnel.connectedSince > 0 ? formatDateTime(tunnel.connectedSince * 1000, language) : '',
    ],
    [t('tunnel_ipv4'), tunnel.ipv4.join(', ')],
    [t('tunnel_ipv6'), tunnel.ipv6.join(', ')],
    [t('tunnel_routes'), tunnel.routes.join(', ')],
    [t('tunnel_excluded'), tunnel.excludedRoutes.join(', ')],
    [t('tunnel_dns'), tunnel.dns.join(', ')],
    // Qt says so in words: an empty suffix is every domain of the tunnel.
    [
      t('tunnel_domains'),
      tunnel.searchDomains.includes('') ? t('tunnel_all_domains') : tunnel.searchDomains.join(', '),
    ],
  ];
  const shown = rows.filter(([, value]) => value);
  if (!shown.length) return null;
  return (
    <div className="vpn-tunnel" data-vpn-tunnel>
      <p className="field-hint">{t('tunnel_details')}</p>
      <dl className="desktop-details">
        {shown.map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
