// Pure formatting of one server row from the snapshot summary and the
// "displayed data" switches of the interface settings. No React, no IPC.
import { formatBytes, regionName } from '../shared/i18n/format.ts';
import { translate } from '../shared/i18n/index.ts';
import { result as probeResult, tooltip as probeTooltip, type Language } from '../probes/messages.ts';
import catalog from '../../contracts/settings.catalog.json' with { type: 'json' };
import type { Profile } from '../api';

const defaults = catalog as { id: string; default: unknown }[];

// Catalog ids of the server-list group that change what a row shows.
export const displayedDataIds = [
  'list_show_address',
  'list_show_port',
  'list_show_protocol',
  'show_config_security',
  'list_show_latency',
  'list_show_ip',
  'list_show_speed',
  'list_show_traffic',
] as const;
export type DisplayedData = Record<(typeof displayedDataIds)[number], boolean>;

// Live values from the snapshot's appearance section; the catalog default
// applies while a value is missing, so a stale snapshot never hides a row.
export function displayedData(appearance?: Record<string, unknown>): DisplayedData {
  return Object.fromEntries(
    displayedDataIds.map((id) => {
      const value = appearance?.[id];
      return [id, typeof value === 'boolean' ? value : defaults.find((f) => f.id === id)?.default === true];
    }),
  ) as DisplayedData;
}

// Engine security classes (profile_descriptor.rs): unknown 0, none 1, weak 2, secure 3.
export const securityWarning = (profile: Profile, view: DisplayedData) =>
  view.show_config_security && (profile.securityLevel === 1 || profile.securityLevel === 2);

// Protocol codes the engine uses for profiles without a single outbound type.
const protocolNames = {
  'external-core': 'library.protocol_external_core',
  custom: 'library.protocol_custom',
} as const;
export function protocolLabel(protocol: string, language: string): string {
  return Object.prototype.hasOwnProperty.call(protocolNames, protocol)
    ? translate(language, protocolNames[protocol as keyof typeof protocolNames])
    : protocol;
}

export function rowSubtitle(profile: Profile, view: DisplayedData, language: Language): string {
  const port = view.list_show_port && profile.port ? `:${profile.port}` : '';
  return [
    view.list_show_address && profile.address ? profile.address + port : '',
    view.list_show_protocol ? protocolLabel(profile.protocol, language) : '',
    view.show_config_security ? profile.security : '',
  ]
    .filter(Boolean)
    .join(' · ');
}

export function trafficText(traffic: Profile['traffic'], language: Language): string {
  if (!traffic || (traffic.upload <= 0 && traffic.download <= 0)) return '';
  return `${formatBytes(traffic.upload, language)}↑ ${formatBytes(traffic.download, language)}↓`;
}

// Second line under the name: exit country/IP, last speed test and window
// traffic, each only while its switch is on and a value exists.
export function rowStats(
  profile: Profile,
  view: DisplayedData,
  language: Language,
): { text: string; title: string } {
  const parts: string[] = [],
    titles: string[] = [];
  if (view.list_show_ip && profile.ipMeasurement) {
    const m = profile.ipMeasurement;
    parts.push(
      m.status === 'ok'
        ? `${m.countryCode ? regionName(m.countryCode, language) : '?'} · ${m.ip || '—'}`
        : probeResult(m, language),
    );
    titles.push(probeTooltip(m, language));
  }
  if (view.list_show_speed && profile.speedMeasurement) {
    parts.push(probeResult(profile.speedMeasurement, language));
    titles.push(probeTooltip(profile.speedMeasurement, language));
  }
  const traffic = view.list_show_traffic ? trafficText(profile.traffic, language) : '';
  if (traffic && profile.traffic) {
    parts.push(traffic);
    titles.push(
      `${translate(language, 'library.traffic_upload')}: ${formatBytes(profile.traffic.upload, language)} · ${translate(language, 'library.traffic_download')}: ${formatBytes(profile.traffic.download, language)}`,
    );
  }
  return { text: parts.join(' · '), title: titles.join('\n') };
}
