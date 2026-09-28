// Labels for a single diagnostic result; the engine names paths and members, the view only formats.
import { formatMilliseconds, formatSpeedPair, formatTime, regionName } from '../shared/i18n/format.ts';
import { translate, type Language } from '../shared/i18n/index.ts';
import type * as Wire from '../shared/api/generated/commands';
import { memberOrigin } from '../probes/messages.ts';

export type Result = Wire.ConnectionTestResult;

// Which path produced a measurement.
const transports = {
  'isolated-core': 'settings.transport_isolated_core',
  'vpn-endpoint': 'settings.transport_vpn_endpoint',
  'wireguard-endpoint': 'settings.transport_wireguard_endpoint',
  direct: 'settings.transport_direct',
} as const;

export function transportLabel(transport: string, language: Language) {
  return transport in transports
    ? translate(language, transports[transport as keyof typeof transports])
    : transport;
}

export function countryLabel(result: Result | undefined, language: Language) {
  return result?.countryCode
    ? regionName(result.countryCode, language)
    : translate(language, 'settings.unknown_ae8809f');
}

/** The one-line summary for results without an exit IP: internet, speed and latency. */
export function summary(result: Result, language: Language) {
  const base =
    'online' in result
      ? translate(
          language,
          result.online ? 'settings.internet_available_b953150' : 'settings.internet_unavailable_9e4a14e',
        )
      : formatSpeedPair(result.download, result.upload, language);
  return typeof result.latencyMs === 'number'
    ? `${base} · ${formatMilliseconds(result.latencyMs, language)}`
    : base;
}

/** Profile, time, path and the measured pool member, when the pool went through one. */
export function context(result: Result, language: Language) {
  if (!result.testedAt) return '';
  const parts = [result.profileName, formatTime(new Date(result.testedAt * 1000), language)];
  if (result.transport) parts.push(transportLabel(result.transport, language));
  if (result.memberName)
    parts.push(
      `${translate(language, 'settings.measured_member')}: ${result.memberName}${memberOrigin(result.memberOrigin, language)}`,
    );
  return parts.filter(Boolean).join(' · ');
}
