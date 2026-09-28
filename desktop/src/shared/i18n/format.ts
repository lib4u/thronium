import { locale, sourceLanguage, translate, translateParts } from './index.ts';

export function formatNumber(value: number, language: string, options?: Intl.NumberFormatOptions): string {
  return new Intl.NumberFormat(locale(language), options).format(value);
}
export function formatDate(
  value: Date | number | string,
  language: string,
  options?: Intl.DateTimeFormatOptions,
): string {
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : new Intl.DateTimeFormat(locale(language), options).format(date);
}
export function formatDateTime(value: Date | number | string, language: string): string {
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString(locale(language));
}
export function formatTime(value: Date | number | string, language: string): string {
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleTimeString(locale(language));
}
/** A formatted number and its unit, kept apart so a view can style each. */
export type Quantity = { value: string; unit?: string };
export const quantityText = ({ value, unit }: Quantity) => (unit ? `${value} ${unit}` : value);
export function byteQuantity(
  value: number,
  language: string = sourceLanguage,
  units: 'binary' | 'short' = 'binary',
): Quantity {
  if (!Number.isFinite(value) || value < 0) return { value: '—' };
  const index = value < 1024 ? 0 : value < 1048576 ? 1 : value < 1073741824 ? 2 : 3;
  const digits = index === 0 ? 0 : index === 3 ? 2 : 1;
  const unit = (
    units === 'binary'
      ? (['common.unit_b', 'common.unit_kib', 'common.unit_mib', 'common.unit_gib'] as const)
      : (['common.unit_b', 'common.unit_kb', 'common.unit_mb', 'common.unit_gb'] as const)
  )[index];
  return {
    value: formatNumber(value / 1024 ** index, language, {
      minimumFractionDigits: digits,
      maximumFractionDigits: digits,
    }),
    unit: translate(language, unit),
  };
}
export function formatBytes(
  value: number,
  language: string = sourceLanguage,
  units: 'binary' | 'short' = 'binary',
): string {
  return quantityText(byteQuantity(value, language, units));
}
export function formatSpeed(value: number, language: string): string {
  return translate(language, 'common.per_second', { value: formatBytes(value, language) });
}
export function formatPercent(value: number, language: string, digits = 0): string {
  return formatNumber(value / 100, language, {
    style: 'percent',
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
}
/** A duration in milliseconds as a number and the unit the language's template puts beside it. */
export function millisecondQuantity(value: number | string, language: string): Quantity {
  const number = typeof value === 'number' ? formatNumber(value, language) : value;
  const unit = translateParts(language, 'common.milliseconds', { value: null })
    .filter((part): part is string => part !== null)
    .join('')
    .trim();
  return { value: number, unit };
}
/** A duration in milliseconds; a text value such as `<1` is shown as given. */
export function formatMilliseconds(value: number | string, language: string): string {
  return translate(language, 'common.milliseconds', {
    value: typeof value === 'number' ? formatNumber(value, language) : value,
  });
}
const BITRATE_UNITS = {
  Kbps: 'common.unit_kbps',
  Mbps: 'common.unit_mbps',
  Gbps: 'common.unit_gbps',
} as const;
/**
 * The core reports speed as text in one fixed form (`12.34Mbps`). That form is
 * shown with the user's number format and unit names; any other text is kept.
 */
export function formatBitrate(value: string | null | undefined, language: string): string {
  if (!value) return '—';
  const match = /^(\d+(?:\.\d+)?)\s*(Kbps|Mbps|Gbps)$/.exec(value.trim());
  if (!match) return value;
  const digits = match[1].split('.')[1]?.length ?? 0;
  const number = formatNumber(Number(match[1]), language, {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
  return `${number} ${translate(language, BITRATE_UNITS[match[2] as keyof typeof BITRATE_UNITS])}`;
}
/** Download and upload speed reported by one speed test. */
export function formatSpeedPair(
  download: string | null | undefined,
  upload: string | null | undefined,
  language: string,
) {
  return translate(language, 'common.speed_pair', {
    download: formatBitrate(download, language),
    upload: formatBitrate(upload, language),
  });
}
export function regionName(code: string, language: string): string {
  return new Intl.DisplayNames([locale(language)], { type: 'region' }).of(code) || code;
}
