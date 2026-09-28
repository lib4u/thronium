import { formatDate } from '../shared/i18n/format.ts';
import type * as Wire from '../shared/api/generated/commands';

/** Qt's period buttons, in the order the selector offers them. */
export const periods = [1, 7, 30, 90] as const;
export type Period = (typeof periods)[number];
export const periodKeys: Record<Period, string> = {
  1: 'common.trafficPeriodDay',
  7: 'common.trafficPeriodWeek',
  30: 'common.trafficPeriodMonth',
  90: 'common.trafficPeriodQuarter',
};

/** One column of the chart, already sized against the busiest bucket. */
export type Bar = {
  bucket: number;
  upload: number;
  download: number;
  /** Share of the tallest column, so the drawing needs no pixel maths. */
  uploadShare: number;
  downloadShare: number;
  label: string;
  /** Qt labels one column in eight; the rest keep the label for the tooltip. */
  labelled: boolean;
};

/**
 * Qt's chart: every bucket of the period is a column, download stacked over
 * upload, scaled to the busiest one and labelled at a fixed stride. Qt draws
 * the breakdown the open tab shows, so the series comes from that side.
 */
export function bars(series: Wire.TrafficPoint[], bucketSeconds: number, language: string): Bar[] {
  const tallest = series.reduce((most, p) => Math.max(most, p.upload + p.download), 0);
  const stride = Math.max(1, Math.ceil(series.length / 8));
  const daily = bucketSeconds >= 86400;
  return series.map((point, index) => ({
    bucket: point.bucket,
    upload: point.upload,
    download: point.download,
    uploadShare: tallest ? point.upload / tallest : 0,
    downloadShare: tallest ? point.download / tallest : 0,
    label: daily
      ? formatDate(point.bucket * 1000, language, { month: 'short', day: 'numeric' })
      : formatDate(point.bucket * 1000, language, { hour: '2-digit', minute: '2-digit' }),
    labelled: index % stride === 0,
  }));
}

/** Qt's row label: a server keeps its name, the rest are named by what they are. */
export function profileLabel(row: Wire.TrafficProfileUsage, translate: (key: string) => string): string {
  if (row.other) return translate('common.trafficOther');
  if (row.direct) return translate('common.trafficDirect');
  return row.name || translate('common.trafficRemovedProfile');
}
export function applicationLabel(row: Wire.TrafficAppUsage, translate: (key: string) => string): string {
  if (row.other) return translate('common.trafficOther');
  return row.process || translate('common.trafficUnknownApplication');
}
