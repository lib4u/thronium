import type * as Wire from '../shared/api/generated/commands';
import { errorCode } from '../shared/api/errors.ts';
export type ProcessUsage = Wire.ProcessUsage;
export type ResourceSnapshot = Wire.ResourceSnapshot;
export type ResourcePoint = {
  at: number;
  appCpu: number | null;
  coreCpu: number | null;
  appRam: number | null;
  coreRam: number | null;
};
export type ResourceSeries = Exclude<keyof ResourcePoint, 'at'>;
export const HISTORY_MS = 60_000;

/**
 * A sample skipped while Engine stays busy is not a failure: the shown values,
 * the history and the native CPU baseline stay, and the next poll measures
 * over the longer interval.
 */
export const skippedSample = (error: unknown): boolean => errorCode(error) === 'process_metrics_busy';

export function appendResourcePoint(
  history: ResourcePoint[],
  snapshot: ResourceSnapshot,
  at: number,
  coreChanged: boolean,
): ResourcePoint[] {
  const value = (usage: ProcessUsage, field: 'cpuPercent' | 'rssBytes') => {
    const n = usage[field];
    return usage.status === 'ok' && n !== null && Number.isFinite(n) && n >= 0 ? n : null;
  };
  const previous = history
    .filter((point) => at - point.at < HISTORY_MS && point.at < at)
    .map((point) => (coreChanged ? { ...point, coreCpu: null, coreRam: null } : point));
  return [
    ...previous,
    {
      at,
      appCpu: value(snapshot.app, 'cpuPercent'),
      coreCpu: value(snapshot.core, 'cpuPercent'),
      appRam: value(snapshot.app, 'rssBytes'),
      coreRam: value(snapshot.core, 'rssBytes'),
    },
  ].slice(-120);
}

// Split paths at missing samples and long gaps, rather than drawing unavailable
// readings as zero or connecting across time spent away from the panel.
export function resourcePaths(history: ResourcePoint[], field: ResourceSeries, maximum: number): string[] {
  if (!history.length || !Number.isFinite(maximum) || maximum <= 0) return [];
  const end = history[history.length - 1].at;
  const paths: string[] = [];
  let path = '';
  let previousAt: number | null = null;
  for (const point of history) {
    const n = point[field];
    if (n === null || !Number.isFinite(n) || n < 0 || (previousAt !== null && point.at - previousAt > 3500)) {
      if (path) paths.push(path);
      path = '';
    }
    if (n !== null && Number.isFinite(n) && n >= 0) {
      const x = Math.max(0, Math.min(600, 600 * (1 - (end - point.at) / HISTORY_MS)));
      const y = 68 - Math.max(0, Math.min(1, n / maximum)) * 64;
      path += `${path ? ' L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`;
    }
    previousAt = point.at;
  }
  if (path) paths.push(path);
  return paths;
}
