import test from 'node:test';
import assert from 'node:assert/strict';
import { appendResourcePoint, resourcePaths, skippedSample } from '../src/diagnostics/resources.ts';
import { CodedError } from '../src/shared/api/errors.ts';

const usage = (cpuPercent = 2, rssBytes = 4096) => ({ status: 'ok', cpuPercent, rssBytes, processes: 1, reason: null });
const snapshot = () => ({ supported: true, logicalCpus: 8, intervalMs: 1000, coreInstance: '1', app: usage(), core: usage() });

test('resource history preserves unknown CPU, excludes partial estimates and truncates the minute window', () => {
  const view = snapshot(); view.app.cpuPercent = null;
  let history = appendResourcePoint([], view, 1000, false);
  assert.equal(history[0].appCpu, null); assert.equal(history[0].appRam, 4096);
  view.app = { ...usage(), status: 'partial' }; view.core = { ...usage(), status: 'inactive' };
  history = appendResourcePoint(history, view, 2000, false);
  assert.deepEqual(history[1], { at: 2000, appCpu: null, appRam: null, coreCpu: null, coreRam: null });
  history = appendResourcePoint(history, snapshot(), 61_000, false);
  assert.deepEqual(history.map(point => point.at), [2000, 61_000]);
});

test('new core clears its previous history without discarding application samples', () => {
  const history = appendResourcePoint([], snapshot(), 1000, false);
  const next = appendResourcePoint(history, snapshot(), 2000, true);
  assert.equal(next[0].appCpu, 2); assert.equal(next[0].coreCpu, null); assert.equal(next[0].coreRam, null);
  assert.equal(next[1].coreCpu, 2);
});

test('chart paths break at missing samples and elapsed gaps, keep elapsed-time spacing and fixed CPU scale', () => {
  const point = (at, cpu) => ({ at, appCpu: cpu, coreCpu: null, appRam: null, coreRam: null });
  const paths = resourcePaths([point(1000, 0), point(2000, 50), point(3000, null), point(4000, 100), point(8000, 50)], 'appCpu', 100);
  assert.deepEqual(paths, ['M530.0,68.0 L540.0,36.0', 'M560.0,4.0', 'M600.0,36.0']);
  assert.deepEqual(resourcePaths([point(1000, NaN)], 'appCpu', 100), []);
  assert.deepEqual(resourcePaths([point(1000, 1)], 'appCpu', 0), []);
});

test('a busy Engine skips one sample instead of failing the panel', () => {
  assert.equal(skippedSample(new CodedError('process_metrics_busy')), true);
  assert.equal(skippedSample(new CodedError('process_metrics_unavailable')), false);
  assert.equal(skippedSample(new Error('boom')), false);
});
