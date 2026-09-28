import test from 'node:test';
import assert from 'node:assert/strict';
import { journalColumns, kindLabel, sourceLabel, statusLabel, subjectText, valueText } from '../src/diagnostics/measurementJournalModel.ts';
import { transportLabel } from '../src/settings/testActionsModel.ts';

const base = { id: 1, at: 1789376433, kind: 'ip', source: 'single', profileId: 'p1', profileName: 'Pool', status: 'ok', transport: 'isolated-core' };

test('journal rows label kind, subject with member and path, status and value without free text', () => {
  const entry = { ...base, memberName: 'First member', ip: '203.0.113.9', countryCode: 'JP' };
  assert.equal(subjectText(entry, 'en'), `Pool · First member · ${transportLabel('isolated-core', 'en')}`);
  assert.equal(valueText(entry, 'en'), 'JP · 203.0.113.9');
  assert.equal(subjectText({ ...entry, memberOrigin: 'running' }, 'en'), `Pool · First member (carrying traffic now) · ${transportLabel('isolated-core', 'en')}`);
  assert.equal(subjectText({ ...entry, memberOrigin: 'first' }, 'ru'), `Pool · First member (первый участник) · ${transportLabel('isolated-core', 'ru')}`);
  assert.equal(valueText({ ...base, kind: 'speed', download: '10 MB/s', upload: '2 MB/s' }, 'en'), '↓ 10 MB/s · ↑ 2 MB/s');
  assert.equal(valueText({ ...base, kind: 'latency', latencyMs: 42 }, 'en'), '42 ms');
  assert.equal(valueText({ ...base, status: 'error', error: 'probe_busy' }, 'ru'), valueText({ ...base, status: 'error', error: 'probe_busy' }, 'ru'));
  assert.notEqual(valueText({ ...base, status: 'error', error: 'probe_busy' }, 'en'), 'probe_busy');
  assert.equal(valueText({ ...base, status: 'cancelled' }, 'en'), '—');
  assert.equal(statusLabel({ ...base, status: 'stale' }, 'en'), statusLabel({ ...base, status: 'stale' }, 'en'));
  assert.equal(statusLabel({ ...base, status: 'custom-code' }, 'en'), 'custom-code');
  assert.equal(sourceLabel({ ...base, source: 'batch' }, 'en'), 'Bulk test');
  assert.equal(sourceLabel(base, 'ru'), 'Диагностика');
  assert.equal(sourceLabel({ ...base, source: 'periodic' }, 'en'), 'Periodic check');
});

test('the direct internet check names no profile and its own kind in both languages', () => {
  const entry = { ...base, kind: 'internet', profileId: 'direct', profileName: '', transport: 'direct' };
  assert.equal(kindLabel(entry, 'en'), 'Internet without proxy');
  assert.equal(kindLabel(entry, 'ru'), 'Интернет без прокси');
  assert.equal(subjectText(entry, 'en'), transportLabel('direct', 'en'));
  assert.equal(subjectText({ ...entry, transport: undefined }, 'ru'), transportLabel('direct', 'ru'));
  assert.equal(subjectText({ ...base, transport: undefined }, 'en'), 'Pool');
  assert.equal(journalColumns.length, 6);
  assert.equal(kindLabel({ ...base, kind: 'ip' }, 'en'), 'Check IP and country');
});
