import test from 'node:test';
import assert from 'node:assert/strict';
import { context, countryLabel, summary, transportLabel } from '../src/settings/testActionsModel.ts';
import { tooltip } from '../src/probes/messages.ts';

const base = { profileId: 'p1', profileName: 'Pool', testedAt: 1789376433, kind: 'ip', transport: 'isolated-core' };

test('the diagnostics context names the profile, path and the measured pool member in both languages', () => {
  const en = context({ ...base, memberId: 'm1', memberName: 'First member' }, 'en');
  assert(en.startsWith('Pool · '), en);
  assert(en.endsWith(` · ${transportLabel('isolated-core', 'en')} · Measured member: First member`), en);
  const ru = context({ ...base, memberId: 'm1', memberName: 'First member' }, 'ru');
  assert(ru.endsWith(' · Измеренный участник: First member'), ru);
  assert(!context(base, 'en').includes('Measured member'));
  assert(context({ ...base, memberId: 'm1', memberName: 'First member', memberOrigin: 'running' }, 'en').endsWith('Measured member: First member (carrying traffic now)'));
  assert(context({ ...base, memberId: 'm1', memberName: 'First member', memberOrigin: 'pinned' }, 'ru').endsWith('Измеренный участник: First member (закреплённый участник)'));
  assert.equal(context({ ...base, testedAt: undefined }, 'en'), '');
  assert.equal(transportLabel('wireguard-endpoint', 'en'), transportLabel('wireguard-endpoint', 'en'));
  assert.equal(transportLabel('unknown-path', 'en'), 'unknown-path');
});

test('summaries keep speed, internet and latency wording and countries fall back to unknown', () => {
  assert.equal(summary({ download: '10 MB/s', upload: '2 MB/s', latencyMs: 42 }, 'en'), '↓ 10 MB/s · ↑ 2 MB/s · 42 ms');
  assert.equal(summary({ online: true }, 'en'), 'Internet available');
  assert.equal(summary({ online: false, latencyMs: 0 }, 'en'), 'Internet unavailable · 0 ms');
  assert.equal(countryLabel({ countryCode: 'JP' }, 'en'), 'Japan');
  assert.equal(countryLabel({ countryCode: null }, 'en'), 'Unknown');
});

test('batch row tooltips add the measured member only when a pool went through one', () => {
  const entry = { kind: 'ip', method: 'http', effectiveMethod: 'http', attempts: [], firstHop: false, profileId: 'p1', name: 'Pool', status: 'ok', latencyMs: null, error: null, at: 1789376433, ip: '203.0.113.9', countryCode: 'JP', download: null, upload: null, downloadBytes: null, uploadBytes: null, transport: 'isolated-core', memberId: 'm1', memberName: 'First member' };
  assert(tooltip(entry, 'en').endsWith('Measured member: First member'), tooltip(entry, 'en'));
  assert(!tooltip({ ...entry, memberId: null, memberName: null }, 'en').includes('Measured member'));
});
