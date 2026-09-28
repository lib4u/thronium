import test from 'node:test';
import assert from 'node:assert/strict';
import { AUTO_SELECT_ID, autoSelectSummary, autoSelectHint, advancedSections, configSections, defaultAutoSelectConfig, durationOptions, intervalPresets, reuseTtlPresets } from '../src/selectors/autoSelectModel.ts';
import { plural } from '../src/shared/i18n/index.ts';

test('the virtual pool has a localized display row and the reserved id', () => {
  assert.equal(AUTO_SELECT_ID, 'auto-select');
  const en = autoSelectSummary('en');
  assert.equal(en.kind, 'auto-selector');
  assert.equal(en.id, 'auto-select');
  assert.equal(en.name, 'Auto-select');
  assert.equal(autoSelectSummary('ru').name, 'Автовыбор');
  assert.equal(en.poolEligible, false);
});

test('advanced settings reuse checks and balancing without duplicating basic controls', () => {
  const ids = configSections(defaultAutoSelectConfig).map((s) => s.id);
  assert.deepEqual(ids, ['health', 'balance']);
  assert.equal(configSections, advancedSections);
  const health = configSections(defaultAutoSelectConfig).find((s) => s.id === 'health');
  assert.ok(health.fields.some((f) => f.path === 'url'));
  assert.ok(health.fields.some((f) => f.path === 'watch_interval'));
  assert.ok(configSections(defaultAutoSelectConfig).every((section) => section.fields.every((field) => !['interval', 'reuse_ttl'].includes(field.path))));
  const balance = configSections(defaultAutoSelectConfig).find((s) => s.id === 'balance');
  assert.ok(balance.fields.some((f) => f.path === 'balance'));
});

test('duration presets match equivalent units while preserving saved and custom values', () => {
  const defaultInterval = durationOptions(intervalPresets, '120s', 'en');
  assert.equal(defaultInterval.length, 5);
  assert.equal(defaultInterval.find((option) => option.value === '120s').label, '2 minutes');
  for (const saved of ['2m', '1m60s', '120000ms']) {
    const options = durationOptions(intervalPresets, saved, 'en');
    assert.equal(options.length, 5);
    assert.equal(options.find((option) => option.value === saved).label, '2 minutes');
  }
  for (const saved of ['47s', '17m']) {
    const options = durationOptions(reuseTtlPresets, saved, 'ru');
    assert.equal(options.at(-1).value, saved);
    assert.equal(options.at(-1).label, 'Другое: ' + saved);
  }
  assert.equal(durationOptions(reuseTtlPresets, '0s', 'ru')[0].label, 'Не запоминать');
  assert.equal(durationOptions(reuseTtlPresets, '30m', 'ru').find((option) => option.value === '30m').label, '30 минут');
});

test('card hint reflects failover and the member count uses Russian plural forms', () => {
  assert.equal(autoSelectHint('ru', true), 'Найдём быстрый сервер и переключимся при сбое');
  assert.equal(autoSelectHint('ru', false), 'Найдём быстрый сервер при подключении');
  assert.equal(autoSelectHint('en', false), 'Find a fast server when you connect');
  assert.equal(plural('ru', 'library.auto_select_count', 1), '1 сервер в автовыборе');
  assert.equal(plural('ru', 'library.auto_select_count', 2), '2 сервера в автовыборе');
  assert.equal(plural('ru', 'library.auto_select_count', 5), '5 серверов в автовыборе');
});
