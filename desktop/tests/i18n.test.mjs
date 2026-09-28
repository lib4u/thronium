import test from 'node:test';
import assert from 'node:assert/strict';
import { catalogs, languages, sourceLanguage } from '../src/shared/i18n/generated/catalogs.ts';
import {
  translate,
  translateParts,
  plural,
  languageCode,
  languageName,
  nextLanguage,
} from '../src/shared/i18n/index.ts';
import { messageRef, LocalizedError, resolveMessage } from '../src/shared/i18n/message.ts';
import {
  formatBitrate,
  formatBytes,
  formatDate,
  formatMilliseconds,
  formatNumber,
  formatPercent,
  formatSpeed,
  formatSpeedPair,
  regionName,
} from '../src/shared/i18n/format.ts';

test('every language catalog has the source keys and the same placeholders', () => {
  const source = catalogs[sourceLanguage];
  const parameters = (value) => [...new Set(value.match(/\{\w+\}/g) || [])].sort();
  for (const { code } of languages) {
    assert.deepEqual(Object.keys(catalogs[code]).sort(), Object.keys(source).sort(), code);
    for (const key of Object.keys(source)) {
      assert.deepEqual(parameters(catalogs[code][key]), parameters(source[key]), `${code}: ${key}`);
      assert.ok(translate(code, key));
    }
  }
});
test('languages come from the manifest: unknown codes fall back and the toggle cycles through all', () => {
  assert.equal(languages[0].code, sourceLanguage);
  assert.equal(languageCode('xx'), sourceLanguage);
  assert.equal(languageName('ru'), 'Русский');
  const seen = new Set();
  let code = sourceLanguage;
  for (const _ of languages) {
    seen.add(code);
    code = nextLanguage(code);
  }
  assert.equal(code, sourceLanguage);
  assert.equal(seen.size, languages.length);
});
test('an existing form message changes language without recreating the message or the draft', () => {
  const draft = { value: 'unsaved fixture' };
  for (const error of [messageRef('common.close'), new LocalizedError('common.close')]) {
    assert.equal(
      resolveMessage('ru', error, () => 'unexpected'),
      'Закрыть',
    );
    assert.equal(
      resolveMessage('en', error, () => 'unexpected'),
      'Close',
    );
    assert.equal(draft.value, 'unsaved fixture');
  }
  assert.equal(
    resolveMessage('en', new Error('synthetic-private-data'), () => 'Operation failed'),
    'Operation failed',
  );
});
test('plural selection follows the active locale, including Russian teens and fractions', () => {
  assert.equal(plural('en', 'common.category_count', 1), '1 category');
  for (const [n, text] of [
    [2, '2 категории'],
    [5, '5 категорий'],
    [11, '11 категорий'],
    [21, '21 категория'],
    [1.5, '1,5 категории'],
  ])
    assert.equal(plural('ru', 'common.category_count', n), text);
});
test('numbers, dates, units and country names use the shared locale', () => {
  assert.equal(formatNumber(1.5, 'ru'), '1,5');
  assert.equal(formatBytes(1536, 'ru'), '1,5 КиБ');
  assert.equal(formatSpeed(1536, 'ru'), '1,5 КиБ/с');
  assert.equal(formatDate('bad date', 'en'), '—');
  assert.equal(regionName('DE', 'ru'), 'Германия');
  assert.equal(languageCode('unsupported'), sourceLanguage);
});

test('units, percents, latency and core speed text follow the language', () => {
  assert.equal(formatBytes(591, 'ru'), '591 Б');
  assert.equal(formatBytes(591, 'en'), '591 B');
  assert.equal(formatMilliseconds(42, 'ru'), '42 мс');
  assert.equal(formatMilliseconds('<1', 'en'), '<1 ms');
  assert.equal(formatPercent(12.5, 'en', 1), '12.5%');
  assert.match(formatPercent(100, 'ru'), /^100\s%$/u);
  assert.equal(formatBitrate('42.00Mbps', 'ru'), '42,00 Мбит/с');
  assert.equal(formatBitrate('1.50Gbps', 'en'), '1.50 Gbit/s');
  assert.equal(formatBitrate('10 MB/s', 'ru'), '10 MB/s', 'unknown core text is shown as given');
  assert.equal(formatSpeedPair('0.25Kbps', '', 'ru'), '↓ 0,25 кбит/с · ↑ —');
});
test('counted phrases use plural forms and whole sentences with placeholders', () => {
  for (const [n, text] of [
    [1, '1 правило'],
    [3, '3 правила'],
    [5, '5 правил'],
  ])
    assert.equal(plural('ru', 'routing.rule_count', n), text);
  assert.equal(plural('ru', 'subscriptions.every_minutes', 1), 'Раз в 1 минуту');
  assert.equal(plural('en', 'diagnostics.kept_days', 1), 'Kept for 1 day');
  assert.equal(translate('en', 'common.copy_name', { name: 'A' }), 'A · copy');
  assert.equal(translate('ru', 'diagnostics.log_count', { shown: 3, total: 10 }), 'Показано: 3 из 10');
  assert.deepEqual(translateParts('en', 'settings.conflict_fields', { fields: 1 }), [
    'Changed while you were editing: ',
    1,
    '. Your input is preserved. Choose which values to use.',
  ]);
  assert.equal(
    translate('en', 'profiles.websocket_early_data_bytes_471e808', { transport: 'HTTPUpgrade' }),
    'HTTPUpgrade early data · bytes',
  );
});

test('every error code returned by Rust has a text for the window', async () => {
  const { readFileSync, readdirSync, statSync } = await import('node:fs');
  const { join } = await import('node:path');
  const walk = (dir, out = []) => {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name);
      if (statSync(path).isDirectory()) walk(path, out);
      else out.push(path);
    }
    return out;
  };
  const registry = new Set(
    [...readFileSync('engine/src/ipc/error_codes.rs', 'utf8').matchAll(/^\s+"([a-z0-9_]+)",$/gm)].map(
      (m) => m[1],
    ),
  );
  const returned = new Set();
  const pattern = /(?:Err\(|ok_or\(|ok_or_else\(\|\|\s*|map_err\(\|[^|]*\|\s*)"([a-z][a-z0-9_]+)"/g;
  for (const file of [...walk('engine/src'), ...walk('src-tauri/src')]) {
    if (!file.endsWith('.rs') || /test/.test(file) || file.includes('/bin/')) continue;
    for (const match of readFileSync(file, 'utf8').matchAll(pattern))
      if (registry.has(match[1])) returned.add(match[1]);
  }
  const catalog = JSON.parse(readFileSync('locales/en/errors.json', 'utf8'));
  const mapped = new Set();
  for (const file of walk('src')) {
    if (!/\.tsx?$/.test(file) || file.includes('generated')) continue;
    for (const match of readFileSync(file, 'utf8').matchAll(/^\s+([a-z][a-z0-9_]+):\s*'[a-z_]+\./gm))
      mapped.add(match[1]);
  }
  // Only fault injection of the store tests produces this code.
  const allowed = new Set(['store_injected_failure']);
  const missing = [...returned].filter(
    (code) => !(code in catalog) && !mapped.has(code) && !allowed.has(code),
  );
  assert.deepEqual(missing, []);
});

test('a registered code outside the legacy key map resolves through the errors catalog', async () => {
  const { catalogError } = await import('../src/shared/i18n/message.ts');
  assert.equal(
    catalogError('en', 'auto_select_no_reachable'),
    catalogs.en['errors.auto_select_no_reachable'],
  );
  assert.equal(catalogError('ru', 'core_exited'), catalogs.ru['errors.core_exited']);
  assert.equal(catalogError('en', 'not_a_registered_code'), undefined);
});

test('application log events are shown in the window language', async () => {
  const { logText } = await import('../src/diagnostics/logModel.ts');
  const entry = { id: 1, at: 0, level: 'error', source: 'app', truncated: false };
  assert.equal(
    logText({ ...entry, text: 'CheckConfig: bad', code: 'check_config_failed', detail: 'bad' }, 'ru'),
    'Проверка конфигурации не пройдена: bad',
  );
  assert.equal(
    logText(
      {
        ...entry,
        text: 'Test failed: store_sync_uncertain',
        code: 'test_failed',
        detail: 'store_sync_uncertain',
      },
      'en',
    ),
    `Test failed: ${translate('en', 'errors.store_sync_uncertain')}`,
  );
  assert.equal(
    logText({ ...entry, text: 'latency_cache_write_failed', code: 'latency_cache_write_failed' }, 'ru'),
    translate('ru', 'errors.latency_cache_write_failed'),
  );
  assert.equal(logText({ ...entry, text: 'unknown_code', code: 'unknown_code' }, 'ru'), 'unknown_code');
  assert.equal(logText({ ...entry, source: 'stdout', text: 'core line' }, 'ru'), 'core line');
});
test('engine limits fill catalog placeholders in every language', async () => {
  const { limits } = await import('../src/shared/limits.ts');
  for (const { code } of languages)
    for (const key of Object.keys(catalogs[sourceLanguage])) {
      const left = [...translate(code, key).matchAll(/\{(\w+)\}/g)].map((m) => m[1]);
      assert.deepEqual(left.filter((name) => Object.hasOwn(limits, name) || /^(max|min)[A-Z]/.test(name)), [], `${code} ${key}`);
    }
  assert.equal(translate('en', 'profiles.import_size_limit'), 'The import limit is 4 MiB.');
  assert.equal(translate('ru', 'profiles.import_size_limit'), 'Лимит импорта — 4 МиБ.');
  assert.match(translate('en', 'errors.chain_too_long'), new RegExp(`\\b${limits.maxChainHops}\\b`));
  // Ports are identifiers: no digit grouping in any locale.
  assert.match(translate('ru', 'errors.external_port_invalid'), /от 1024 до 65535/);
  assert.equal(translate('en', 'errors.chain_too_long', { maxChainHops: 3 }), 'The expanded chain exceeds 3 hops.');
});
