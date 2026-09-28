import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// The Core serves the generated messages and the page logic as one script.
const script =
  readFileSync(new URL('../engine/src/dashboard/messages.js', import.meta.url), 'utf8') +
  readFileSync(new URL('../engine/src/dashboard/bootstrap.js', import.meta.url), 'utf8');
function bootstrap(
  previous,
  {
    writeFails = false,
    host = '127.0.0.1:9091',
    page = 'handoff',
    hash = '#secret=a%26b%23%3D%2B&url=untrusted.invalid&language=ru',
    languages = ['en-US'],
  } = {},
) {
  const events = [],
    status = { textContent: '' };
  let saved;
  vm.runInNewContext(script, {
    URLSearchParams,
    navigator: { languages },
    location: {
      hash,
      host,
      pathname: '/thronium-dashboard.html',
      replace: (path) => events.push(['navigate', path]),
    },
    history: { replaceState: (_state, _title, path) => events.push(['clear', path]) },
    localStorage: {
      getItem: () => previous,
      setItem: (key, value) => {
        if (writeFails) throw new Error('unavailable');
        saved = { key, value: JSON.parse(value) };
        events.push(['save']);
      },
    },
    document: {
      getElementById: () => status,
      documentElement: {},
      body: { dataset: { throniumPage: page } },
    },
  });
  return { events, saved, status };
}
test('dashboard bootstrap uses its own active authority, preserves other servers and clears the fragment before navigation', () => {
  const { events, saved } = bootstrap(
    JSON.stringify({
      servers: [
        { id: 'other', url: 'other.test:1' },
        { id: 'thronium', secret: 'old' },
      ],
      activeId: 'other',
      option: 17,
    }),
  );
  assert.equal(saved.key, 'sing-box-dashboard.servers');
  assert.deepEqual(saved.value, {
    servers: [
      { id: 'other', url: 'other.test:1' },
      { id: 'thronium', name: 'Thronium', url: '127.0.0.1:9091', secret: 'a&b#=+' },
    ],
    activeId: 'thronium',
    option: 17,
  });
  assert.deepEqual(events, [['clear', '/thronium-dashboard.html'], ['save'], ['navigate', '/dashboard/']]);
});
test('dashboard bootstrap handles invalid prior storage and IPv6 without accepting a foreign fragment authority', () => {
  for (const previous of ['invalid', 'null', '[]', '{"servers":{}}', '{"servers":[null,0,false]}']) {
    const { saved } = bootstrap(previous, { host: '[::1]:9092' });
    assert.equal(saved.value.servers.length, 1);
    assert.equal(saved.value.servers[0].url, '[::1]:9092');
  }
});
test('unavailable browser storage produces a local error without navigating with credentials', () => {
  const { events, saved, status } = bootstrap(null, { writeFails: true });
  assert.equal(saved, undefined);
  assert.deepEqual(events, [['clear', '/thronium-dashboard.html']]);
  assert.match(status.textContent, /хранилище браузера/);
  assert.doesNotMatch(status.textContent, /a&b|untrusted/);
});
test('stub pages show one language: the application setting, then the browser, then the source language', () => {
  assert.match(
    bootstrap(null, { page: 'placeholder', hash: '', languages: ['ru-RU'] }).status.textContent,
    /Установите веб-панель/,
  );
  assert.match(
    bootstrap(null, { page: 'placeholder', hash: '', languages: ['de-DE'] }).status.textContent,
    /^Install the dashboard/,
  );
  assert.deepEqual(bootstrap(null, { page: 'placeholder', hash: '' }).events, []);
  assert.equal(
    bootstrap(null, { writeFails: true, hash: '#secret=x&language=en', languages: ['ru'] }).status
      .textContent,
    'Could not prepare browser storage.',
  );
});
