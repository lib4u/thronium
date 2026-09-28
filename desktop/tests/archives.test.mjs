import test from 'node:test';
import assert from 'node:assert/strict';
import { unzipSync, strFromU8 } from 'fflate';
import { fixtures, wgFile } from './import-fixtures.mjs';
import { parseImport } from '../src/profiles/import.ts';
import { planArchive, createArchive, MAX_ARCHIVE_BYTES } from '../src/profiles/archives.ts';

const wg = () => parseImport(wgFile, 'group')[0].draft;
const png =
  'data:image/png;base64,' + Buffer.from([137, 80, 78, 71, 13, 10, 26, 10, 1, 2, 3]).toString('base64');
const signal = () => new AbortController().signal;

test('WG ZIP preserves distinct configs with all peers and safe unique Unicode filenames', async () => {
  const source = wg();
  const profiles = ['../CON:сервер\\test', '../CON:сервер\\test', ' \u202e../../NUL\n '].map((name, i) => ({
    ...structuredClone(source),
    name,
    config: { ...source.config, mtu: 1300 + i },
  }));
  const plan = planArchive(profiles, 'wireguard-archive');
  assert.equal(new Set(plan.map((p) => p.name.toLowerCase())).size, 3);
  for (const entry of plan) assert.match(entry.name, /^\d{3}-[^/\\:\r\n\u202e]+\.conf$/u);
  const data = await createArchive(
    plan,
    'wireguard-archive',
    () => {
      throw Error('must not render QR');
    },
    () => {},
    signal(),
  );
  const files = unzipSync(Buffer.from(data, 'base64'));
  assert.deepEqual(
    Object.keys(files),
    plan.map((p) => p.name),
  );
  Object.values(files).forEach((bytes, i) => {
    const parsed = parseImport(strFromU8(bytes), 'target')[0];
    assert.deepEqual(parsed.warnings, []);
    assert.deepEqual(parsed.draft.config, profiles[i].config);
  });
});

test('PNG ZIP passes exact native URI per profile to the local QR renderer', async () => {
  const profiles = fixtures()
    .filter((p) => !p.name.endsWith('multi-peer'))
    .slice(0, 3);
  const plan = planArchive(profiles, 'qr-archive');
  const calls = [],
    progress = [];
  const data = await createArchive(
    plan,
    'qr-archive',
    async (text) => {
      calls.push(text);
      return png;
    },
    (...p) => progress.push(p),
    signal(),
  );
  assert.deepEqual(
    calls,
    plan.map((e) => e.text),
  );
  assert.deepEqual(progress, [
    [1, 3],
    [2, 3],
    [3, 3],
  ]);
  const files = unzipSync(Buffer.from(data, 'base64'));
  assert.equal(Object.keys(files).length, 3);
  for (const [name, bytes] of Object.entries(files)) {
    assert.match(name, /^\d{3}-.+\.png$/);
    assert.deepEqual(Buffer.from(bytes), Buffer.from(png.split(',')[1], 'base64'));
  }
});

test('batch conversions reject invalid selections and unsupported profiles without silent skips', () => {
  assert.throws(() => planArchive([], 'wireguard-archive'), /archive_invalid_selection/);
  assert.throws(() => planArchive(Array(101).fill(wg()), 'wireguard-archive'), /archive_invalid_selection/);
  assert.throws(
    () =>
      planArchive(
        [wg(), { name: 'Unsupported', kind: 'xray-config', config: { outbounds: [] } }],
        'wireguard-archive',
      ),
    /share_wireguard_only/,
  );
  const good = fixtures().find((p) => p.config.type === 'vless');
  assert.throws(
    () =>
      planArchive(
        [good, { ...good, config: { ...good.config, future: { password: 'not-in-error' } } }],
        'qr-archive',
      ),
    (e) => e.message.startsWith('share_fields:') && !e.message.includes('not-in-error'),
  );
});

test('long multibyte names stay within extraction filename limits without splitting Unicode', () => {
  const plan = planArchive(
    [
      { ...wg(), name: '🦊'.repeat(128) },
      { ...wg(), name: '...' },
    ],
    'wireguard-archive',
  );
  assert.ok(Buffer.byteLength(plan[0].name, 'utf8') < 200);
  assert.match(plan[0].name, /^001-🦊+\.conf$/u);
  assert.equal(plan[1].name, '002.conf');
});

test('cancel during QR generation stops further files and discards prepared output', async () => {
  const abort = new AbortController();
  let calls = 0;
  let progress = 0;
  await assert.rejects(
    createArchive(
      [
        { name: '001.png', text: 'a' },
        { name: '002.png', text: 'b' },
      ],
      'qr-archive',
      async () => {
        calls++;
        abort.abort();
        return png;
      },
      () => progress++,
      abort.signal,
    ),
    /archive_cancelled/,
  );
  assert.equal(calls, 1);
  assert.equal(progress, 0);
  await assert.rejects(
    createArchive(
      [],
      'qr-archive',
      async () => {
        throw Error('not called');
      },
      () => {},
      abort.signal,
    ),
    /archive_cancelled/,
  );
});

test('unexpected renderer data and oversized uncompressed content never produce an archive', async () => {
  for (const data of [
    'https://example.test/image.png',
    'data:image/png;base64,invalid!',
    'data:image/png;base64,YQ==',
  ]) {
    await assert.rejects(
      createArchive(
        [{ name: '001.png', text: 'a' }],
        'qr-archive',
        async () => data,
        () => {},
        signal(),
      ),
      /archive_invalid_data/,
    );
  }
  await assert.rejects(
    createArchive(
      [{ name: '001.conf', text: 'x'.repeat(MAX_ARCHIVE_BYTES + 1) }],
      'wireguard-archive',
      async () => png,
      () => {},
      signal(),
    ),
    /archive_too_large/,
  );
});
