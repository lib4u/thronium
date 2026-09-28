import test from 'node:test';
import assert from 'node:assert/strict';
import { definitions, sections, get, set, parse, format } from '../src/profiles/schema.ts';

const fields = sections(definitions.find(d => d.id === 'http'), {}).find(s => s.id === 'tls').fields;
const field = name => fields.find(f => f.path === 'tls_fragment.' + name);

test('custom fragment ranges keep the Core string representation and valid boundary values', () => {
  for (const name of ['size', 'sleep']) {
    for (const value of ['1', '10-100', '65535', '00010']) {
      assert.equal(parse(field(name), value), value);
      assert.equal(format(field(name), parse(field(name), value)), value);
    }
    assert.equal(parse(field(name), ''), undefined);
  }
  for (const value of ['0', '0-10']) {
    assert.equal(parse(field('sleep'), value), value);
    assert.throws(() => parse(field('size'), value), /invalid_range/);
  }
});

test('custom fragment fields reject malformed and overflowing ranges before changing JSON', () => {
  for (const name of ['size', 'sleep']) {
    for (const value of ['10-20-30', '-1', '65536', '1-65536', '20-10', '1.5', '1e2', '+1', ' 1', '1 ', 'one', '18446744073709551615']) {
      assert.throws(() => parse(field(name), value), /invalid_range/, name + ':' + value);
    }
  }
});

test('editing custom ranges preserves imported extensions, builtin fragmentation and explicit TFO', () => {
  const original = { tls: { fragment: true, record_fragment: false, future: [1, 2] }, tcp_fast_open: true,
    tls_fragment: { enabled: false, size: '10-100', sleep: '0', method: 'future', extra: { preserve: true } } };
  const snapshot = structuredClone(original);
  const changed = set(original, field('size').path, parse(field('size'), '1500'));
  assert.deepEqual(changed, { ...original, tls_fragment: { ...original.tls_fragment, size: '1500' } });
  const enabled = set(changed, field('enabled').path, parse(field('enabled'), 'true'));
  assert.equal(enabled.tcp_fast_open, true);
  assert.deepEqual(enabled.tls, original.tls);
  assert.deepEqual(enabled.tls_fragment.extra, original.tls_fragment.extra);
  assert.deepEqual(original, snapshot);
});

test('unsetting custom fields only removes the block when its last property is explicitly cleared', () => {
  const original = { tls_fragment: { enabled: true, size: '10-100', sleep: '0' }, tls: { fragment: false } };
  let next = set(original, field('enabled').path, parse(field('enabled'), ''));
  assert.deepEqual(next.tls_fragment, { size: '10-100', sleep: '0' });
  next = set(next, field('size').path, parse(field('size'), ''));
  next = set(next, field('sleep').path, parse(field('sleep'), ''));
  assert.deepEqual(next, { tls: { fragment: false } });
  assert.deepEqual(set({ tls_fragment: { enabled: false, future: [1] } }, field('enabled').path, undefined), { tls_fragment: { future: [1] } });
  assert.deepEqual(original.tls_fragment, { enabled: true, size: '10-100', sleep: '0' });
});

test('malformed custom blocks cannot lose imported data through ordinary field edits', () => {
  for (const value of [null, true, false, 0, '', 'invalid', [], [false], [1, 2]]) {
    const original = { tls_fragment: value, tcp_fast_open: false };
    const snapshot = structuredClone(original);
    for (const name of ['enabled', 'size', 'sleep']) {
      for (const text of [name === 'enabled' ? 'true' : '10', '']) {
        assert.throws(() => set(original, field(name).path, parse(field(name), text)), /invalid_field_value/);
      }
    }
    assert.deepEqual(original, snapshot);
    // Removing the whole block is a separate explicit action, available even
    // when a malformed imported value prevents individual field edits.
    assert.deepEqual(set(original, 'tls_fragment', undefined), { tcp_fast_open: false });
  }
});

test('custom fragment controls belong to ordinary TCP TLS profiles, not opaque, Xray or QUIC definitions', () => {
  for (const def of definitions) {
    const paths = sections(def, def.seed).flatMap(s => s.fields.map(f => f.path));
    const expected = !!def.tls && !def.quic && def.kind === 'sing-box-outbound' && !['openvpn', 'openconnect'].includes(def.id);
    assert.equal(paths.includes('tls_fragment.enabled'), expected, def.id);
    if (expected) {
      assert(paths.includes('tls_fragment.size'));
      assert(paths.includes('tls_fragment.sleep'));
      assert(paths.includes('tls.fragment'));
    }
  }
});

test('reading imported disabled or invalid custom values is lossless until an explicit edit', () => {
  const original = { tls_fragment: { enabled: false, size: 1500, sleep: 'retained text' } };
  const snapshot = structuredClone(original);
  assert.equal(format(field('size'), get(original, field('size').path)), '1500');
  assert.equal(format(field('sleep'), get(original, field('sleep').path)), 'retained text');
  assert.deepEqual(original, snapshot);
  assert.equal(typeof set(original, field('size').path, parse(field('size'), '1500')).tls_fragment.size, 'string');
});
