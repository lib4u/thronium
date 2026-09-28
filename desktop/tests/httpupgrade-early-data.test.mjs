import test from 'node:test';
import assert from 'node:assert/strict';
import { editWsEarlyData as edit, inspectWsEarlyData as inspect, wsEarlyDataText as text } from '../src/profiles/wsEarlyData.ts';

test('HTTPUpgrade path edits preserve authentication query bytes and the fragment', () => {
  const raw = '/upgrade?token=a%2Fb+z&e%64=16&version=1&version=2#part';
  assert.equal(inspect(raw).value, 16);
  assert.equal(edit(raw, '8192'), '/upgrade?token=a%2Fb+z&ed=8192&version=1&version=2#part');
  assert.equal(edit(raw, ''), '/upgrade?token=a%2Fb+z&version=1&version=2#part');
});

test('HTTPUpgrade explanations name the selected transport in both languages', () => {
  for (const language of ['ru', 'en']) {
    for (const key of ['label', 'invalidPath', 'pathRequired']) {
      assert.ok(text(key, language, 'httpupgrade').includes('HTTPUpgrade'));
      assert.ok(!text(key, language, 'httpupgrade').includes('WebSocket'));
      assert.ok(text(key, language, 'ws').includes('WebSocket'));
    }
  }
});
