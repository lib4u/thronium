import test from 'node:test';
import assert from 'node:assert/strict';
import { stageImportText } from '../src/otp/importText.ts';

const part = n => `otpauth-migration://offline?data=synthetic-part-${n}`;
test('successive migration scans accumulate and exact rescans do not duplicate entries', () => {
  const first = stageImportText('', ` \r\n${part(1)}\r\n`);
  const complete = stageImportText(first, `${part(2)}\n${part(1)}`);
  assert.equal(complete, `${part(1)}\n${part(2)}`);
  assert.equal(stageImportText(complete, part(2)), complete);
  assert.equal(stageImportText('', `${part(2)}\r${part(1)}\r${part(2)}`), `${part(2)}\n${part(1)}`);
});
test('different payloads for one batch part reach the native validator unchanged', () => {
  const conflicting = part(1) + '-different-payload';
  assert.equal(stageImportText(part(1), conflicting), part(1) + '\n' + conflicting);
  assert.equal(stageImportText(part(1), part(1).toUpperCase()), part(1) + '\n' + part(1).toUpperCase());
});
test('ordinary OTP formats replace the input and mixed text is not silently filtered', () => {
  const ordinary = 'otpauth://totp/Synthetic?secret=GEZDGNBVGY3TQOJQ';
  for (const value of [ordinary, '{"version":1,"otp":[]}', ordinary+'\n'+part(2), '']) {
    assert.equal(stageImportText(part(1), value), value);
  }
  assert.equal(stageImportText(ordinary, part(1)), part(1));
});
test('staging enforces the native UTF-8 limit on each file and the assembled set', () => {
  const max = 1024*1024;
  assert.throws(() => stageImportText('', 'я'.repeat(max/2+1)), e => e==='otp_text_too_large');
  const large = part(1)+'x'.repeat(max-part(1).length);
  assert.equal(stageImportText('', large), large);
  assert.throws(() => stageImportText(large, part(2)), e => e==='otp_text_too_large');
  assert.equal(stageImportText(large, large), large);
});
