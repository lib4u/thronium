import test from 'node:test';
import assert from 'node:assert/strict';
import { formatLogEntries } from '../src/diagnostics/logModel.ts';

test('export preserves run identity and text without emitting invisible entries', () => {
  const row = {at:0, level:'warn', source:'stderr', text:'Final error', truncated:true,
    probe:{runId:'unique-run', profileId:'p', profileName:'東京', kind:'http'}};
  assert.equal(formatLogEntries([row]), '1970-01-01T00:00:00.000Z [WARN] [stderr] [test unique-run http 東京] Final error [truncated]');
  assert.equal(formatLogEntries([{...row, probe:undefined, truncated:false}]), '1970-01-01T00:00:00.000Z [WARN] [stderr] Final error');
  assert.equal(formatLogEntries([]), '');
});
