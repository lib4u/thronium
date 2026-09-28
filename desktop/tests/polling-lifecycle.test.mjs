import test from 'node:test';
import assert from 'node:assert/strict';
import { hookHarness, deferred, settle } from './helpers/hookHarness.mjs';

const errors = { errorCode: e => typeof e === 'string' ? e : 'operation_failed' };

test('snapshot StrictMode replay cancels the first loop and never resurrects it', async () => {
  const reads = [], failures = [];
  const harness = hookHarness(new URL('../src/app/useSnapshot.ts', import.meta.url), 'useSnapshot', {
    '../api': { empty: {}, command: () => { const d = deferred(); reads.push(d); return d.promise; } },
    '../shared/api/errors': errors,
  }, [e => failures.push(e)]);
  harness.render();
  harness.replay();
  assert.equal(reads.length, 2);
  reads[0].resolve({ generation: 'old' }); await settle();
  assert.equal(harness.timers.size, 0);
  reads[1].resolve({ generation: 'new' }); await settle();
  assert.equal(harness.timers.size, 1);
  assert.equal(harness.render().state.generation, 'new');
  harness.tick();
  const manual = harness.value.refresh();
  reads[3].resolve({ generation: 'manual' }); await manual;
  reads[2].resolve({ generation: 'slow' }); await settle();
  assert.equal(harness.render().state.generation, 'manual');
  harness.tick(); harness.unmount(); reads[4].reject('late'); await settle();
  assert.equal(harness.timers.size, 0);
  assert.deepEqual(failures, []);
});

test('visible diagnostic log polls without library changes and suppresses pre-clear reads', async () => {
  const reads = [], clearing = deferred();
  const harness = hookHarness(new URL('../src/diagnostics/useDiagnosticLog.ts', import.meta.url), 'useDiagnosticLog', {
    '../shared/api/errors.ts': errors,
  }, [() => { const d = deferred(); reads.push(d); return d.promise; }, () => clearing.promise, 7]);
  harness.render();
  reads[0].resolve({ total: 1 }); await settle();
  assert.equal(harness.render().data.total, 1);
  harness.tick();
  reads[1].resolve({ total: 2 }); await settle();
  assert.equal(harness.render().data.total, 2);
  harness.tick(); // This read predates the explicit clear.
  await harness.value.clear(); harness.render();
  const cleared = harness.value.clear();
  reads[2].resolve({ total: 99 }); await settle();
  assert.equal(harness.render().data.total, 2);
  clearing.resolve(); await cleared; harness.render();
  reads[3].resolve({ total: 0 }); await settle();
  assert.equal(harness.render().data.total, 0);
  assert.equal(harness.value.confirm, false);
  harness.tick(); harness.unmount(); reads[4].resolve({ total: 100 }); await settle();
  assert.equal(harness.timers.size, 0);
});

test('diagnostic log StrictMode replay schedules only the current effect', async () => {
  const reads = [];
  const harness = hookHarness(new URL('../src/diagnostics/useDiagnosticLog.ts', import.meta.url), 'useDiagnosticLog', {
    '../shared/api/errors.ts': errors,
  }, [() => { const d = deferred(); reads.push(d); return d.promise; }, async () => {}, 0]);
  harness.render(); harness.replay();
  reads[0].resolve({ total: 1 }); reads[1].resolve({ total: 2 }); await settle();
  assert.equal(harness.timers.size, 1);
  assert.equal(harness.render().data.total, 2);
  harness.unmount();
});
