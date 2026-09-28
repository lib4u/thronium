import type { Draft, command } from '../api';
import { limits } from '../shared/api/generated/limits.ts';

export type SavedRanking = { members: string[]; ranked_at: number };
export type MeasurementProgress = {
  total: number;
  done: number;
  fresh: number;
  phase: 'measuring' | 'ranking';
};
type Flow = {
  command: typeof command;
  current(): boolean;
  progress(value: MeasurementProgress): void;
  batch(id: string | undefined): void;
  pause?(): Promise<void>;
  now?(): number;
};

// Network workers belong to the existing backend queue. Never cancel a batch
// merely because it is currently visible: retain the exact ID this flow issued.
export async function measureAndRank(profile: Draft, flow: Flow): Promise<SavedRanking> {
  const current = () => {
    if (!flow.current()) throw new Error('selector_measurements_cancelled');
  };
  const pause = flow.pause ?? (() => new Promise<void>((resolve) => setTimeout(resolve, 120)));
  const now = flow.now ?? (() => performance.now());
  current();
  const plan = await flow.command('planSelectorMeasurements', { profile });
  current();
  // A disposable Core check warms the connection, then measures it. Match the
  // backend's two-request/IPC budget even when the queue runs one server at a time.
  const deadline = now() + 30_000 + plan.ids.length * (2 * plan.timeoutMs + 9000);
  let done = 0;
  const progress = (phase: MeasurementProgress['phase'], completed = done) =>
    flow.progress({ total: plan.ids.length, done: completed, fresh: plan.freshCount, phase });
  progress('measuring');
  for (let start = 0; start < plan.ids.length; start += limits.maxBatchProfiles) {
    current();
    const ids = plan.ids.slice(start, start + limits.maxBatchProfiles);
    const expected = new Set(ids);
    const run = await flow.command('startUrlTests', {
      ids,
      url: plan.url,
      timeoutMs: plan.timeoutMs,
    });
    let completed = false;
    flow.batch(run.id);
    try {
      // Covers cancellation while startUrlTests was returning the issued ID.
      current();
      while (true) {
        current();
        if (now() > deadline) throw new Error('selector_measurements_timeout');
        const snapshot = await flow.command('snapshot');
        current();
        const batch = snapshot.urlTests;
        if (
          !batch ||
          batch.id !== run.id ||
          batch.url !== plan.url ||
          batch.method !== 'http' ||
          batch.entries.length !== ids.length ||
          new Set(batch.entries.map((e) => e.profileId)).size !== ids.length ||
          batch.entries.some((e) => !expected.has(e.profileId))
        ) {
          throw new Error('selector_measurements_interrupted');
        }
        if (batch.entries.some((e) => !['queued', 'testing', 'ok', 'error'].includes(e.status))) {
          throw new Error('selector_measurements_interrupted');
        }
        const finished = batch.entries.filter((e) => e.status === 'ok' || e.status === 'error').length;
        progress('measuring', done + finished);
        if (finished === ids.length) {
          completed = true;
          break;
        }
        await pause();
      }
    } finally {
      if (!completed) {
        try {
          await flow.command('cancelUrlTestBatch', { id: run.id });
        } catch {
          /* app shutdown can close IPC */
        }
      }
      flow.batch(undefined);
    }
    done += ids.length;
  }
  current();
  progress('ranking');
  const ranking = await flow.command('rankMeasuredSelector', {
    profile,
    context: plan.context,
  });
  current();
  return ranking;
}
