import type { Snapshot } from '../api';
import { AUTO_SELECT_ID } from './autoSelectModel.ts';
import { autoSelectStatus, quickSelectPool } from './autoSelectStatus.ts';
import { useAutoSelectorPools } from './autoSelectorPools.ts';

/** The quick pool's host per connection, resolved against the latest profile
 * list. The detailed pool panel reports read errors; the last host stays. */
export function useAutoSelectStatus(snapshot: Snapshot) {
  const generation = snapshot.running === AUTO_SELECT_ID ? `${snapshot.running}:${snapshot.since}` : null;
  const pool = quickSelectPool(useAutoSelectorPools(generation)?.pools ?? []);
  return pool ? autoSelectStatus(pool, snapshot.profiles) : undefined;
}
