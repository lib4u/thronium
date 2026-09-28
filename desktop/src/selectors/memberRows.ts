import type * as Wire from '../shared/api/generated/commands';
type SelectorMember = Wire.SelectorMember;
type SelectorPool = Wire.SelectorPool;

/** The columns Qt's auto-selector statistics sorts by. */
export type MemberSort = 'rank' | 'name' | 'state' | 'latency' | 'jitter' | 'checks' | 'dials' | 'lastOk';
/** Columns Qt opens descending: the most recent success and the largest counts. */
export const descendingFirst: MemberSort[] = ['lastOk', 'checks', 'dials'];
/** Qt's state order: working first, failing last. */
const stateOrder = (state: string) => ({ ok: 0, degraded: 1, untested: 2, cooldown: 3 })[state] ?? 4;
/** Qt's `hasProblem`: what the "only problems" filter keeps. */
export const hasProblem = (member: SelectorMember) => ['dead', 'cooldown', 'degraded'].includes(member.state);
/** A value that is missing sorts last in both directions, as in Qt. */
type Key = { known: boolean; value: number };
const key = (member: SelectorMember, sort: MemberSort): Key => {
  switch (sort) {
    case 'latency':
      return { known: member.samples > 0 && member.averageMs > 0, value: member.averageMs };
    case 'jitter':
      return { known: member.samples > 0, value: member.deviationMs };
    case 'checks':
      return {
        known: member.samples > 0,
        value: member.samples > 0 ? (member.samples - member.failures) / member.samples : 0,
      };
    case 'dials':
      return {
        known: member.dialTotal > 0,
        value: member.dialTotal > 0 ? (member.dialTotal - member.dialFailures) / member.dialTotal : 0,
      };
    case 'lastOk':
      return { known: member.lastOkMs > 0, value: member.lastOkMs };
    case 'state':
      return { known: true, value: stateOrder(member.state) };
    default:
      return { known: true, value: member.rank };
  }
};
/**
 * Qt's ordering: the chosen column decides, an unknown value sinks to the
 * bottom either way, and rank breaks every tie so rows do not shuffle between
 * polls.
 */
export function sortMembers(
  members: SelectorMember[],
  sort: MemberSort,
  descending: boolean,
): SelectorMember[] {
  const direction = descending ? -1 : 1;
  return [...members].sort((a, b) => {
    if (sort === 'name') {
      const compared = a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
      if (compared) return compared * direction;
      return a.rank - b.rank;
    }
    const left = key(a, sort),
      right = key(b, sort);
    if (left.known !== right.known) return left.known ? -1 : 1;
    if (left.known && left.value !== right.value) return (left.value - right.value) * direction;
    return a.rank - b.rank;
  });
}
/** Qt's note column: why this member is where it is. */
export function memberNote(
  member: SelectorMember,
  pool: SelectorPool,
  nowMs: number,
): { key: string; params?: Record<string, number | string> } | null {
  const pinned = pool.pinned === member.tag;
  if (pinned) return { key: member.selected ? 'notePinnedSelected' : 'notePinnedUnusable' };
  if (member.selected) return { key: 'noteSelected' };
  if (member.state === 'cooldown') {
    const seconds = Math.round((member.cooldownUntilMs - nowMs) / 1000);
    return seconds > 0 ? { key: 'noteCooldownIn', params: { seconds } } : { key: 'noteCooldown' };
  }
  if (member.state === 'dead') return { key: member.lastError || 'noteDead' };
  if (member.qualified) return { key: 'noteQualified' };
  if (member.state === 'untested') return { key: member.active ? 'noteChecking' : 'noteQueued' };
  if (member.failures > 0)
    return { key: 'noteFailures', params: { failures: member.failures, samples: member.samples } };
  return null;
}
