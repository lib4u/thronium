import { Button, Checkbox } from '../shared/ui/controls';
import { translate, type Language } from '../shared/i18n/index.ts';
import { formatDateTime, formatMilliseconds, formatTime } from '../shared/i18n/format.ts';
import { useState } from 'react';
import type * as Wire from '../shared/api/generated/commands';
type SelectorMember = Wire.SelectorMember;
type SelectorPool = Wire.SelectorPool;
import { descendingFirst, hasProblem, memberNote, sortMembers, type MemberSort } from './memberRows';

const columns: { id: MemberSort | 'note'; label: string; hint?: string }[] = [
  { id: 'rank', label: 'library.member_column_rank' },
  { id: 'name', label: 'library.member_column_name' },
  { id: 'state', label: 'library.member_column_state' },
  { id: 'latency', label: 'library.member_column_latency' },
  { id: 'jitter', label: 'library.member_column_jitter', hint: 'library.member_jitter_hint' },
  { id: 'checks', label: 'library.member_column_checks' },
  { id: 'dials', label: 'library.member_column_dials', hint: 'library.member_dials_hint' },
  { id: 'lastOk', label: 'library.member_column_last_ok' },
  { id: 'note', label: 'library.member_column_note' },
];
/** Qt's note keys; a dead member shows the probe code the core reported. */
const noteKeys: Record<string, string> = {
  notePinnedSelected: 'library.member_note_pinned_selected',
  notePinnedUnusable: 'library.member_note_pinned_unusable',
  noteSelected: 'library.member_note_selected',
  noteCooldown: 'library.member_note_cooldown',
  noteCooldownIn: 'library.member_note_cooldown_in',
  noteDead: 'library.member_note_dead',
  noteQualified: 'library.member_note_qualified',
  noteChecking: 'library.member_note_checking',
  noteQueued: 'library.member_note_queued',
  noteFailures: 'library.member_note_failures',
};

/** Qt's auto-selector statistics table: one row per member, sortable, filterable. */
export default function MemberTable({
  pool,
  language,
  busy,
  stateText,
  translateError,
  pin,
}: {
  pool: SelectorPool;
  language: Language;
  busy: boolean;
  stateText(state: string): string;
  translateError(code: string): string;
  pin(member: SelectorMember): void;
}) {
  const [sort, setSort] = useState<MemberSort>('rank');
  const [descending, setDescending] = useState(false);
  const [problems, setProblems] = useState(false);
  const t = (key: string, params?: Record<string, number | string>) =>
    translate(language, key as Parameters<typeof translate>[1], params);
  const rows = sortMembers(problems ? pool.members.filter(hasProblem) : pool.members, sort, descending);
  const now = Date.now();
  const ok = (total: number, failures: number) =>
    total > 0 ? t('library.member_ok_of', { ok: total - failures, total }) : '—';
  function note(member: SelectorMember) {
    const value = memberNote(member, pool, now);
    if (!value) return '';
    const key = noteKeys[value.key];
    return key ? t(key, value.params) : translateError(value.key);
  }
  return (
    <div className="selector-member-table" data-selector-members={pool.tag}>
      <label className="import-toggle">
        <Checkbox
          type="checkbox"
          data-selector-problems={pool.tag}
          checked={problems}
          onChange={(event) => setProblems(event.target.checked)}
        />
        {t('library.member_only_problems')}
      </label>
      <table>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.id} title={column.hint ? t(column.hint) : undefined}>
                {column.id === 'note' ? (
                  t(column.label)
                ) : (
                  <Button
                    className="text-button"
                    data-selector-sort={column.id}
                    aria-sort={sort === column.id ? (descending ? 'descending' : 'ascending') : undefined}
                    onClick={() => {
                      const next = column.id as MemberSort;
                      if (next === sort) setDescending(!descending);
                      else {
                        setSort(next);
                        setDescending(descendingFirst.includes(next));
                      }
                    }}
                  >
                    {t(column.label)}
                    {sort === column.id ? (descending ? ' ↓' : ' ↑') : ''}
                  </Button>
                )}
              </th>
            ))}
            <th />
          </tr>
        </thead>
        <tbody>
          {rows.map((member) => (
            <tr key={member.tag} data-selector-live-member={member.profileId || member.tag}>
              <td>{member.rank}</td>
              <td className={member.selected ? 'selector-member-current' : undefined}>
                <span title={member.tag}>{member.name}</span>
              </td>
              <td data-selector-member-state={member.state}>{stateText(member.state)}</td>
              <td
                title={
                  member.samples > 0
                    ? t('library.member_latency_range', { min: member.minMs, max: member.maxMs })
                    : undefined
                }
              >
                {member.samples > 0 && member.averageMs > 0
                  ? formatMilliseconds(member.averageMs, language)
                  : '—'}
              </td>
              <td>{member.samples > 0 ? formatMilliseconds(member.deviationMs, language) : '—'}</td>
              <td>{ok(member.samples, member.failures)}</td>
              <td data-selector-member-dials>{ok(member.dialTotal, member.dialFailures)}</td>
              <td
                data-selector-member-last-ok
                title={member.lastOkMs > 0 ? formatDateTime(member.lastOkMs, language) : undefined}
              >
                {member.lastOkMs > 0 ? formatTime(member.lastOkMs, language) : t('library.member_never')}
              </td>
              <td data-selector-member-note>{note(member)}</td>
              <td>
                <Button
                  className="text-button"
                  data-selector-pin={member.profileId || member.tag}
                  disabled={busy || pool.pinned === member.tag}
                  onClick={() => pin(member)}
                >
                  {t(
                    pool.pinned === member.tag
                      ? 'library.pinned_179addd'
                      : 'library.pin_for_this_session_e897fb3',
                  )}
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!rows.length && <p data-selector-members-empty>{t('library.member_no_problems')}</p>}
    </div>
  );
}
