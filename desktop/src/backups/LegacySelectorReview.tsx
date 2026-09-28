import { Checkbox } from '../shared/ui/controls';
import type { useLegacyReview } from './useLegacyReview';
export default function LegacySelectorReview({
  controller,
}: {
  controller: ReturnType<typeof useLegacyReview>;
}) {
  const { busy, changeScopes, data, t } = controller;

  return (
    <div id="legacy-selector-review">
      <label className="import-toggle">
        <Checkbox
          type="checkbox"
          id="legacy-selector-snapshot"
          disabled={busy}
          checked={data.scopes.autoSelectors === 'last-built'}
          onChange={(e) =>
            changeScopes({
              ...data.scopes,
              autoSelectors: e.target.checked ? 'last-built' : 'require-choice',
            })
          }
        />
        {t('selectorChoice')}
      </label>
      <p className="field-hint">{t('selectorHint')}</p>
      {(data.selectorSnapshots || []).length > 0 && (
        <ul id="legacy-selector-snapshots">
          {data.selectorSnapshots!.slice(0, 50).map((row) => (
            <li key={row.sourceId}>
              {row.name}: {row.members} {t('selectorMembers')}
              {row.pinned ? `; ${t('selectorPinned')}` : ''}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
