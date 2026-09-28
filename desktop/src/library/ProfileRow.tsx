import { Button, Checkbox } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import { command } from '../api';
import type { Profile } from '../api';
import { Icon } from '../ui';
import { menuTriggerProps } from '../DropdownMenu';
import { orderText, orderHint } from './profileOrder';
import { profileName } from './profileName';
import { latency, result as probeResult, batchEntry, tooltip as probeTooltip } from '../probes/messages';
import { rowStats, rowSubtitle, securityWarning, type DisplayedData } from './rowData';
import type { useAppController } from '../useAppController';
import { limits } from '../shared/api/generated/limits.ts';

// One server row: name, the subtitle and stats chosen in "Displayed data",
// the latency column, favourite and the row menu. Text comes from rowData.
export default function ProfileRow({
  profile: p,
  view,
  controller,
}: {
  profile: Profile;
  view: DisplayedData;
  controller: ReturnType<typeof useAppController>;
}) {
  const {
    busy,
    perform,
    state,
    t,
    profiles: { batchText: bt },
    connection: { connectAction },
    menus: { menu, openMenu },
    library: { moveNeighbor, orderReason, profileDrag, selectedIds, selecting, selection, toggleSelected },
  } = controller;
  const language = state.preferences.language;
  const name = profileName(p.name);
  const subscribed = !!state.groups.find((g) => g.id === p.groupId)?.subscribed;
  const hint = orderHint(orderReason, subscribed, language);
  const stats = rowStats(p, view, language);
  const warning = securityWarning(p, view) ? translate(language, 'library.insecure_transport') : '';
  const entry = batchEntry(state.urlTests, p.id);
  return (
    <div
      className={`connection-row ${p.id === state.selected ? 'selected' : ''}`}
      data-order-profile={p.id}
      data-profile-dragging={profileDrag.source === p.id || undefined}
      data-profile-drop={
        profileDrag.target?.id === p.id ? (profileDrag.target.after ? 'after' : 'before') : undefined
      }
    >
      {selecting && (
        <Checkbox
          className="bulk-profile-check"
          type="checkbox"
          data-bulk-profile={p.id}
          aria-label={`${bt('selected')}: ${p.name}`}
          checked={selection.has(p.id)}
          disabled={!selection.has(p.id) && selectedIds.length >= limits.maxBatchProfiles}
          onChange={() => toggleSelected(p.id)}
        />
      )}
      <Button
        className="profile-order-handle"
        data-profile-drag={p.id}
        draggable={false}
        disabled={!profileDrag.canStart(p.id)}
        aria-label={`${orderText('drag', language)}: ${p.name}`}
        aria-description={hint}
        title={hint}
        aria-keyshortcuts="Alt+ArrowUp Alt+ArrowDown"
        aria-haspopup="menu"
        aria-expanded={menu?.anchor.dataset.profileDrag === p.id}
        onPointerDown={(e) => profileDrag.start(e, p.id)}
        onPointerMove={profileDrag.over}
        onPointerUp={profileDrag.drop}
        onPointerCancel={profileDrag.finish}
        onLostPointerCapture={profileDrag.finish}
        onClick={(e) => {
          if (!profileDrag.ignoreClick()) openMenu('profile', p.id, e.currentTarget);
        }}
        onKeyDown={(e) => {
          if (e.key !== 'ArrowUp' && e.key !== 'ArrowDown') return;
          e.preventDefault();
          e.stopPropagation();
          if (e.altKey && !e.ctrlKey && !e.metaKey) moveNeighbor(p.id, e.key === 'ArrowUp' ? -1 : 1);
          else if (!e.altKey && !e.ctrlKey && !e.metaKey)
            openMenu('profile', p.id, e.currentTarget, e.key === 'ArrowUp' ? 'last' : 'first');
        }}
      >
        <Icon name="grip-vertical" />
      </Button>
      <Button
        className="connection-row-button"
        aria-label={p.name}
        title={p.name}
        aria-pressed={selecting ? selection.has(p.id) : p.id === state.selected}
        disabled={busy}
        onClick={() => {
          if (profileDrag.ignoreClick()) return;
          if (selecting) toggleSelected(p.id);
          else
            void (state.running
              ? connectAction('connect', p.id)
              : perform(() => command('select', { id: p.id })));
        }}
      >
        <span className={`desktop-profile-icon ${name.emoji ? 'profile-emoji' : ''}`} aria-hidden="true">
          {name.emoji || <Icon name="server" />}
        </span>
        <span className="row-server-info">
          <strong>
            {name.text}
            {state.running === p.id && <span className="row-current-dot" />}
          </strong>
          <small>
            {warning && (
              <span className="row-security-warn" role="img" aria-label={warning} title={warning}>
                <Icon name="alert" />
              </span>
            )}
            {rowSubtitle(p, view, language)}
          </small>
          {stats.text && (
            <small className="row-stats" data-profile-stats={p.id} title={stats.title}>
              {stats.text}
            </small>
          )}
        </span>
        {view.list_show_latency && (
          <span
            className="row-ping"
            data-profile-latency={p.id}
            data-probe-status={(entry || p.measurement)?.status}
            title={probeTooltip(entry || p.measurement, language)}
          >
            {entry ? probeResult(entry, language) : latency(p.measurement, language)}
          </span>
        )}
      </Button>
      <Button
        className={`icon-button favorite-button ${p.favorite ? 'is-favorite' : ''}`}
        aria-label={`${t('favorites')}: ${p.name}`}
        aria-pressed={p.favorite}
        onClick={() => void perform(() => command('favorite', { id: p.id }))}
      >
        <Icon name="star" />
      </Button>
      <Button
        className="icon-button row-more"
        data-profile-menu={p.id}
        disabled={busy}
        aria-label={`${t('parameters')}: ${p.name}`}
        {...menuTriggerProps(menu?.type === 'profile' && menu.id === p.id, (anchor, edge) =>
          openMenu('profile', p.id, anchor, edge),
        )}
      >
        <Icon name="more" />
      </Button>
    </div>
  );
}
