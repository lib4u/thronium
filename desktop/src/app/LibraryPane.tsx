import { Button, Select, Checkbox, SearchField } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import { command } from '../api';
import { Icon } from '../ui';
import { exportText } from '../profiles/ExportDialog';
import { duplicateText } from '../library/DuplicatesDialog';
import LibraryToolbar from '../library/Toolbar';
import ProfileRow from '../library/ProfileRow';
import { displayedData } from '../library/rowData';
import { maintenanceText } from '../library/MaintenanceDialog';
import PingStatus from '../probes/LibraryStatus';
import { tr as probeText, libraryBatch } from '../probes/messages';
import LibraryGroups from '../groups/LibraryGroups';
import AutoSelectCard from '../selectors/AutoSelectCard';
import { AUTO_SELECT_ID } from '../selectors/autoSelectModel.ts';
import { jobActive, jobNeedsAttention } from '../groups/jobStatus';
import { tr as groupText } from '../groups/messages';
import type { useAppController } from '../useAppController';
import { limits } from '../shared/api/generated/limits.ts';
import { profilesOf } from '../groups/groupModel';
export default function LibraryPane({ controller }: { controller: ReturnType<typeof useAppController> }) {
  const {
    busy,
    perform,
    setModal,
    setToast,
    state,
    t,
    translateError,
    profiles: { batchText: bt, openNew, savePreferences },
    library: {
      favorites,
      group,
      groupLabel,
      groupViews,
      matches,
      profileDrag,
      protocol,
      query,
      resetFilters,
      searching,
      selectedIds,
      selecting,
      selection,
      setFavorites,
      setGroup,
      setProtocol,
      setQuery,
      setSelecting,
      setSelection,
      toggleGroup,
      visibleMatches,
    },
    menus: { menu, openMenu },
    probes: { probeAction, probeBusy, probesBlocked, probing },
    navigation: { openSettings },
  } = controller;
  const view = displayedData(state.appearance);

  return (
    <section className="library-pane" aria-label={t('servers')} ref={profileDrag.root}>
      <div className="pane-heading library-heading">
        <div>
          <h2>{t('servers')}</h2>
          <span className="connection-count">{state.profiles.length}</span>
        </div>
        <div className="library-heading-actions">
          <Button
            className="icon-button"
            id="open-probes"
            disabled={probeBusy || (!probing && (!matches.length || !state.coreAvailable))}
            title={probeText(probing ? 'cancel' : 'visible', state.preferences.language)}
            aria-label={probeText(probing ? 'cancel' : 'visible', state.preferences.language)}
            onClick={() =>
              void probeAction(
                probing ? 'cancelUrlTests' : 'startPing',
                probing ? undefined : matches.map((p) => p.id),
              )
            }
          >
            <Icon name={probing ? 'x' : 'activity'} />
          </Button>
          <Button
            className="button secondary add-connection"
            title={t('addConfiguration')}
            aria-label={t('addConfiguration')}
            onClick={openNew}
          >
            <Icon name="plus" />
            {t('add')}
          </Button>
        </div>
      </div>
      <div className="library-compact-search">
        <div className="group-strip">
          <Select
            className="text-input"
            aria-label={t('group')}
            value={group}
            onChange={(e) => setGroup(e.target.value)}
          >
            <option value="all">
              {t('allGroups')} · {state.profiles.length}
            </option>
            {state.groups.map((g) => (
              <option key={g.id} value={g.id}>
                {groupLabel(g.id)} · {profilesOf(state.profiles, g.id).length}
              </option>
            ))}
          </Select>
          <Button
            className="icon-button"
            title={t('groups')}
            aria-label={t('groups')}
            onClick={() => setModal({ type: 'groups' })}
          >
            <Icon name="folder" />
          </Button>
        </div>
        <div className="library-search">
          <SearchField
            id="client-search"
            placeholder={translate(state.preferences.language, 'common.search_servers_209030d')}
            aria-label={t('search')}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          >
            <kbd>/</kbd>
          </SearchField>
        </div>
      </div>
      <div className="library-tabs">
        <Button
          className={favorites ? '' : 'active'}
          aria-pressed={!favorites}
          onClick={() => setFavorites(false)}
        >
          {t('all')}
        </Button>
        <Button
          className={favorites ? 'active' : ''}
          aria-pressed={favorites}
          onClick={() => setFavorites(true)}
        >
          <Icon name="star" />
          {t('favorites')}
        </Button>
        <LibraryToolbar
          preferences={state.preferences}
          busy={busy}
          protocols={[...new Set(state.profiles.map((p) => p.protocol))].sort()}
          protocol={protocol}
          filter={setProtocol}
          selecting={selecting}
          select={() => {
            setSelecting(!selecting);
            setSelection(new Set());
          }}
          save={savePreferences}
          view={view}
          displayedData={() => openSettings('appearance', 'setting-list_show_traffic')}
          canDeduplicate={matches.length >= 2 && matches.length <= limits.maxBatchProfiles}
          canExport={matches.length > 0 && matches.length <= limits.maxBatchProfiles}
          duplicates={() => setModal({ type: 'duplicates', ids: matches.map((p) => p.id) })}
          maintenance={(kind) => setModal({ type: 'maintenance', kind, ids: matches.map((p) => p.id) })}
          exportProfiles={() => setModal({ type: 'export', ids: matches.map((p) => p.id) })}
        />
      </div>
      {selecting && (
        <div className="library-batch-toolbar">
          <label className="import-toggle">
            <Checkbox
              type="checkbox"
              id="bulk-select-visible"
              disabled={busy || !visibleMatches.length}
              checked={visibleMatches.length > 0 && visibleMatches.every((p) => selection.has(p.id))}
              ref={(el) => {
                if (el)
                  el.indeterminate =
                    visibleMatches.some((p) => selection.has(p.id)) &&
                    !visibleMatches.every((p) => selection.has(p.id));
              }}
              onChange={(e) =>
                setSelection((old) => {
                  const next = new Set(old);
                  for (const p of visibleMatches) {
                    if (!e.target.checked) next.delete(p.id);
                    else if (next.size < limits.maxBatchProfiles) next.add(p.id);
                  }
                  return next;
                })
              }
            />
            {bt('visible')}
          </label>
          <span id="bulk-count">
            {bt('selected')}: {selectedIds.length}
          </span>
          <div className="library-batch-actions">
            <Button
              className="text-button"
              id="bulk-move"
              disabled={!selectedIds.length || busy}
              onClick={() => setModal({ type: 'batch', operation: 'move', ids: selectedIds })}
            >
              {bt('move')}
            </Button>
            <Button
              className="text-button"
              id="bulk-probe"
              disabled={!selectedIds.length || busy || probesBlocked}
              onClick={() => void probeAction('startPing', selectedIds)}
            >
              {bt('test')}
            </Button>
            <Button
              className="text-button"
              id="bulk-ip"
              disabled={!selectedIds.length || busy || probesBlocked}
              onClick={() => void probeAction('startIpTests', selectedIds)}
            >
              {bt('ip')}
            </Button>
            <Button
              className="text-button"
              id="bulk-speed"
              disabled={!selectedIds.length || busy || probesBlocked}
              onClick={() => void probeAction('startSpeedTests', selectedIds)}
            >
              {bt('speed')}
            </Button>
            <Button
              className="text-button"
              id="bulk-export"
              disabled={!selectedIds.length || busy}
              onClick={() => setModal({ type: 'export', ids: selectedIds })}
            >
              {exportText('title', state.preferences.language)}
            </Button>
            <Button
              className="text-button"
              id="bulk-duplicates"
              disabled={selectedIds.length < 2 || busy}
              onClick={() => setModal({ type: 'duplicates', ids: selectedIds })}
            >
              {duplicateText('open', state.preferences.language)}
            </Button>
            <Button
              className="text-button"
              id="bulk-reset-traffic"
              disabled={!selectedIds.length || busy}
              onClick={() =>
                void perform(
                  () => command('resetProfileTraffic', { ids: selectedIds }),
                  () =>
                    setToast(
                      translate(state.preferences.language, 'library.maintenance_traffic_done', {
                        count: selectedIds.length,
                      }),
                    ),
                )
              }
            >
              {maintenanceText('resetTraffic', state.preferences.language)}
            </Button>
            <Button
              className="text-button"
              id="bulk-delete"
              disabled={!selectedIds.length || busy}
              onClick={() => setModal({ type: 'batch', operation: 'remove', ids: selectedIds })}
            >
              {bt('remove')}
            </Button>
          </div>
        </div>
      )}
      <PingStatus
        batch={libraryBatch(state.urlTests)}
        language={state.preferences.language}
        busy={probeBusy}
        cancel={() => void probeAction('cancelUrlTests')}
        clear={() => void probeAction('clearUrlTests')}
        settings={() => openSettings('testing')}
      />
      {state.preferences.autoSelect.enabled && (
        <AutoSelectCard
          language={state.preferences.language}
          selected={(state.running || state.selected) === AUTO_SELECT_ID}
          count={state.autoSelectMemberCount}
          failover={state.preferences.autoSelect.failover}
          disabled={!state.autoSelectAvailable}
          onSelect={() => void perform(() => command('select', { id: AUTO_SELECT_ID }))}
          onConfigure={() => setModal({ type: 'auto-select-config' })}
        />
      )}
      <LibraryGroups
        probeBusy={probesBlocked}
        snapshot={state}
        views={groupViews}
        filtered={searching || favorites}
        busy={busy}
        t={t}
        translateError={translateError}
        reorder={(id, targetId, after) =>
          void perform(() => command('reorderGroup', { id, targetId, after }))
        }
        toggle={toggleGroup}
        update={(id) => void perform(() => command('startSubscriptionUpdates', { id }))}
        probe={(id) =>
          void probeAction(
            'startPing',
            profilesOf(state.profiles, id).map((p) => p.id),
          )
        }
        menu={(id, anchor, edge) => openMenu('group', id, anchor, edge)}
        menuGroupId={menu?.type === 'group' ? menu.id : undefined}
        tasks={() => setModal({ type: 'updates' })}
        review={(groupId) => setModal({ type: 'subscription', groupId, autoLoad: true })}
        add={(initialGroup) => setModal({ type: 'add', initialGroup })}
        reset={resetFilters}
        renderProfile={(p) => <ProfileRow key={p.id} profile={p} view={view} controller={controller} />}
      />
      <div className="library-footer">
        {state.subscriptionJobs.length > 0 && (
          <Button
            id="subscription-job-status"
            className="text-button subscription-job-status"
            onClick={() => setModal({ type: 'updates' })}
          >
            {groupText('updates', state.preferences.language)} ·{' '}
            {state.subscriptionJobs.some((j) => jobActive(j.status))
              ? `${groupText('pending', state.preferences.language)}: ${state.subscriptionJobs.filter((j) => jobActive(j.status)).length}`
              : state.subscriptionJobs.some((j) => jobNeedsAttention(j.status))
                ? `${groupText('needs-review', state.preferences.language)}: ${state.subscriptionJobs.filter((j) => jobNeedsAttention(j.status)).length}`
                : `${groupText('finished', state.preferences.language)}: ${state.subscriptionJobs.length}`}
          </Button>
        )}
        <div className="library-footer-info">
          <span>
            {t('core')} · {t(state.coreAvailable ? 'coreReady' : 'coreMissing')}
          </span>
          <span>
            {translate(state.preferences.language, 'common.shown_of', {
              shown: visibleMatches.length,
              total: state.profiles.length,
            })}
          </span>
        </div>
      </div>
    </section>
  );
}
