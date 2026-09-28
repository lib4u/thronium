import { Button } from '../shared/ui/controls';
import { formatDateTime, formatDate } from '../shared/i18n/format.ts';
import { useState, type ReactNode } from 'react';
import type { Group, Profile, Snapshot } from '../api';
import type { Key } from '../i18n';
import { Icon } from '../ui';
import DropdownMenu, { menuTriggerProps, type MenuEdge, type MenuItem } from '../DropdownMenu';
import {
  tr,
  message,
  usageText,
  updatedText,
  bytes,
  intervalText,
  usedTraffic,
  type Language,
} from './messages';
import { libraryBatch } from '../probes/messages';
import { jobActive } from './jobStatus';
import { groupName, isPersonalGroup, profilesOf } from './groupModel';
import { active as probeActive } from '../probes/messages';
import './LibraryGroups.css';
import useGroupDrag from './useGroupDrag';

export type GroupView = { group: Group; profiles: Profile[]; total: number; collapsed: boolean };

function Announcement({ value, language }: { value: string; language: Language }) {
  const [expanded, setExpanded] = useState(false);
  const expandable = value.length > 200 || value.split('\n').length > 3;
  return (
    <div className="group-announcement" role="note" aria-label={tr('announcement', language)}>
      <Icon name="info" />
      <div>
        <p className={!expanded && expandable ? 'announcement-summary' : ''}>{value}</p>
        {expandable && (
          <Button className="text-button" aria-expanded={expanded} onClick={() => setExpanded(!expanded)}>
            {tr(expanded ? 'less' : 'more', language)}
          </Button>
        )}
      </div>
    </div>
  );
}

export function GroupMenu({
  snapshot,
  group,
  busy,
  probeBusy,
  anchor,
  edge,
  close,
  edit,
  remove,
  move,
  review,
  update,
  probe,
}: {
  snapshot: Snapshot;
  group: Group;
  busy: boolean;
  probeBusy: boolean;
  anchor: HTMLButtonElement;
  edge?: MenuEdge;
  close(): void;
  edit(): void;
  remove(): void;
  move(offset: number): void;
  review(): void;
  update(): void;
  probe(): void;
}) {
  const lang = snapshot.preferences.language;
  const t = (k: Parameters<typeof tr>[0]) => tr(k, lang);
  const index = snapshot.groups.findIndex((g) => g.id === group.id);
  const updating = snapshot.subscriptionJobs.some((j) => j.groupId === group.id && jobActive(j.status));
  const items: MenuItem[] = [];
  if (group.subscribed)
    items.push({
      id: 'menu-update-group',
      label: t('update'),
      icon: 'refresh',
      disabled: busy || updating,
      select: update,
    });
  items.push({
    id: 'menu-probe-group',
    label: t('groupProbe'),
    icon: 'activity',
    disabled: busy || probeBusy || !profilesOf(snapshot.profiles, group.id).length,
    select: probe,
  });
  if (group.subscribed)
    items.push({
      id: 'update-subscription',
      label: t('reviewUpdate'),
      icon: 'download',
      disabled: busy || updating,
      select: review,
    });
  if (!isPersonalGroup(group.id))
    items.push({
      id: 'menu-edit-group',
      groupAction: 'edit',
      label: t('edit'),
      icon: 'edit',
      disabled: busy,
      separator: true,
      select: edit,
    });
  items.push({
    id: 'menu-group-up',
    groupAction: 'up',
    label: t('up'),
    icon: 'arrow-up',
    disabled: busy || index === 0,
    select: () => move(-1),
  });
  items.push({
    id: 'menu-group-down',
    groupAction: 'down',
    label: t('down'),
    icon: 'arrow-down',
    disabled: busy || index === snapshot.groups.length - 1,
    select: () => move(1),
  });
  if (!isPersonalGroup(group.id))
    items.push({
      id: 'menu-delete-group',
      groupAction: 'delete',
      label: t('remove'),
      icon: 'trash',
      danger: true,
      separator: true,
      disabled: busy,
      select: remove,
    });
  return (
    <DropdownMenu
      anchor={anchor}
      edge={edge}
      label={`${t('groupMenu')}: ${groupName(group, lang)}`}
      items={items}
      close={close}
    />
  );
}

export default function LibraryGroups({
  snapshot,
  views,
  filtered,
  busy,
  probeBusy,
  t,
  translateError,
  renderProfile,
  toggle,
  update,
  probe,
  menu,
  menuGroupId,
  tasks,
  review,
  add,
  reset,
  reorder,
}: {
  snapshot: Snapshot;
  views: GroupView[];
  filtered: boolean;
  busy: boolean;
  probeBusy: boolean;
  t(k: Key): string;
  translateError(e: unknown): string;
  reorder(id: string, target: string, after: boolean): void;
  renderProfile(profile: Profile): ReactNode;
  toggle(view: GroupView): void;
  update(id: string): void;
  probe(id: string): void;
  menu(id: string, anchor: HTMLButtonElement, edge?: MenuEdge): void;
  menuGroupId?: string;
  tasks(): void;
  review(id: string): void;
  add(id?: string): void;
  reset(): void;
}) {
  const lang = snapshot.preferences.language;
  const gt = (k: Parameters<typeof tr>[0]) => tr(k, lang);
  const drag = useGroupDrag(
    views.map((v) => v.group.id),
    busy,
    reorder,
  );
  const profileGroups = new Map(snapshot.profiles.map((p) => [p.id, p.groupId]));
  return (
    <div ref={drag.list} className="connections-scroll grouped-library">
      {views.map((view) => {
        const { group: g, profiles, collapsed, total } = view;
        const name = groupName(g, lang);
        const job = snapshot.subscriptionJobs.find((j) => j.groupId === g.id && jobActive(j.status));
        const interval = g.intervalMinutes || 0;
        const schedule = interval ? intervalText(interval, lang) : gt('manualSchedule');
        const usage = g.usage;
        const used = usedTraffic(usage);
        const percentage =
          used !== null && usage?.total ? Math.min(100, Math.max(0, (used / usage.total) * 100)) : null;
        const measures =
          libraryBatch(snapshot.urlTests)?.entries.filter((e) => profileGroups.get(e.profileId) === g.id) ||
          [];
        const probing = measures.some((m) => probeActive(m.status));
        const remaining = measures.filter((m) => probeActive(m.status)).length;
        const error = g.lastUpdate?.error;
        return (
          <section
            className={`subscription-group library-group ${drag.source === g.id ? 'group-drag-source' : ''} ${drag.target?.id === g.id ? (drag.target.after ? 'group-drop-after' : 'group-drop-before') : ''}`}
            data-library-group={g.id}
            key={g.id}
            aria-label={name}
          >
            <div className="subscription-group-head">
              <Button
                className="subscription-collapse"
                data-group-collapse={g.id}
                aria-expanded={!collapsed}
                aria-controls={`group-rows-${g.id}`}
                aria-label={`${gt(collapsed ? 'expand' : 'collapse')}: ${name}`}
                disabled={busy}
                draggable={false}
                data-group-drag={drag.enabled ? g.id : undefined}
                title={drag.enabled ? gt('dragGroup') : undefined}
                onPointerDown={(e) => drag.start(e, g.id)}
                onPointerMove={drag.over}
                onPointerUp={drag.drop}
                onPointerCancel={drag.end}
                onLostPointerCapture={drag.end}
                onClick={() => {
                  if (!drag.ignoreClick()) toggle(view);
                }}
              >
                {drag.enabled && (
                  <span className="group-drag-grip" aria-hidden="true">
                    <Icon name="grip" />
                  </span>
                )}
                <Icon name="chevron-down" />
                <span className="library-group-label">
                  <span className="library-group-title">
                    <strong>{name}</strong>
                    <span className="connection-count">
                      {filtered && profiles.length !== total ? `${profiles.length} / ${total}` : total}
                    </span>
                    {snapshot.running && profileGroups.get(snapshot.running) === g.id && (
                      <span className="group-connected" title={t('connected')} aria-label={t('connected')} />
                    )}
                  </span>
                  <small>{g.subscribed ? `${updatedText(g, lang)} · ${schedule}` : t('savedProfiles')}</small>
                </span>
              </Button>
              <div className="library-group-actions">
                {g.subscribed && (
                  <Button
                    className={`icon-button ${job ? 'group-updating' : ''}`}
                    data-group-refresh={g.id}
                    disabled={busy || !!job}
                    title={gt('update')}
                    aria-label={`${gt('update')}: ${name}`}
                    onClick={() => update(g.id)}
                  >
                    <Icon name="refresh" />
                  </Button>
                )}
                <Button
                  className="icon-button"
                  data-group-probe={g.id}
                  disabled={!total || busy || probeBusy}
                  aria-busy={probing}
                  title={gt('groupProbe')}
                  aria-label={`${gt('groupProbe')}: ${name}`}
                  onClick={() => probe(g.id)}
                >
                  <Icon name="activity" />
                </Button>
                <Button
                  className="icon-button"
                  data-group-menu={g.id}
                  disabled={busy}
                  title={gt('groupMenu')}
                  aria-label={`${gt('groupMenu')}: ${name}`}
                  {...menuTriggerProps(menuGroupId === g.id, (anchor, edge) => menu(g.id, anchor, edge))}
                >
                  <Icon name="more" />
                </Button>
              </div>
            </div>
            {g.subscribed && usage && (
              <div className="group-usage" data-group-usage={g.id}>
                <div className="group-usage-caption">
                  <span>{gt('subscriptionTraffic')}</span>
                  <span className="group-usage-values">
                    <strong>{used === null ? '—' : bytes(used, lang)}</strong>
                    {usage.total === 0 ? (
                      <> / {gt('unlimitedShort')}</>
                    ) : usage.total ? (
                      <> / {bytes(usage.total, lang)}</>
                    ) : null}
                  </span>
                </div>
                <div
                  className="group-usage-track"
                  {...(percentage === null
                    ? { 'aria-hidden': true as const }
                    : {
                        role: 'progressbar',
                        'aria-label': gt('subscriptionTraffic'),
                        'aria-valuemin': 0,
                        'aria-valuemax': 100,
                        'aria-valuenow': Math.round(percentage),
                        'aria-valuetext': usageText(usage, lang),
                      })}
                >
                  <span style={{ width: `${percentage ?? 0}%` }} />
                </div>
                {!!usage.expire && (
                  <p className="group-usage-expiry">
                    {gt('expires')}:{' '}
                    <time title={formatDateTime(new Date(usage.expire * 1000), lang)}>
                      {formatDate(new Date(usage.expire * 1000), lang)}
                    </time>
                  </p>
                )}
              </div>
            )}
            {g.subscribed && g.announcement && (
              <Announcement key={g.announcement} value={g.announcement} language={lang} />
            )}
            {(job || error || g.lastUpdate?.status === 'needs-review') && (
              <div className="library-group-status" role="status">
                <Button
                  className={`text-button ${error ? 'group-status-error' : ''}`}
                  data-group-status={g.id}
                  onClick={() => (g.lastUpdate?.status === 'needs-review' && !job ? review(g.id) : tasks())}
                >
                  {job
                    ? `${gt(job.status)}${job.total ? ` · ${job.checked} / ${job.total}` : ''}`
                    : error
                      ? message(error, lang, translateError)
                      : gt('needs-review')}
                </Button>
              </div>
            )}
            {probing && (
              <div className="library-group-status" data-group-probe-status={g.id} role="status">
                {gt('groupProbe')} · {measures.length - remaining} / {measures.length}
              </div>
            )}
            <div className="connection-rows" id={`group-rows-${g.id}`} hidden={collapsed}>
              {!collapsed && profiles.map(renderProfile)}
              {!collapsed && !profiles.length && (
                <div
                  className="client-empty group-empty"
                  data-group-empty={g.id}
                  id={views.length === 1 && g.subscribed && !total ? 'subscription-empty' : undefined}
                >
                  <Icon name={g.subscribed && !total ? 'download' : total ? 'search' : 'server'} />
                  <strong>
                    {total
                      ? t('noMatches')
                      : g.subscribed
                        ? gt(job ? 'importingServers' : 'emptySubscription')
                        : gt('emptyGroup')}
                  </strong>
                  <p>
                    {total
                      ? t('noProfilesHint')
                      : g.subscribed
                        ? gt('emptySubscriptionHint')
                        : t('noProfilesHint')}
                  </p>
                  {total ? (
                    <Button className="text-button" onClick={reset}>
                      {t('reset')}
                    </Button>
                  ) : g.subscribed ? (
                    job ? (
                      <Button className="text-button" onClick={tasks}>
                        {gt('updates')}
                      </Button>
                    ) : g.lastUpdate?.status === 'needs-review' ? (
                      <Button
                        className="text-button"
                        id={views.length === 1 ? 'subscription-resume-review' : undefined}
                        onClick={() => review(g.id)}
                      >
                        {gt('continueImport')}
                      </Button>
                    ) : (
                      <Button
                        className="button secondary"
                        id={views.length === 1 ? 'subscription-empty-load' : undefined}
                        disabled={busy}
                        onClick={() => update(g.id)}
                      >
                        {gt('loadServers')}
                      </Button>
                    )
                  ) : (
                    <Button className="text-button" onClick={() => add(g.id)}>
                      {t('add')}
                    </Button>
                  )}
                </div>
              )}
            </div>
          </section>
        );
      })}
      {!views.length && (
        <div className="client-empty">
          <Icon name={snapshot.profiles.length ? 'search' : 'server'} />
          <strong>{t(snapshot.profiles.length ? 'noMatches' : 'noProfiles')}</strong>
          <p>{t('noProfilesHint')}</p>
          <Button className="text-button" onClick={() => (snapshot.profiles.length ? reset() : add())}>
            {t(snapshot.profiles.length ? 'reset' : 'add')}
          </Button>
        </div>
      )}
    </div>
  );
}
