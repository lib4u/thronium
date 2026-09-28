import { useEffect, useMemo, useRef, useState } from 'react';
import { command, empty, type Snapshot } from '../api';
import { GROUP_STORAGE_KEY, rememberedGroup } from '../AppModel';
import type { GroupView } from '../groups/LibraryGroups';
import { groupName, isPersonalGroup, profilesOf } from '../groups/groupModel';
import { protocolLabel } from '../library/rowData';
import { sortProfiles } from '../library/sort';
import { orderBlocked, orderNeighbor } from '../library/profileOrder';
import useProfileDrag from '../library/useProfileDrag';
import { limits } from '../shared/api/generated/limits.ts';

type Perform = (action: () => Promise<unknown>, done?: () => void) => Promise<void>;

/** The server list: filters, the shown groups, multi-selection and manual order. */
export function useLibraryView({
  state,
  busy,
  interactive,
  perform,
}: {
  state: Snapshot;
  busy: boolean;
  /** No dialog covers the list and the connection page is shown. */
  interactive: boolean;
  perform: Perform;
}) {
  const [protocol, setProtocol] = useState('');
  const [query, setQuery] = useState('');
  const [chosenGroup, setGroup] = useState(rememberedGroup);
  // A chosen group that no longer exists shows every group.
  const group =
    state !== empty && chosenGroup !== 'all' && !state.groups.some((g) => g.id === chosenGroup)
      ? 'all'
      : chosenGroup;
  const [favorites, setFavorites] = useState(false);
  const [selecting, setSelecting] = useState(false);
  const [picked, setSelection] = useState<Set<string>>(new Set());
  // Deleted profiles leave the selection without an extra render.
  const selection = useMemo(
    () => new Set([...picked].filter((id) => state.profiles.some((p) => p.id === id))),
    [picked, state.profiles],
  );
  // Groups folded during a search belong to that search; a new query starts unfolded.
  const searchKey = JSON.stringify([query, protocol]);
  const [folded, setFolded] = useState<{ key: string; ids: Set<string> }>({ key: searchKey, ids: new Set() });
  const searchCollapsed = folded.key === searchKey ? folded.ids : new Set<string>();
  const loaded = state !== empty;
  useEffect(() => {
    if (!loaded) return;
    try {
      localStorage.setItem(GROUP_STORAGE_KEY, group);
    } catch {
      /* The current selection still works when storage is unavailable. */
    }
  }, [group, loaded]);
  const matches = sortProfiles(
    state.profiles.filter(
      (p) =>
        (group === 'all' || p.groupId === group) &&
        (!favorites || p.favorite) &&
        (!protocol || p.protocol === protocol) &&
        `${p.name} ${p.address} ${p.protocol} ${protocolLabel(p.protocol, state.preferences.language)}`
          .toLocaleLowerCase()
          .includes(query.toLocaleLowerCase()),
    ),
    state.preferences,
  );
  const searching = !!query.trim() || !!protocol;
  const groupViews: GroupView[] = state.groups
    .filter((g) => group === 'all' || g.id === group)
    .map((g) => ({
      group: g,
      profiles: matches.filter((p) => p.groupId === g.id),
      total: profilesOf(state.profiles, g.id).length,
      collapsed: searching ? searchCollapsed.has(g.id) : !!g.collapsed,
    }))
    .filter((v) =>
      searching || favorites
        ? v.profiles.length > 0 || group === v.group.id
        : v.total > 0 || v.group.subscribed || group === v.group.id || !isPersonalGroup(v.group.id),
    );
  const visibleMatches = groupViews.filter((v) => !v.collapsed).flatMap((v) => v.profiles);
  const orderReason = orderBlocked({
    busy: busy || !interactive,
    selecting,
    query,
    protocol,
    favorites,
    sort: state.preferences.librarySort,
  });
  const orderInFlight = useRef(false),
    orderFocus = useRef<string | null>(null);
  async function orderProfiles(id: string, targetId: string, after: boolean, focus = false) {
    if (orderReason || orderInFlight.current) return;
    orderInFlight.current = true;
    if (focus) orderFocus.current = id;
    try {
      await perform(() => command('reorderProfile', { id, targetId, after }));
    } finally {
      orderInFlight.current = false;
    }
  }
  const profileDrag = useProfileDrag(
    visibleMatches,
    !orderReason,
    (id, target, after) => void orderProfiles(id, target, after),
  );
  // Keyboard reordering keeps focus on the moved row once the list re-renders.
  useEffect(() => {
    if (busy || !orderFocus.current) return;
    const id = orderFocus.current;
    orderFocus.current = null;
    const frame = requestAnimationFrame(() => {
      const handle = document.querySelector<HTMLButtonElement>(`[data-profile-drag="${CSS.escape(id)}"]`);
      if (handle && !handle.disabled) {
        handle.focus({ preventScroll: true });
        handle.scrollIntoView({ block: 'nearest', inline: 'nearest' });
      }
    });
    return () => cancelAnimationFrame(frame);
  }, [busy]);
  return {
    protocol,
    setProtocol,
    query,
    setQuery,
    group,
    setGroup,
    favorites,
    setFavorites,
    selecting,
    setSelecting,
    selection,
    setSelection,
    selectedIds: state.profiles.filter((p) => selection.has(p.id)).map((p) => p.id),
    toggleSelected(id: string) {
      setSelection((old) => {
        const next = new Set(old);
        if (next.has(id)) next.delete(id);
        else if (next.size < limits.maxBatchProfiles) next.add(id);
        return next;
      });
    },
    searching,
    matches,
    groupViews,
    visibleMatches,
    toggleGroup(view: GroupView) {
      if (searching)
        setFolded((old) => {
          const next = new Set(old.key === searchKey ? old.ids : []);
          if (view.collapsed) next.delete(view.group.id);
          else next.add(view.group.id);
          return { key: searchKey, ids: next };
        });
      else void perform(() => command('collapseGroup', { id: view.group.id, collapsed: !view.collapsed }));
    },
    resetFilters() {
      setQuery('');
      setFavorites(false);
      setProtocol('');
    },
    groupLabel(id: string) {
      const g = state.groups.find((g) => g.id === id);
      return g ? groupName(g, state.preferences.language) : '';
    },
    orderReason,
    moveNeighbor(id: string, offset: -1 | 1) {
      const target = orderNeighbor(state.profiles, id, offset);
      if (target) void orderProfiles(id, target, offset === 1, true);
    },
    profileDrag,
  };
}
