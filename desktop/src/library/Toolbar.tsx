import { Button } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import { useState } from 'react';
import type { Preferences } from '../api';
import { Icon } from '../ui';
import DropdownMenu, { menuTriggerProps, type MenuEdge, type MenuItem } from '../DropdownMenu';
import { maintenanceText } from './MaintenanceDialog';
import type { MaintenanceKind } from './maintenance';
import type { DisplayedData } from './rowData';
import './Toolbar.css';
import { protocolLabel } from './rowData';

const orders = [
  ['original', 'library.library_order_29ea999'],
  ['name', 'library.by_name_9f1a603'],
  ['latency', 'library.by_latency_f96873a'],
  ['address', 'library.by_address_61e7222'],
  ['protocol', 'library.by_protocol_890ae7d'],
  ['security', 'library.by_security'],
  ['traffic', 'library.by_traffic'],
] as const;

export default function LibraryToolbar({
  preferences,
  busy,
  protocols,
  protocol,
  filter,
  selecting,
  select,
  save,
  view,
  displayedData,
  duplicates,
  exportProfiles,
  maintenance,
  canExport,
  canDeduplicate,
}: {
  preferences: Preferences;
  busy: boolean;
  protocols: string[];
  protocol: string;
  filter(value: string): void;
  selecting: boolean;
  select(): void;
  save(value: Preferences): Promise<void>;
  view: DisplayedData;
  displayedData(): void;
  duplicates(): void;
  exportProfiles(): void;
  maintenance(kind: MaintenanceKind): void;
  canExport: boolean;
  canDeduplicate: boolean;
}) {
  const [menu, setMenu] = useState<{
    type: 'sort' | 'filter' | 'more';
    anchor: HTMLButtonElement;
    edge?: MenuEdge;
  } | null>(null);
  // A sort key is offered while its datum is displayed; a saved key stays listed.
  const offered = (value: (typeof orders)[number][0]) =>
    value === preferences.librarySort ||
    (value === 'security' ? view.show_config_security : value === 'traffic' ? view.list_show_traffic : true);
  const current = orders.find((o) => o[0] === preferences.librarySort) ?? orders[0];
  const sortTitle = `${translate(preferences.language, 'library.sort_789a7d3')}: ${translate(preferences.language, current[1])}`;
  const filterTitle = protocol
    ? `${translate(preferences.language, 'library.protocol_abb4c67')}: ${protocolLabel(protocol, preferences.language)}`
    : translate(preferences.language, 'library.filter_by_protocol_cee41f7');
  const items: MenuItem[] =
    menu?.type === 'sort'
      ? [
          ...orders
            .filter(([value]) => offered(value))
            .map(([value, message]): MenuItem => ({
              id: `library-sort-${value}`,
              label: translate(preferences.language, message),
              icon: 'list',
              checked: preferences.librarySort === value,
              disabled: busy,
              select: () => void save({ ...preferences, librarySort: value }),
            })),
          ...[false, true].map((descending): MenuItem => ({
            id: `library-sort-${descending ? 'descending' : 'ascending'}`,
            label: descending
              ? translate(preferences.language, 'library.descending_941fbb0')
              : translate(preferences.language, 'library.ascending_e4e884b'),
            icon: descending ? 'arrow-down' : 'arrow-up',
            checked: preferences.librarySortDescending === descending,
            disabled: busy || preferences.librarySort === 'original',
            separator: !descending,
            select: () => void save({ ...preferences, librarySortDescending: descending }),
          })),
        ]
      : menu?.type === 'filter'
        ? ['', ...protocols].map((value) => ({
            id: `library-filter-${value || 'all'}`,
            label: value
              ? protocolLabel(value, preferences.language)
              : translate(preferences.language, 'library.all_protocols_bcf31e4'),
            icon: 'server',
            checked: protocol === value,
            select: () => filter(value),
          }))
        : [
            {
              id: 'library-duplicates',
              label: translate(preferences.language, 'library.find_duplicates_221e0fd'),
              icon: 'copy',
              disabled: busy || !canDeduplicate,
              select: duplicates,
            },
            {
              id: 'library-export',
              label: translate(preferences.language, 'library.export_displayed_profiles_0e43bb5'),
              icon: 'download',
              disabled: busy || !canExport,
              select: exportProfiles,
            },
            ...(
              [
                ['unavailable', 'block'],
                ['invalid', 'alert'],
                ['insecure', 'lock'],
                ['resolve', 'globe'],
              ] as const
            ).map(([kind, icon], index) => ({
              id: `library-${kind}`,
              label: maintenanceText(kind, preferences.language),
              icon,
              separator: index === 0,
              disabled: busy || !canExport,
              select: () => maintenance(kind),
            })),
            {
              id: 'library-displayed-data',
              label: translate(preferences.language, 'library.displayed_data'),
              icon: 'sliders',
              separator: true,
              select: displayedData,
            },
          ];
  const trigger = (type: 'sort' | 'filter' | 'more') =>
    menuTriggerProps(menu?.type === type, (anchor, edge) =>
      setMenu((old) => (old?.type === type && !edge ? null : { type, anchor, edge })),
    );
  return (
    <div className="library-toolbar-tools">
      <Button
        id="library-sort"
        className={`icon-button ${preferences.librarySort !== 'original' ? 'has-filter' : ''}`}
        title={sortTitle}
        aria-label={sortTitle}
        disabled={busy}
        {...trigger('sort')}
      >
        <Icon name="sort" />
      </Button>
      <Button
        id="library-filter"
        className={`icon-button ${protocol ? 'has-filter' : ''}`}
        title={filterTitle}
        aria-label={filterTitle}
        {...trigger('filter')}
      >
        <Icon name="sliders" />
      </Button>
      <Button
        id="bulk-select-toggle"
        className="icon-button"
        aria-pressed={selecting}
        title={
          selecting
            ? translate(preferences.language, 'library.finish_selection_f42e1fd')
            : translate(preferences.language, 'library.select_multiple_7da743b')
        }
        aria-label={
          selecting
            ? translate(preferences.language, 'library.finish_selection_f42e1fd')
            : translate(preferences.language, 'library.select_multiple_7da743b')
        }
        onClick={select}
      >
        <Icon name="check-square" />
      </Button>
      <Button
        id="library-more"
        className="icon-button"
        title={translate(preferences.language, 'library.library_actions_ef61604')}
        aria-label={translate(preferences.language, 'library.library_actions_ef61604')}
        {...trigger('more')}
      >
        <Icon name="more" />
      </Button>
      {menu && (
        <DropdownMenu
          key={menu.type}
          anchor={menu.anchor}
          edge={menu.edge}
          label={
            menu.type === 'sort'
              ? sortTitle
              : menu.type === 'filter'
                ? filterTitle
                : translate(preferences.language, 'library.library_actions_ef61604')
          }
          items={items}
          close={() => setMenu(null)}
        />
      )}
    </div>
  );
}
