import { Select, Input, Button, Checkbox, Field } from '../shared/ui/controls';
import { translate, type Language } from '../shared/i18n/index.ts';
import { useState } from 'react';
import type { Snapshot } from '../api';
import { label, type Label, type Config } from '../profiles/schema';
import DynamicFields from './DynamicFields';
import { protocolLabel } from '../library/rowData';
import { groupName } from '../groups/groupModel';
import { limits } from '../shared/api/generated/limits.ts';
const messageKeys = {
  hint: 'library.pool_members_hint',
  all: 'library.all_groups_f7d603c',
  filter: 'library.filter_pool_candidates_cbbfc1e',
  group: 'library.candidate_group_8cacf9f',
  add: 'library.add_visible_3a2514f',
  clear: 'library.clear_pool_867d7b0',
  count: 'library.selected_f19a934',
  preferred: 'library.preferred_server_at_connection_start_0389d96',
  automatic: 'library.automatic_039411e',
  unsupported: 'library.ordinary_sing_box_xray_profiles_and_explicit_cha_d97c93e',
  missing: 'library.missing_pool_member_036200c',
  removeMissing: 'library.remove_missing_member',
} satisfies Record<string, Label>;
export default function SelectorFields({
  libraryRevision = 0,
  config,
  profiles,
  groups,
  profileId,
  profileGroup,
  translateError,
  language,
  disabled,
  change,
}: {
  libraryRevision?: number;
  config: Config;
  profiles: Snapshot['profiles'];
  groups: Snapshot['groups'];
  profileId?: string;
  profileGroup: string;
  translateError(e: unknown): string;
  language: Language;
  disabled: boolean;
  change(c: Config): void;
}) {
  const t = (key: keyof typeof messageKeys) => label(messageKeys[key], language);
  const [query, setQuery] = useState('');
  const [group, setGroup] = useState('all');
  const [explicit, setExplicit] = useState<Config>();
  const [source, setSource] = useState<Config>();
  const dynamic = config.member_source !== undefined;
  function mode(value: string) {
    const next = { ...config };
    if (value === 'dynamic') {
      setExplicit({ members: config.members, pinned_profile: config.pinned_profile });
      delete next.members;
      delete next.pinned_profile;
      next.member_source = source || {
        group_id: group === 'all' ? profileGroup : group,
        name_regex: '',
        exclude_regex: '',
      };
    } else {
      setSource(config.member_source as Config);
      delete next.member_source;
      next.members = explicit?.members || [];
      delete next.pinned_profile;
      if (explicit?.pinned_profile) next.pinned_profile = explicit.pinned_profile;
    }
    change(next);
  }
  const modeField = (
    <Field className="feature-field" label={translate(language, 'library.pool_membership_3004b7e')}>
      <Select
        id="selector-membership"
        className="text-input"
        value={dynamic ? 'dynamic' : 'explicit'}
        disabled={disabled}
        onChange={(e) => mode(e.target.value)}
      >
        <option value="explicit">{translate(language, 'library.choose_manually_377dcb4')}</option>
        <option value="dynamic">{translate(language, 'library.from_a_group_and_filter_081cab1')}</option>
      </Select>
    </Field>
  );
  const members: string[] = Array.isArray(config.members)
    ? config.members.filter((v): v is string => typeof v === 'string')
    : [];
  // Eligibility is decided once by the engine (member_eligible) and published
  // per profile, so the picker never hardcodes which protocols may join a pool.
  const options = profiles.filter((p) => p.poolEligible);
  const visible = options.filter(
    (p) =>
      (group === 'all' || p.groupId === group) &&
      `${p.name} ${p.address}`.toLocaleLowerCase().includes(query.toLocaleLowerCase()),
  );
  const merged = [...new Set([...members, ...visible.map((p) => p.id)])];
  function setMembers(members: string[]) {
    const next: Config = { ...config, members };
    if (typeof config.pinned_profile === 'string' && !members.includes(config.pinned_profile))
      delete next.pinned_profile;
    change(next);
  }
  if (dynamic)
    return (
      <div className="selector-fields">
        {modeField}
        <DynamicFields
          {...{
            libraryRevision,
            config,
            profiles,
            groups,
            profileId,
            profileGroup,
            translateError,
            language,
            disabled,
            change,
          }}
        />
      </div>
    );
  return (
    <div className="selector-fields">
      {modeField}
      <p>{t('hint')}</p>
      <div className="feature-fields">
        <Field className="feature-field" label={t('group')}>
          <Select
            className="text-input"
            id="selector-group"
            value={group}
            disabled={disabled}
            onChange={(e) => setGroup(e.target.value)}
          >
            <option value="all">{t('all')}</option>
            {groups.map((g) => (
              <option key={g.id} value={g.id}>
                {groupName(g, language)}
              </option>
            ))}
          </Select>
        </Field>
        <Field className="feature-field" label={t('filter')}>
          <Input
            id="selector-search"
            className="text-input"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            disabled={disabled}
          />
        </Field>
      </div>
      <div className="selector-pool-actions">
        <span>
          {t('count')}: {members.length} / {limits.maxPoolMembers}
        </span>
        <Button
          type="button"
          id="selector-add-visible"
          className="text-button"
          disabled={disabled || merged.length > limits.maxPoolMembers || merged.length === members.length}
          onClick={() => setMembers(merged)}
        >
          {t('add')}
        </Button>
        <Button
          type="button"
          id="selector-clear"
          className="text-button"
          disabled={disabled || !members.length}
          onClick={() => setMembers([])}
        >
          {t('clear')}
        </Button>
      </div>
      <div className="selector-candidates">
        {visible.map((p) => (
          <label key={p.id} className="import-toggle">
            <Checkbox
              type="checkbox"
              data-selector-member={p.id}
              checked={members.includes(p.id)}
              disabled={disabled || (!members.includes(p.id) && members.length >= limits.maxPoolMembers)}
              onChange={(e) =>
                setMembers(e.target.checked ? [...members, p.id] : members.filter((id) => id !== p.id))
              }
            />
            <span>
              {p.name}
              <small>
                {protocolLabel(p.protocol, language)} · {p.address}
              </small>
            </span>
          </label>
        ))}
      </div>
      {members
        .filter((id) => !options.some((p) => p.id === id))
        .map((id) => (
          <p className="desktop-inline-error" key={id}>
            {t('missing')}
            <Button
              type="button"
              className="text-button"
              aria-label={t('removeMissing')}
              title={t('removeMissing')}
              onClick={() => setMembers(members.filter((p) => p !== id))}
            >
              ×
            </Button>
          </p>
        ))}
      <Field className="feature-field" label={t('preferred')}>
        <Select
          id="selector-preferred"
          className="text-input"
          disabled={disabled}
          value={String(config.pinned_profile || '')}
          onChange={(e) => change({ ...config, pinned_profile: e.target.value })}
        >
          <option value="">{t('automatic')}</option>
          {members.map((id) => (
            <option key={id} value={id}>
              {profiles.find((p) => p.id === id)?.name || t('missing')}
            </option>
          ))}
        </Select>
      </Field>
      <p className="field-hint">{t('unsupported')}</p>
    </div>
  );
}
