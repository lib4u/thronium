import { Button } from '../shared/ui/controls';
import { formatBytes } from '../shared/i18n/format';
import { translate } from '../shared/i18n';
import type { useLegacyReview } from './useLegacyReview';
import './LegacyResources.css';

type Resource = NonNullable<ReturnType<typeof useLegacyReview>['data']['resources']>[number];

const kindKeys = {
  hosts: 'backups.resource_hosts',
  'rule-set-source': 'backups.resource_json',
  'rule-set-binary': 'backups.resource_srs',
  pem: 'backups.resource_pem',
  text: 'backups.resource_text',
  geodata: 'backups.resource_geodata',
} as const;
const groups = [
  { entity: 'route', key: 'backups.resources_route_group' },
  { entity: 'profile', key: 'backups.resources_profile_group' },
] as const;

export default function LegacyResources({ controller }: { controller: ReturnType<typeof useLegacyReview> }) {
  const { data, language, busy, chooseResource } = controller;
  if (!data.resources?.length) return null;
  const row = (resource: Resource) => (
    <li key={resource.id} data-legacy-resource={resource.id} data-legacy-resource-entity={resource.entity}>
      <div>
        <span className="legacy-resource-path">{resource.path}</span>
        <small>
          {translate(language, kindKeys[resource.kind])}
          {resource.name && <> · {resource.name}</>}
          {resource.selected && (
            <>
              {' '}
              · {translate(language, 'backups.resource_selected')} · {formatBytes(resource.bytes, language)}
            </>
          )}
        </small>
      </div>
      <Button
        className="button secondary compact"
        disabled={busy}
        onClick={() => chooseResource(resource.id)}
      >
        {translate(language, resource.selected ? 'backups.resource_replace' : 'backups.resource_choose')}
      </Button>
    </li>
  );
  return (
    <section className="legacy-resources" aria-labelledby="legacy-resources-title">
      <h3 id="legacy-resources-title">{translate(language, 'backups.resources_title')}</h3>
      <p className="field-hint">{translate(language, 'backups.resources_hint')}</p>
      {groups
        .map((group) => ({ ...group, rows: data.resources!.filter((r) => r.entity === group.entity) }))
        .filter((group) => group.rows.length)
        .map((group) => (
          <div key={group.entity} data-legacy-resource-group={group.entity}>
            <h4>{translate(language, group.key)}</h4>
            <ul>{group.rows.map(row)}</ul>
          </div>
        ))}
    </section>
  );
}
