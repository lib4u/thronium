import { translate } from '../shared/i18n/index.ts';
import { Button } from '../shared/ui/controls';
import { Icon } from '../ui';
import { tags } from './resources';
import ResourceControls from './ResourceControls';
import type { ResourcesController } from './useResourcesPanel';

/** Rule sets of the active routing profile. */
export default function RuleSetResources({ controller }: { controller: ResourcesController }) {
  const { language, tr, disabled, sets, ruleSet, editContents } = controller;
  return (
    <section className="feature-panel">
      <div className="feature-panel-head">
        <div>
          <h2>
            {tr('sets')} <span className="count-badge">{sets.length}</span>
          </h2>
          <p>{tr('setHint')}</p>
        </div>
        <Button id="ruleset-add" className="button secondary" disabled={disabled} onClick={() => ruleSet()}>
          <Icon name="plus" />
          {tr('addSet')}
        </Button>
      </div>
      {sets.map((s, index) => (
        <div className="resource-row" key={index}>
          <Icon name="folder" />
          <div className="resource-description">
            <strong>{tags(s.tag).join(', ')}</strong>
            <small>
              {s.type === 'geodata'
                ? `${s.kind}:${s.category}`
                : ['local', 'remote', 'inline'].includes(String(s.type || 'inline'))
                  ? tr((s.type || 'inline') as 'local' | 'remote' | 'inline')
                  : String(s.type)}
            </small>
            {s.type === 'geodata' && <small className="geo-set-source">{String(s.url)}</small>}
          </div>
          {(s.type === 'geodata' || s.type === 'inline' || !s.type) && (
            <Button
              className="text-button"
              data-set-content={index}
              disabled={disabled}
              onClick={() => editContents(index)}
            >
              {translate(language, 'routing.contents_8889522')}
            </Button>
          )}
          <ResourceControls
            controller={controller}
            entry={{ kind: 'set', index }}
            edit={() => ruleSet(index)}
          />
        </div>
      ))}
      {!sets.length && <p className="resource-empty">{tr('empty')}</p>}
    </section>
  );
}
