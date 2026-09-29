import { translate } from '../shared/i18n/index.ts';
import { defaultTarget, matches, type RouteProfile, type RouteRule } from './model';
import { FormActions, SearchField, Button } from '../shared/ui/controls';
import { formatRuleValue } from './ruleInput';
import { Icon } from '../ui';
import { label } from '../profiles/schema';
import { Targets } from './RuleEditor';
import type { RoutingPageController } from './useRoutingPage';

/** The rules tab: ordered rules with their actions, the final outbound and the local network shortcut. */
export default function RulesPanel({
  controller,
  current,
}: {
  controller: RoutingPageController;
  current: RouteProfile;
}) {
  const {
    snapshot,
    language,
    tr,
    busy,
    query,
    setQuery,
    actionLabel,
    setEditing,
    setModal,
    run,
    update,
    reorder,
    readOnly,
  } = controller;
  return (
    <>
      <section className="feature-panel">
        <div className="feature-panel-head">
          <div>
            <h2>
              {tr('rules')} <span className="count-badge">{current.rules.length}</span>
            </h2>
            <p>{tr('order')}</p>
          </div>
          <SearchField
            className="slim"
            id="rule-search"
            placeholder={tr('search')}
            aria-label={tr('search')}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        {current.mode !== 'rules' && <p className="rules-notice">{tr('inactive')}</p>}
        <div className="feature-table-wrap">
          <table className="feature-table routing-table">
            <thead>
              <tr>
                <th>{tr('priority')}</th>
                <th>{tr('action')}</th>
                <th>{tr('enabled')}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {current.rules
                .filter((r) =>
                  (r.name + JSON.stringify(r.config)).toLowerCase().includes(query.toLowerCase()),
                )
                .map((rule) => {
                  const i = current.rules.indexOf(rule);
                  const summary = matches
                    .filter((f) => rule.config[f.key] !== undefined)
                    .map(
                      (f) =>
                        label(f.label, language) +
                        ': ' +
                        (f.kind === 'bool'
                          ? tr(rule.config[f.key] ? 'yes' : 'no')
                          : formatRuleValue(f, rule.config[f.key]).replace(/\n/g, ', ')),
                    )
                    .join(' · ');
                  const name = (
                    <>
                      <span className="rule-number">{String(i + 1).padStart(2, '0')}</span>
                      <span>
                        <strong>{rule.name}</strong>
                        <small>
                          {summary || (rule.config.type === 'logical' ? tr('logical') : tr('any'))}
                        </small>
                      </span>
                    </>
                  );
                  return (
                    <tr key={rule.id}>
                      <td>
                        {readOnly ? (
                          <div className="route-rule-name">{name}</div>
                        ) : (
                          <Button
                            className="route-rule-name"
                            data-edit-rule={rule.id}
                            onClick={() => {
                              setEditing(rule);
                              setModal('rule');
                            }}
                          >
                            {name}
                          </Button>
                        )}
                      </td>
                      <td>
                        <span className="status-tag">{actionLabel(rule)}</span>
                      </td>
                      <td>
                        <Button
                          className={`switch ${rule.enabled ? 'active' : ''}`}
                          data-toggle-rule={rule.id}
                          aria-label={translate(language, 'routing.rule_enabled_label', {
                            name: rule.name,
                          })}
                          aria-pressed={rule.enabled}
                          disabled={busy || readOnly}
                          onClick={() =>
                            run(() =>
                              update({
                                ...current,
                                rules: current.rules.map((r) =>
                                  r.id === rule.id ? { ...r, enabled: !r.enabled } : r,
                                ),
                              }),
                            )
                          }
                        />
                      </td>
                      <td>
                        {!readOnly && (
                          <div className="route-actions">
                            <Button
                              className="icon-button"
                              data-rule-up={rule.id}
                              disabled={!i || busy}
                              aria-label={tr('up')}
                              onClick={() => reorder(rule, -1)}
                            >
                              <Icon name="arrow-up" />
                            </Button>
                            <Button
                              className="icon-button"
                              data-rule-down={rule.id}
                              disabled={i === current.rules.length - 1 || busy}
                              aria-label={tr('down')}
                              onClick={() => reorder(rule, 1)}
                            >
                              <Icon name="arrow-down" />
                            </Button>
                            <Button
                              className="icon-button"
                              data-delete-rule={rule.id}
                              disabled={busy}
                              aria-label={tr('remove')}
                              onClick={() => {
                                setEditing(rule);
                                setModal('delete-rule');
                              }}
                            >
                              <Icon name="trash" />
                            </Button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
            </tbody>
          </table>
        </div>
        {!current.rules.some((r) =>
          (r.name + JSON.stringify(r.config)).toLowerCase().includes(query.toLowerCase()),
        ) && (
          <div className="client-empty">
            <Icon name="route" />
            <strong>{tr('none')}</strong>
            <p>{tr('empty')}</p>
          </div>
        )}
        <div className="rules-footer">
          <Icon name="corner-down-right" />
          <span>{tr('final')}</span>
          <span className="filter-spacer" />
          <Targets
            tr={tr}
            profiles={snapshot.profiles}
            value={String(current.route.final || defaultTarget)}
            disabled={busy || readOnly}
            changed={(value) => run(() => update({ ...current, route: { ...current.route, final: value } }))}
          />
        </div>
      </section>
      {!readOnly && (
        <FormActions className="feature-toolbar">
          <Button
            className="button secondary"
            id="route-local"
            title={tr('localHint')}
            disabled={busy}
            onClick={() => {
              const rule: RouteRule = {
                id: crypto.randomUUID(),
                name: tr('local'),
                enabled: true,
                config: { ip_is_private: true, action: 'route', outbound: 'direct' },
              };
              setEditing(rule);
              setModal('rule');
            }}
          >
            <Icon name="wifi" />
            {tr('local')}
          </Button>
        </FormActions>
      )}
    </>
  );
}
