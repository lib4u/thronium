import { translate } from '../shared/i18n/index.ts';
import { FormActions, Button } from '../shared/ui/controls';
import { Icon } from '../ui';
import { tags, dnsGeneralSections } from './resources';
import ResourceControls from './ResourceControls';
import { messageKeys, type ResourcesController } from './useResourcesPanel';

/** DNS servers and DNS rules of the active routing profile. */
export default function DnsResources({ controller }: { controller: ResourcesController }) {
  const {
    profile,
    language,
    update,
    tr,
    disabled,
    servers,
    rules,
    resolvers,
    run,
    open,
    server,
    rule,
    outboundDns,
  } = controller;
  return (
    <>
      <section className="feature-panel">
        <div className="feature-panel-head">
          <div>
            <h2>
              {tr('servers')} <span className="count-badge">{servers.length}</span>
            </h2>
            <p>
              {tr('defaultServer')}: {String(profile.dns.final || tr('firstServer'))}
            </p>
          </div>
          <FormActions className="feature-toolbar">
            <Button
              id="dns-options"
              className="button secondary"
              disabled={disabled}
              onClick={() =>
                open(
                  profile.dns,
                  tr('options'),
                  () => dnsGeneralSections(resolvers),
                  (current, c) => ({ ...current, dns: c }),
                )
              }
            >
              {tr('options')}
            </Button>
            <Button id="dns-outbound" className="button secondary" disabled={disabled} onClick={outboundDns}>
              {translate(language, 'routing.server_address_dns_7c6314a')}
            </Button>
            <Button
              id="dns-add-server"
              className="button secondary"
              disabled={disabled}
              onClick={() => server()}
            >
              <Icon name="plus" />
              {tr('addServer')}
            </Button>
          </FormActions>
        </div>
        {servers.map((s, index) => (
          <div className="resource-row" key={index}>
            <Icon name="globe" />
            <div className="resource-description">
              <strong>{String(s.tag || '—')}</strong>
              <small>
                {String(s.type || '')}
                {s.server ? ' · ' + String(s.server) : ''}
                {s.type === 'hosts' ? ' · ' + Object.keys(s.predefined || {}).length : ''}
                {s.type === 'fakeip' ? ' · ' + String(s.inet4_range || s.inet6_range || '') : ''}
              </small>
            </div>
            <ResourceControls
              controller={controller}
              entry={{ kind: 'server', index }}
              edit={() => server(index)}
            />
          </div>
        ))}
        {!servers.length && <p className="resource-empty">{tr('empty')}</p>}
      </section>
      <section className="feature-panel">
        <div className="feature-panel-head">
          <div>
            <h2>
              {tr('rules')} <span className="count-badge">{rules.length}</span>
            </h2>
            <p>{tr('ruleHint')}</p>
          </div>
          <FormActions className="feature-toolbar">
            <Button
              id="dns-resolve-domains"
              className="button secondary"
              title={tr('resolveHint')}
              disabled={
                disabled ||
                profile.mode !== 'rules' ||
                profile.rules.some(
                  (r, i) =>
                    i === 0 &&
                    r.enabled &&
                    r.config.action === 'resolve' &&
                    Object.keys(r.config).length === 1,
                )
              }
              onClick={() =>
                void run(() =>
                  update({
                    ...profile,
                    rules: [
                      {
                        id: crypto.randomUUID(),
                        name: tr('resolveDomains'),
                        enabled: true,
                        config: { action: 'resolve' },
                      },
                      ...profile.rules,
                    ],
                  }),
                )
              }
            >
              {tr('resolveDomains')}
            </Button>
            <Button id="dns-add-rule" className="button secondary" disabled={disabled} onClick={() => rule()}>
              <Icon name="plus" />
              {tr('addRule')}
            </Button>
          </FormActions>
        </div>
        {rules.map((r, index) => {
          const summary = [
            'domain',
            'domain_suffix',
            'domain_regex',
            'query_type',
            'rule_set',
            'preferred_by',
          ]
            .flatMap((k) => tags(r[k]))
            .join(', ');
          const action = String(r.action || 'route');
          return (
            <div className="resource-row" key={index}>
              <span className="rule-number">{String(index + 1).padStart(2, '0')}</span>
              <div className="resource-description">
                <strong>{summary || tr(r.type === 'logical' ? 'nested' : 'all')}</strong>
                <small>
                  {action === 'route'
                    ? String(r.server || tr('defaultServer'))
                    : messageKeys[action as keyof typeof messageKeys]
                      ? tr(action as keyof typeof messageKeys)
                      : action}
                </small>
              </div>
              <ResourceControls
                controller={controller}
                entry={{ kind: 'rule', index }}
                edit={() => rule(index)}
              />
            </div>
          );
        })}
        {!rules.length && <p className="resource-empty">{tr('empty')}</p>}
      </section>
    </>
  );
}
