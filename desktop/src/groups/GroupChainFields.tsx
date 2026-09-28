import { Section, Field } from '../shared/ui/controls';
import { Select } from '../shared/ui/controls';
import { translate, type Language } from '../shared/i18n/index.ts';
import type { GroupChain, Profile } from '../api';
import { hopCandidates } from '../profiles/chainHops';

export default function GroupChainFields({
  value,
  profiles,
  language,
  changed,
}: {
  value?: GroupChain;
  profiles: Profile[];
  language: Language;
  changed(value: GroupChain): void;
}) {
  const chain = value || { front: null, landing: null };
  // The front proxy is the device-side hop.
  const candidates = (key: 'front' | 'landing') => hopCandidates(profiles, key === 'front');
  return (
    <Section
      title={<>{translate(language, 'subscriptions.front_and_landing_proxies_253dd60')}</>}
      id="group-chain-fields"
      className="route-advanced"
      open={!!(chain.front || chain.landing)}
    >
      <p className="field-hint">
        {translate(language, 'subscriptions.device_front_proxy_server_or_chain_landing_proxy_0858e92')}
      </p>
      {(['front', 'landing'] as const).map((key) => (
        <Field
          key={key}
          className="feature-field"
          label={
            key === 'front'
              ? translate(language, 'subscriptions.front_proxy_cdc76e6')
              : translate(language, 'subscriptions.landing_proxy_8daa7a7')
          }
        >
          <Select
            id={`group-chain-${key}`}
            className="text-input"
            value={chain[key] || ''}
            onChange={(e) => changed({ ...chain, [key]: e.target.value || null })}
          >
            <option value="">{translate(language, 'subscriptions.none_08a1eef')}</option>
            {candidates(key).map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </Select>
        </Field>
      ))}
      <p className="field-hint">{translate(language, 'subscriptions.group_chain_limits')}</p>
    </Section>
  );
}
