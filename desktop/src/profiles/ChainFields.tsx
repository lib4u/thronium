import { Select, Button, Field } from '../shared/ui/controls';
import type { Snapshot } from '../api';
import { Icon } from '../ui';
import { protocolLabel } from '../library/rowData';
import { label, type Config, type Label } from './schema';
import { hopCandidates } from './chainHops';
import { limits } from '../shared/api/generated/limits.ts';
import type { Language } from '../shared/i18n/index.ts';
const messageKeys = {
  hint: 'profiles.connection_order_your_device_the_servers_from_to_db8351f',
  limits: 'profiles.chain_limits',
  add: 'profiles.add_hop_fa71e07',
  choose: 'profiles.choose_a_profile_a59c283',
  hop: 'profiles.hop_b0c4bd3',
  entry: 'profiles.entry_1832014',
  exit: 'profiles.exit_c9b8055',
  up: 'profiles.move_up_441b312',
  down: 'profiles.move_down_d672813',
  remove: 'profiles.remove_hop_261fc5d',
  missing: 'profiles.missing_profile_71417f8',
} satisfies Record<string, Label>;
export default function ChainFields({
  config,
  profiles,
  selfId,
  language,
  disabled,
  change,
}: {
  config: Config;
  profiles: Snapshot['profiles'];
  selfId?: string;
  language: Language;
  disabled: boolean;
  change(config: Config): void;
}) {
  const t = (key: keyof typeof messageKeys) => label(messageKeys[key], language);
  const hops: string[] = Array.isArray(config.hops)
    ? config.hops.map((v) => (typeof v === 'string' ? v : ''))
    : [];
  // Any outbound or userspace endpoint is a hop; the backend refuses complete
  // sing-box configurations, pools and host-owned interfaces.
  const optionsFor = (index: number) => hopCandidates(profiles, index === 0).filter((p) => p.id !== selfId);
  const setHops = (hops: string[]) => change({ ...config, hops });
  const move = (index: number, offset: number) => {
    const next = [...hops];
    [next[index], next[index + offset]] = [next[index + offset], next[index]];
    setHops(next);
  };
  return (
    <div className="chain-fields">
      <p>{t('hint')}</p>
      <ol className="chain-hops">
        {hops.map((id, i) => (
          <li key={i}>
            <Field
              className="feature-field"
              label={
                <>
                  {t('hop')} {i + 1}
                  {i === 0 ? ` · ${t('entry')}` : ''}
                  {i === hops.length - 1 ? ` · ${t('exit')}` : ''}
                </>
              }
            >
              <Select
                className="text-input"
                data-chain-hop={i}
                value={id}
                disabled={disabled}
                onChange={(e) => setHops(hops.map((old, j) => (j === i ? e.target.value : old)))}
              >
                <option value="">{t('choose')}</option>
                {optionsFor(i).map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} · {protocolLabel(p.protocol, language)}
                  </option>
                ))}
                {id && !optionsFor(i).some((p) => p.id === id) && <option value={id}>{t('missing')}</option>}
              </Select>
            </Field>
            <div className="chain-hop-actions">
              <Button
                type="button"
                className="icon-button"
                data-chain-up={i}
                disabled={disabled || i === 0}
                aria-label={t('up')}
                onClick={() => move(i, -1)}
              >
                <Icon name="arrow-up" />
              </Button>
              <Button
                type="button"
                className="icon-button"
                data-chain-down={i}
                disabled={disabled || i === hops.length - 1}
                aria-label={t('down')}
                onClick={() => move(i, 1)}
              >
                <Icon name="arrow-down" />
              </Button>
              <Button
                type="button"
                className="icon-button"
                data-chain-remove={i}
                disabled={disabled}
                aria-label={t('remove')}
                onClick={() => setHops(hops.filter((_, j) => j !== i))}
              >
                <Icon name="trash" />
              </Button>
            </div>
          </li>
        ))}
      </ol>
      <Button
        id="chain-add-hop"
        className="button secondary"
        type="button"
        disabled={disabled || hops.length >= limits.maxChainHops}
        onClick={() => setHops([...hops, ''])}
      >
        <Icon name="plus" />
        {t('add')}
      </Button>
      <p className="field-hint">{t('limits')}</p>
    </div>
  );
}
