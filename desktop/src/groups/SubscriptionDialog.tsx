import { useMessageState } from '../shared/i18n/react';
import { InlineError } from '../shared/ui/controls';
import { Button, Checkbox } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import type * as Wire from '../shared/api/generated/commands';
import { useEffect, useRef, useState } from 'react';
import { command, type Group, type SubscriptionUsage, type ProviderRouting } from '../api';
import { Modal } from '../ui';
import { parseImport, importDrafts, type ImportRow } from '../profiles/import';
import { importMessage, importWarning } from '../profiles/ImportDialog';
import { tr, message, usageText, updatedText, type Language } from './messages';
type Change = Wire.SubscriptionChange;
export default function SubscriptionDialog({
  group,
  language,
  close,
  changed,
  autoLoad = false,
  translateError,
}: {
  group: Group;
  language: Language;
  close(): void;
  changed(): Promise<void>;
  autoLoad?: boolean;
  translateError(e: unknown): string;
}) {
  const t = (key: Parameters<typeof tr>[0]) => tr(key, language);
  const im = (key: string) => importMessage(key, language);
  const [phase, setPhase] = useState<'ready' | 'loading' | 'review' | 'checking' | 'applying'>('ready');
  const [rows, setRows] = useState<ImportRow[]>([]);
  const [changes, setChanges] = useState<Change[]>([]);
  const [usage, setUsage] = useState<SubscriptionUsage | null>(null);
  const [error, setError] = useMessageState(language, (value) => message(value, language, translateError));
  const [accepted, setAccepted] = useState(false);
  const [checked, setChecked] = useState(false);
  // The failed profile and the raw error, resolved in the current language.
  const [checkFailure, setCheckFailure] = useState<{ name?: string; error: unknown } | null>(null);
  const checkError = checkFailure
    ? `${checkFailure.name ? checkFailure.name + ': ' : ''}${message(checkFailure.error, language, translateError)}`
    : '';
  const [progress, setProgress] = useState(0);
  const [providerRouting, setProviderRouting] = useState<ProviderRouting | null>(null);
  const [useProviderRouting, setUseProviderRouting] = useState(!!group.providerRouting?.enabled);
  const request = useRef<string | null>(null);
  const ticket = useRef<string | null>(null);
  const checkRun = useRef<string | null>(null);
  const discard = () => {
    if (ticket.current) {
      void command('discardSubscription', { ticket: ticket.current }).catch(() => {});
      ticket.current = null;
    }
  };
  const cancel = () => {
    checkRun.current = null;
    if (request.current) {
      void command('cancelSubscription', { requestId: request.current }).catch(() => {});
      request.current = null;
    }
    discard();
  };
  useEffect(() => () => cancel(), []);
  useEffect(() => {
    if (autoLoad) {
      const timer = setTimeout(() => void load(), 0);
      return () => clearTimeout(timer);
    }
  }, []);
  async function load() {
    cancel();
    const id = crypto.randomUUID();
    request.current = id;
    setPhase('loading');
    setError('');
    setRows([]);
    setChanges([]);
    setAccepted(false);
    setChecked(false);
    setCheckFailure(null);
    setUsage(null);
    try {
      const response = await command('fetchSubscription', { id: group.id, requestId: id });
      if (request.current !== id) {
        void command('discardSubscription', { ticket: response.ticket }).catch(() => {});
        return;
      }
      ticket.current = response.ticket;
      setUsage(response.usage);
      setProviderRouting(response.providerRouting);
      setUseProviderRouting(!!response.providerRouting?.enabled && !response.providerRouting?.error);
      const parsed = parseImport(response.body, group.id);
      setRows(parsed);
      if (!parsed.length || parsed.some((r) => !r.draft || r.error)) {
        setError(parsed.length ? 'invalidResponse' : 'empty');
        discard();
        return;
      }
      const preview = await command('previewSubscription', {
        ticket: response.ticket,
        profiles: importDrafts(parsed),
      });
      if (request.current === id) setChanges(preview);
    } catch (e) {
      if (request.current === id) {
        setError(e);
        discard();
      }
    } finally {
      if (request.current === id) {
        request.current = null;
        setPhase('review');
      }
    }
  }
  const checkable = changes.filter((c) => c.action !== 'removed');
  async function validate() {
    const currentTicket = ticket.current;
    if (!currentTicket) return;
    const id = crypto.randomUUID();
    checkRun.current = id;
    setPhase('checking');
    setCheckFailure(null);
    setChecked(false);
    setProgress(0);
    try {
      for (let i = 0; i < checkable.length; i++) {
        try {
          await command('checkSubscriptionProfile', {
            ticket: currentTicket,
            profileId: checkable[i].id,
            useProviderRouting,
          });
        } catch (e) {
          if (checkRun.current === id) setCheckFailure({ name: checkable[i].name, error: e });
          return;
        }
        if (checkRun.current !== id) return;
        setProgress(i + 1);
      }
      if (checkRun.current === id) setChecked(true);
    } catch (e) {
      if (checkRun.current === id) setCheckFailure({ error: e });
    } finally {
      if (checkRun.current === id) {
        checkRun.current = null;
        setPhase('review');
      }
    }
  }
  async function apply() {
    const currentTicket = ticket.current;
    if (!currentTicket) return;
    setPhase('applying');
    setError('');
    try {
      await command('applySubscription', { ticket: currentTicket, useProviderRouting });
      ticket.current = null;
      await changed();
      close();
    } catch (e) {
      setError(e);
      setPhase('review');
      discard();
    }
  }
  const warnings = rows.filter((r) => r.warnings.length);
  const busy = phase === 'loading' || phase === 'checking' || phase === 'applying';
  const leave = () => {
    if (phase !== 'applying') {
      cancel();
      close();
    }
  };
  return (
    <Modal
      className="desktop-import-modal subscription-modal"
      title={`${t('update')} · ${group.name}`}
      description={t('reviewHint')}
      close={leave}
      closeLabel={t('close')}
      footer={
        <>
          <Button className="text-button" disabled={phase === 'applying'} onClick={leave}>
            {t('cancel')}
          </Button>
          {phase === 'ready' ? (
            <Button id="subscription-load" className="button primary" onClick={() => void load()}>
              {t('load')}
            </Button>
          ) : (
            <Button
              id="subscription-apply"
              className="button primary"
              disabled={
                busy ||
                !ticket.current ||
                !changes.length ||
                !!error ||
                !!checkError ||
                (!!warnings.length && !accepted)
              }
              onClick={() => void apply()}
            >
              {t(phase === 'applying' ? 'applying' : 'apply')}
            </Button>
          )}
        </>
      }
    >
      <p className="field-hint">{updatedText(group, language)}</p>
      <p className="field-hint">{usageText(phase === 'ready' ? group.usage : usage, language)}</p>
      {phase === 'ready' && <p className="field-hint">{t('sourceHint')}</p>}
      {phase === 'loading' && <p role="status">{t('loading')}</p>}
      {error && (
        <InlineError className="desktop-inline-error" role="alert">
          {error}
        </InlineError>
      )}
      {phase !== 'ready' && phase !== 'loading' && (
        <>
          {providerRouting && (
            <div className="subscription-warning" id="subscription-routing-info">
              <p>
                {translate(
                  language,
                  'subscriptions.subscription_includes_routing_value0_conditions__7415575',
                  {
                    value0: providerRouting.rules,
                    value1: providerRouting.hasDns
                      ? translate(language, 'subscriptions.and_dns_settings_f58f07e')
                      : '',
                  },
                )}
              </p>
              {providerRouting.unsupportedCount > 0 && (
                <p className="field-hint" id="subscription-routing-unsupported">
                  {providerRouting.unsupported.length
                    ? translate(
                        language,
                        'subscriptions.the_provider_sent_parameters_this_version_does_not_090f2cb',
                        { value0: providerRouting.unsupported.join(', ') },
                      )
                    : translate(
                        language,
                        'subscriptions.the_provider_sent_value0_parameters_this_version_d_4a66798',
                        { value0: providerRouting.unsupportedCount },
                      )}
                </p>
              )}
              {providerRouting.fakeDns && !providerRouting.error && (
                <p className="field-hint" id="subscription-routing-fakeip">
                  {translate(language, 'subscriptions.fake_dns_as_fake_ip')}
                </p>
              )}
              {providerRouting.error ? (
                <InlineError role="alert">
                  {translate(
                    language,
                    'subscriptions.subscription_routing_could_not_be_parsed_applyin_7d66fe9',
                  )}
                </InlineError>
              ) : (
                <label className="import-toggle">
                  <Checkbox
                    id="subscription-use-routing"
                    type="checkbox"
                    disabled={busy}
                    checked={useProviderRouting}
                    onChange={(e) => {
                      // Checks ran with the other routing choice; their result no longer applies.
                      setUseProviderRouting(e.target.checked);
                      setChecked(false);
                      setCheckFailure(null);
                    }}
                  />
                  {translate(language, 'subscriptions.use_by_default_your_own_rules_take_priority_48ce28e')}
                </label>
              )}
            </div>
          )}
          <div className="import-summary">
            <div>
              {(['added', 'updated', 'removed', 'kept', 'unchanged'] as const).map((action) => (
                <span key={action} data-subscription-count={action}>
                  {t(action)}: {changes.filter((c) => c.action === action).length}
                </span>
              ))}
            </div>
            <Button
              id="subscription-reload"
              className="text-button"
              disabled={busy}
              onClick={() => void load()}
            >
              {t('reload')}
            </Button>
          </div>
          {rows
            .filter((r) => r.error)
            .map((row) => (
              <InlineError className="desktop-inline-error" role="alert" key={row.index}>
                {im('line')} {row.index}: {im(row.error!)}
              </InlineError>
            ))}
          <div className="subscription-changes">
            {changes.map((c) => (
              <article className="subscription-change" data-subscription-action={c.action} key={c.id}>
                <div>
                  <strong>{c.name}</strong>
                  {c.reason && <small>{t(c.reason)}</small>}
                </div>
                <span>{t(c.action)}</span>
              </article>
            ))}
          </div>
          {warnings.map((row) => (
            <div className="subscription-warning" key={row.index}>
              <strong>{row.draft?.name}</strong>
              <ul className="import-warnings">
                {row.warnings.map((w) => (
                  <li key={w} data-import-warning={w}>
                    {importWarning(w, language)}
                  </li>
                ))}
              </ul>
            </div>
          ))}
          {!!warnings.length && (
            <label className="import-toggle">
              <Checkbox
                id="subscription-acknowledge"
                type="checkbox"
                checked={accepted}
                disabled={busy}
                onChange={(e) => setAccepted(e.target.checked)}
              />
              {im('acknowledge')}
            </label>
          )}
          {changes.length > 0 && (
            <Button
              id="subscription-check"
              className="text-button"
              disabled={busy}
              onClick={() => void validate()}
            >
              {im(phase === 'checking' ? 'checking' : 'check')}
              {phase === 'checking' && ` ${progress}/${checkable.length}`}
            </Button>
          )}
          {checked && (
            <p className="import-valid" role="status">
              {t('checksPassed')}
            </p>
          )}
          {checkError && (
            <InlineError className="desktop-inline-error" role="alert">
              {checkError}
            </InlineError>
          )}
          <p className="field-hint">{im('notTested')}</p>
        </>
      )}
    </Modal>
  );
}
