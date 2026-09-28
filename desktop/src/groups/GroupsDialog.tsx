import { useMessageState } from '../shared/i18n/react';
import { Field } from '../shared/ui/controls';
import { InlineError } from '../shared/ui/controls';
import { Button, Input, Checkbox } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import type * as Wire from '../shared/api/generated/commands';
import { useEffect, useState } from 'react';
import { command, type Snapshot, type SubscriptionSettings, type Group } from '../api';
import { Modal, Icon } from '../ui';
import GroupChainFields from './GroupChainFields';
import { tr, message, usageText, updatedText, intervalText as scheduleText, type Language } from './messages';
import { limits } from '../shared/api/generated/limits.ts';
import { groupName, isPersonalGroup, profilesOf } from './groupModel';
import SubscriptionFields from './SubscriptionFields';

type Edit = Wire.GroupDraft;
const defaults = (): SubscriptionSettings => ({
  inheritDefaults: true,
  url: '',
  userAgent: limits.subscriptionUserAgent,
  headers: {},
  viaProxy: false,
  useProviderRouting: true,
});
export default function GroupsDialog({
  snapshot,
  close,
  changed,
  update,
  updates,
  initialGroupId,
  initialAction,
  translateError,
}: {
  snapshot: Snapshot;
  close(): void;
  changed(): Promise<void>;
  update(id: string): void;
  updates(): void;
  initialGroupId?: string;
  initialAction?: 'edit' | 'delete';
  translateError(e: unknown): string;
}) {
  const lang: Language = snapshot.preferences.language;
  const t = (key: Parameters<typeof tr>[0]) => tr(key, lang);
  const [edit, setEdit] = useState<Edit | null>(null);
  const [headers, setHeaders] = useState('{}');
  const [showURL, setShowURL] = useState(false);
  const [removing, setRemoving] = useState<Group | null>(null);
  const [deleteProfiles, setDeleteProfiles] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useMessageState(lang, (value) => message(value, lang, translateError));
  const [globalDefaults, setGlobalDefaults] = useState<{ user_agent: string; sub_auto_update: number }>();
  useEffect(() => {
    void command('settings')
      .then((s) => {
        const defaults = s.subscriptions;
        if (
          !defaults ||
          typeof defaults.user_agent !== 'string' ||
          typeof defaults.sub_auto_update !== 'number'
        )
          throw new Error('invalid_command_response');
        setGlobalDefaults({ user_agent: defaults.user_agent, sub_auto_update: defaults.sub_auto_update });
      })
      .catch((e) => setError(e));
  }, []);
  const effectiveInterval =
    edit?.subscription?.inheritDefaults === true
      ? globalDefaults?.sub_auto_update
      : edit?.subscription?.intervalMinutes;
  const name = (g: Group) => groupName(g, lang);
  async function run(action: () => Promise<unknown>, done?: () => void) {
    setBusy(true);
    setError('');
    try {
      await action();
      await changed();
      done?.();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  function begin(value: Edit) {
    setEdit(value);
    setIntervalText(undefined);
    setHeaders(JSON.stringify(value.subscription?.headers || {}, null, 2));
    setShowURL(false);
    setError('');
  }
  // The field keeps what is typed, so it can be cleared and retyped; the
  // subscription takes only whole minutes in range, and the form's own
  // validation blocks saving anything else.
  const [intervalText, setIntervalText] = useState<string>();
  function changeInterval(text: string) {
    setIntervalText(text);
    const minutes = Number(text);
    if (
      text.trim() !== '' &&
      Number.isInteger(minutes) &&
      minutes >= 1 &&
      minutes <= limits.maxSubscriptionIntervalMinutes
    )
      patch({ intervalMinutes: minutes });
  }
  function patch(settings: Partial<SubscriptionSettings>) {
    setEdit((old) => old && { ...old, subscription: { ...old.subscription!, ...settings } });
  }
  async function save() {
    if (!edit) return;
    let subscription = edit.subscription;
    if (subscription) {
      try {
        const parsed: unknown = JSON.parse(headers);
        if (
          !parsed ||
          Array.isArray(parsed) ||
          typeof parsed !== 'object' ||
          Object.values(parsed).some((v) => typeof v !== 'string')
        )
          throw new Error();
        subscription = {
          ...subscription,
          url: subscription.url.trim(),
          headers: parsed as Record<string, string>,
        };
      } catch {
        setError('invalid_subscription_headers');
        return;
      }
    }
    await run(
      async () => {
        const result = await command('saveGroup', { ...edit, subscription });
        setEdit((old) => old && { ...old, id: result.id });
      },
      () => setEdit(null),
    );
  }
  useEffect(() => {
    if (!initialGroupId || isPersonalGroup(initialGroupId)) return;
    if (initialAction === 'delete') {
      setRemoving(snapshot.groups.find((g) => g.id === initialGroupId) || null);
      return;
    }
    let active = true;
    setBusy(true);
    void command('group', { id: initialGroupId })
      .then((value) => {
        if (active) begin(value);
      })
      .catch((e) => {
        if (active) setError(e);
      })
      .finally(() => {
        if (active) setBusy(false);
      });
    return () => {
      active = false;
    };
  }, [initialGroupId, initialAction]);
  return (
    <Modal
      className="groups-modal desktop-import-modal"
      title={removing ? t('remove') : edit ? (edit.id ? t('edit') : t('add')) : t('groups')}
      close={() => {
        if (!busy) close();
      }}
      closeLabel={t('close')}
      footer={
        <>
          <Button
            className="text-button"
            disabled={busy}
            onClick={() => {
              if (edit || removing) {
                setEdit(null);
                setRemoving(null);
                setError('');
              } else close();
            }}
          >
            {edit || removing ? t('back') : t('close')}
          </Button>
          {!edit && !removing && (
            <Button
              id="subscription-open-jobs"
              className="button secondary"
              disabled={busy}
              onClick={updates}
            >
              {t('updates')}
            </Button>
          )}
          {edit ? (
            <Button
              className="button primary"
              id="group-save"
              type="submit"
              form="group-form"
              disabled={busy}
            >
              {t('save')}
            </Button>
          ) : removing ? (
            <Button
              className="button primary"
              id="group-delete-confirm"
              disabled={busy}
              onClick={() =>
                void run(
                  () => command('deleteGroup', { id: removing.id, deleteProfiles }),
                  () => setRemoving(null),
                )
              }
            >
              {t('remove')}
            </Button>
          ) : (
            <Button
              className="button primary"
              id="group-new"
              disabled={busy}
              onClick={() => begin({ name: '', subscription: null })}
            >
              <Icon name="plus" />
              {t('add')}
            </Button>
          )}
        </>
      }
    >
      {error && (
        <InlineError className="desktop-inline-error" role="alert">
          {error}
        </InlineError>
      )}
      {edit ? (
        <form
          id="group-form"
          onSubmit={(e) => {
            e.preventDefault();
            void save();
          }}
        >
          <fieldset className="group-fields" disabled={busy}>
            <Field className="feature-field" label={t('name')}>
              <Input
                id="group-name"
                className="text-input"
                required
                maxLength={limits.maxNameBytes}
                value={edit.name}
                onChange={(e) => setEdit({ ...edit, name: e.target.value })}
              />
            </Field>
            <label className="import-toggle">
              <Checkbox
                id="group-subscribed"
                type="checkbox"
                checked={!!edit.subscription}
                onChange={(e) => setEdit({ ...edit, subscription: e.target.checked ? defaults() : null })}
              />
              {t('subscription')}
            </label>
            {edit.subscription ? (
              <SubscriptionFields
                lang={lang}
                subscription={edit.subscription}
                showURL={showURL}
                setShowURL={setShowURL}
                patch={patch}
                effectiveInterval={effectiveInterval}
                intervalText={intervalText}
                setIntervalText={setIntervalText}
                changeInterval={changeInterval}
                globalDefaults={globalDefaults}
                headers={headers}
                setHeaders={setHeaders}
              />
            ) : (
              edit.id && <p className="field-hint">{t('detach')}</p>
            )}
            <label className="import-toggle">
              <Checkbox
                id="group-auto-clear-unavailable"
                type="checkbox"
                checked={edit.autoClearUnavailable === true}
                onChange={(e) => setEdit({ ...edit, autoClearUnavailable: e.target.checked })}
              />
              {translate(lang, 'library.group_auto_clear')}
            </label>
            <GroupChainFields
              value={edit.proxyChain ?? undefined}
              profiles={snapshot.profiles}
              language={lang}
              changed={(proxyChain) => setEdit((old) => old && { ...old, proxyChain })}
            />
          </fieldset>
        </form>
      ) : removing ? (
        <>
          <strong>{name(removing)}</strong>
          <p className="field-hint">{t('deleteHint')}</p>
          <label className="import-toggle">
            <Checkbox
              id="group-delete-profiles"
              type="checkbox"
              checked={deleteProfiles}
              disabled={busy}
              onChange={(e) => setDeleteProfiles(e.target.checked)}
            />
            {t('deleteProfiles')}
          </label>
          {deleteProfiles && <p className="field-hint">{t('deleteWarning')}</p>}
        </>
      ) : (
        <div className="group-list">
          {snapshot.groups.map((g, i) => (
            <article className="group-item" key={g.id} data-group-id={g.id}>
              <div className="group-item-info">
                <strong>
                  {name(g)}{' '}
                  <span className="connection-count">{profilesOf(snapshot.profiles, g.id).length}</span>
                </strong>
                <small>{g.subscribed ? `${t('subscription')} · ${updatedText(g, lang)}` : t('local')}</small>
                {(g.proxyChain?.front || g.proxyChain?.landing) && (
                  <small>{translate(lang, 'subscriptions.group_chain_enabled_034c481')}</small>
                )}
                {g.subscribed && g.usage && <small>{usageText(g.usage, lang)}</small>}
              </div>
              {!!g.intervalMinutes && (
                <small className="group-schedule">{scheduleText(g.intervalMinutes, lang)}</small>
              )}
              {g.lastUpdate?.error && (
                <p className="desktop-inline-error group-update-error">
                  {message(g.lastUpdate.error, lang, translateError)}
                </p>
              )}
              <div className="group-item-actions">
                {g.subscribed && (
                  <Button
                    className="text-button"
                    data-group-update={g.id}
                    disabled={busy}
                    onClick={() => update(g.id)}
                  >
                    {t('update')}
                  </Button>
                )}
                {!isPersonalGroup(g.id) && (
                  <>
                    <Button
                      className="icon-button"
                      data-group-edit={g.id}
                      title={t('edit')}
                      aria-label={`${t('edit')}: ${name(g)}`}
                      disabled={busy}
                      onClick={() => void run(async () => begin(await command('group', { id: g.id })))}
                    >
                      <Icon name="edit" />
                    </Button>
                    <Button
                      className="icon-button"
                      data-group-delete={g.id}
                      title={t('remove')}
                      aria-label={`${t('remove')}: ${name(g)}`}
                      disabled={busy}
                      onClick={() => {
                        setRemoving(g);
                        setDeleteProfiles(false);
                        setError('');
                      }}
                    >
                      <Icon name="trash" />
                    </Button>
                  </>
                )}
                <Button
                  className="icon-button"
                  data-group-up={g.id}
                  title={t('up')}
                  aria-label={`${t('up')}: ${name(g)}`}
                  disabled={busy || i === 0}
                  onClick={() => void run(() => command('moveGroup', { id: g.id, offset: -1 }))}
                >
                  <Icon name="arrow-up" />
                </Button>
                <Button
                  className="icon-button"
                  data-group-down={g.id}
                  title={t('down')}
                  aria-label={`${t('down')}: ${name(g)}`}
                  disabled={busy || i === snapshot.groups.length - 1}
                  onClick={() => void run(() => command('moveGroup', { id: g.id, offset: 1 }))}
                >
                  <Icon name="arrow-down" />
                </Button>
              </div>
            </article>
          ))}
        </div>
      )}
    </Modal>
  );
}
