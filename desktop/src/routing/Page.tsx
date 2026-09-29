import { TabList, Select, Button } from '../shared/ui/controls';
import ResourcesPanel from './ResourcesPanel';
import GeoPanel from './GeoPanel';
import RoutingImportDialog from './ImportDialog';
import SourceControls from './SourceControls';
import './Catalog.css';
import './RuleEditor.css';
import { Icon, ConfirmDialog } from '../ui';
import { label } from '../profiles/schema';
import { messageRef } from '../shared/i18n/message';
import { translate } from '../shared/i18n/index.ts';
import { isBaselineProfile } from './model';
import RuleEditor, { messageKeys, type W } from './RuleEditor';
import RulesPanel from './RulesPanel';
import RoutingTextPanel from './RoutingTextPanel';
import RoutingProfilesDialog from './RoutingProfilesDialog';
import { useRoutingPage, type RoutingPageProps } from './useRoutingPage';

export default function RoutingPage(props: RoutingPageProps) {
  const controller = useRoutingPage(props);
  const {
    snapshot,
    refresh,
    translateError,
    language,
    tr,
    data,
    setData,
    error,
    setError,
    busy,
    notice,
    setNotice,
    tab,
    setTab,
    buffers,
    setBuffers,
    modal,
    setModal,
    editing,
    setEditing,
    setProfileName,
    setProfileEditing,
    setDeleting,
    importRequest,
    setImportRequest,
    current,
    provider,
    providerName,
    readOnly,
    copyProvider,
    useProvider,
    persist,
    update,
    run,
    apply,
    nameOf,
    bufferKey,
    exportProfile,
  } = controller;
  const view = provider?.profile;
  const defaultProfile = data?.profiles.find((p) => p.id === 'default');
  // With a subscription's routing on offer, an untouched Default would mean
  // the same as choosing it, so only the subscription is listed.
  const choices = data?.profiles.filter((p) => !(view && isBaselineProfile(p))) ?? [];
  // Read-only, the subscription's policy is shown as JSON on every tab.
  const tabs = readOnly
    ? (['rules', 'sets', 'dns', 'raw'] as const)
    : (['rules', 'categories', 'simple', 'sets', 'dns', 'raw'] as const);
  const shown = (tabs as readonly string[]).includes(tab) ? tab : 'rules';
  return (
    <>
      <div className="page-heading">
        <div>
          <h1>{tr('title')}</h1>
          <p className="subtitle">{tr('hint')}</p>
        </div>
        <Button
          className="button primary"
          id="route-add-rule"
          disabled={!current || busy || readOnly}
          onClick={() => {
            setEditing(undefined);
            setModal('rule');
          }}
        >
          <Icon name="plus" />
          {tr('add')}
        </Button>
      </div>
      {error && (
        <div className="desktop-inline-error" role="alert">
          {error}
        </div>
      )}
      {current && data && (
        <>
          {current.legacyConstraints && (
            <p className="rules-notice" id="route-legacy-policy">
              <Icon name="info" />
              {current.legacyConstraints.rawVerbatim
                ? label('routing.raw_verbatim_notice', language)
                : tr('legacyPolicy')}
            </p>
          )}
          {readOnly && (
            <p className="rules-notice" id="route-provider-notice">
              <Icon name="info" />
              {translate(language, 'routing.provider_applied', { name: providerName })}
            </p>
          )}
          {view && !snapshot.routing.providerOwned && (
            <p className="rules-notice" id="route-provider-offered">
              <Icon name="info" />
              {translate(language, 'routing.provider_overridden', {
                name: providerName,
                profile: nameOf(data.profiles.find((p) => p.id === data.active) ?? current),
              })}
            </p>
          )}
          {provider?.error && (
            <div className="desktop-inline-error" role="alert">
              {translate(language, 'routing.provider_unavailable', {
                error: translateError(provider.error),
              })}
            </div>
          )}
          {snapshot.routing.profileOwned && (
            <p className="rules-notice">
              <Icon name="info" />
              {tr('own')}
            </p>
          )}
          {snapshot.routing.pending && (
            <div className="routing-pending">
              <span>{tr('pending')}</span>
              <Button
                className="button primary"
                id="route-apply"
                disabled={busy}
                onClick={() => void apply()}
              >
                {tr('apply')}
              </Button>
            </div>
          )}
          <div className="route-profile-bar">
            <Icon name="route" />
            <Select
              id="route-profile-select"
              className="text-input"
              aria-label={tr('profile')}
              value={readOnly ? current.id : data.active}
              disabled={busy}
              onChange={(e) => {
                if (view && e.target.value === view.id) {
                  // Kept changes to Default are confirmed; otherwise it is only a choice.
                  if (defaultProfile && isBaselineProfile(defaultProfile)) run(useProvider);
                  else setModal('provider-use');
                  return;
                }
                const p = data.profiles.find((p) => p.id === e.target.value)!;
                run(() => persist({ ...data, active: p.id }, p));
              }}
            >
              {view && (
                <option value={view.id}>
                  {translate(language, 'routing.provider_option', { name: providerName })}
                </option>
              )}
              {choices.map((p) => (
                <option key={p.id} value={p.id}>
                  {nameOf(p)}
                </option>
              ))}
            </Select>
            {readOnly && (
              <Button
                className="button secondary"
                id="route-provider-copy"
                disabled={busy}
                onClick={() => setModal('provider-copy')}
              >
                <Icon name="copy" />
                {label('routing.provider_copy', language)}
              </Button>
            )}
            <Button
              className="button secondary"
              id="route-profiles"
              disabled={busy}
              onClick={() => {
                setModal('profiles');
                setProfileName('');
                setProfileEditing('');
                setDeleting('');
              }}
            >
              <Icon name="folder" />
              {tr('profiles')}
            </Button>
            <Button
              className="button secondary"
              id="route-import"
              disabled={busy}
              onClick={() => {
                setImportRequest(undefined);
                setModal('import');
              }}
            >
              <Icon name="download" />
              {tr('loadProfile')}
            </Button>
            <Button
              className="icon-button"
              id="route-export"
              disabled={busy || readOnly}
              aria-label={tr('exportProfile')}
              title={tr('exportProfile')}
              onClick={() => void exportProfile()}
            >
              <Icon name="upload" />
            </Button>
            <span className="filter-spacer" />
            <Button className="button secondary" onClick={() => setTab('dns')}>
              {tr('dns')}
            </Button>
          </div>
          <section className="routing-mode-grid">
            {(['rules', 'all', 'direct'] as const).map((mode) => (
              <Button
                className={`mode-card ${current.mode === mode ? 'active' : ''}`}
                data-routing-mode={mode}
                aria-pressed={current.mode === mode}
                disabled={busy || readOnly}
                key={mode}
                onClick={() => run(() => update({ ...current, mode }))}
              >
                <span className="mode-icon">
                  <Icon name={mode === 'rules' ? 'route' : mode === 'all' ? 'globe' : 'arrow-up-right'} />
                </span>
                <span>
                  <strong>{tr((mode + 'Mode') as W)}</strong>
                  <small>{tr((mode + 'Hint') as W)}</small>
                </span>
                <span className="mode-radio" />
              </Button>
            ))}
          </section>
          <TabList
            className="feature-tabs route-tabs"
            value={shown}
            onChange={(id) => {
              setTab(id);
              setNotice('');
            }}
            tabs={tabs.map((id) => ({
              id,
              label: tr(id),
              attributes: { 'data-route-tab': id },
            }))}
          />
          {current.source?.url && (
            <SourceControls
              profile={current}
              language={language}
              disabled={busy || !!modal || Object.keys(buffers).length > 0}
              changed={(source) =>
                persist({
                  ...data,
                  profiles: data.profiles.map((p) => (p.id === current.id ? { ...p, source } : p)),
                })
              }
              refreshed={async (routing) => {
                setData(routing);
                await refresh();
                setNotice(messageRef(messageKeys.saved));
              }}
              failed={(error) => setError(error)}
            />
          )}
          {readOnly && shown !== 'rules' ? (
            <RoutingTextPanel controller={controller} />
          ) : shown === 'categories' ? (
            <GeoPanel
              key={current.id}
              profile={current}
              profiles={snapshot.profiles}
              language={language}
              busy={busy}
              update={update}
              refresh={refresh}
              translateError={translateError}
            />
          ) : shown === 'rules' ? (
            <RulesPanel controller={controller} current={current} />
          ) : shown === 'dns' || shown === 'sets' ? (
            <ResourcesPanel
              key={current.id + ':' + shown}
              kind={shown}
              profile={current}
              profiles={snapshot.profiles}
              language={language}
              busy={busy}
              rawDraft={buffers[bufferKey]}
              setRawDraft={(value) =>
                setBuffers((old) => {
                  const next = { ...old };
                  if (value === undefined) delete next[bufferKey];
                  else next[bufferKey] = value;
                  return next;
                })
              }
              update={update}
              translateError={translateError}
            />
          ) : (
            <RoutingTextPanel controller={controller} />
          )}
          <div className="workspace-footer">
            <span role="status">
              {busy ? tr('saving') : notice || (snapshot.running ? tr('saved') : tr('next'))}
            </span>
          </div>
          {modal === 'import' && (
            <RoutingImportDialog
              language={language}
              initialCountry={importRequest?.country}
              initialText={importRequest?.text}
              close={() => setModal(null)}
              translateError={translateError}
              save={async (profiles, activate) => {
                await persist(
                  {
                    ...data,
                    active: activate ? profiles[0].id : data.active,
                    profiles: [...data.profiles, ...profiles],
                  },
                  profiles,
                );
                if (activate) setTab('rules');
              }}
            />
          )}
          {modal === 'rule' && (
            <RuleEditor
              rule={editing}
              creating={!current.rules.some((r) => r.id === editing?.id)}
              profiles={snapshot.profiles}
              tr={tr}
              language={language}
              close={() => setModal(null)}
              translateError={translateError}
              save={async (rule) => {
                const found = current.rules.some((r) => r.id === rule.id);
                await update({
                  ...current,
                  rules: found
                    ? current.rules.map((r) => (r.id === rule.id ? rule : r))
                    : [...current.rules, rule],
                });
              }}
            />
          )}
          {modal === 'delete-rule' && editing && (
            <ConfirmDialog
              title={tr('deleteRule')}
              message={editing.name}
              cancelLabel={tr('cancel')}
              confirmLabel={tr('remove')}
              busy={busy}
              error={error}
              cancel={() => setModal(null)}
              confirmId="route-delete-confirm"
              confirm={() =>
                void run(async () => {
                  await update({ ...current, rules: current.rules.filter((r) => r.id !== editing.id) });
                  setModal(null);
                })
              }
            />
          )}
          {modal === 'profiles' && <RoutingProfilesDialog controller={controller} data={data} />}
          {modal === 'provider-copy' && view && (
            <ConfirmDialog
              title={label('routing.provider_copy_title', language)}
              message={
                label('routing.provider_copy_message', language) +
                (provider.pinnedResolvers ? ' ' + label('routing.provider_copy_pinned', language) : '')
              }
              cancelLabel={tr('cancel')}
              confirmLabel={label('routing.provider_copy', language)}
              busy={busy}
              error={error}
              cancel={() => setModal(null)}
              confirmId="route-provider-copy-confirm"
              confirm={() =>
                void run(async () => {
                  await copyProvider();
                  setModal(null);
                })
              }
            />
          )}
          {modal === 'provider-use' && view && (
            <ConfirmDialog
              title={label('routing.provider_use_title', language)}
              message={translate(language, 'routing.provider_use_message', {
                name: label('routing.provider_kept_name', language),
              })}
              cancelLabel={tr('cancel')}
              confirmLabel={translate(language, 'routing.provider_option', { name: providerName })}
              busy={busy}
              error={error}
              cancel={() => setModal(null)}
              confirmId="route-provider-use-confirm"
              confirm={() =>
                void run(async () => {
                  await useProvider();
                  setModal(null);
                })
              }
            />
          )}
        </>
      )}
    </>
  );
}
