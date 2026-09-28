import { InlineError, JsonEditor, TabList, Button } from '../shared/ui/controls';
import { ConfirmDialog } from '../ui';
import ObjectEditor from './ObjectEditor';
import CategoryEditor from './CategoryEditor';
import DnsResources from './DnsResources';
import RuleSetResources from './RuleSetResources';
import { useResourcesPanel, type ResourcesPanelProps } from './useResourcesPanel';

export default function ResourcesPanel(props: ResourcesPanelProps) {
  const controller = useResourcesPanel(props);
  const {
    kind,
    profile,
    language,
    update,
    translateError,
    tr,
    view,
    setView,
    raw,
    setRaw,
    error,
    notice,
    setNotice,
    discard,
    setDiscard,
    editor,
    setEditor,
    deleting,
    setDeleting,
    content,
    setContent,
    disabled,
    optionLabels,
    check,
    encoded,
    dirty,
    run,
    contentCandidate,
    name,
    remove,
    changeView,
    jsonAction,
  } = controller;
  return (
    <div className="routing-resources">
      <div className="feature-toolbar resource-view">
        <TabList
          value={view}
          onChange={changeView}
          disabled={disabled}
          tabs={(['fields', 'json'] as const).map((id) => ({
            id,
            label: tr(id),
            attributes: { 'data-resource-view': id },
          }))}
        />
      </div>
      {error && !deleting && (
        <InlineError className="desktop-inline-error" role="alert">
          {error}
        </InlineError>
      )}
      {view === 'json' ? (
        <section className="feature-panel">
          <div className="feature-panel-head">
            <div>
              <h2>{kind === 'dns' ? 'DNS' : tr('sets')}</h2>
              <p>{tr('rawHint')}</p>
            </div>
          </div>
          <JsonEditor
            id="route-json"
            className="text-input desktop-json mono routing-json"
            aria-label={kind === 'dns' ? 'DNS JSON' : tr('sets')}
            spellCheck={false}
            value={raw ?? encoded}
            disabled={disabled}
            onChange={(e) => {
              setRaw(e.target.value);
              setNotice('');
            }}
          />
          <div className="settings-save">
            <span>{dirty ? tr('unsaved') : ''}</span>
            <Button
              id="route-json-check"
              className="button secondary"
              disabled={disabled}
              onClick={() => void run(() => jsonAction(false), 'checked')}
            >
              {tr('check')}
            </Button>
            <Button
              id="route-json-save"
              className="button primary"
              disabled={disabled}
              onClick={() => void run(() => jsonAction(true))}
            >
              {tr('save')}
            </Button>
          </div>
        </section>
      ) : kind === 'dns' ? (
        <DnsResources controller={controller} />
      ) : (
        <RuleSetResources controller={controller} />
      )}
      <p className="resource-notice" role="status">
        {disabled ? tr('busy') : notice}
      </p>
      {editor && (
        <ObjectEditor
          {...editor.props}
          optionLabels={optionLabels}
          save={(c) => update(editor.candidate(profile, c))}
          check={async (c) => {
            await check(editor.candidate(profile, c));
          }}
          language={language}
          translateError={translateError}
          close={() => setEditor(null)}
        />
      )}
      {content && (
        <CategoryEditor
          name={content.name}
          rules={content.rules}
          copy={content.source.type === 'geodata'}
          language={language}
          translateError={translateError}
          close={() => setContent(null)}
          check={async (name, rules) => {
            await check(contentCandidate(name, rules));
          }}
          save={async (name, rules) => {
            await update(contentCandidate(name, rules));
          }}
        />
      )}
      {deleting && (
        <ConfirmDialog
          title={tr('confirm')}
          message={name(deleting)}
          cancelLabel={tr('cancel')}
          confirmLabel={tr('remove')}
          busy={disabled}
          error={error}
          cancel={() => setDeleting(null)}
          confirm={() => void run(remove)}
          confirmId="resource-delete-confirm"
        />
      )}
      {discard && (
        <ConfirmDialog
          title={tr('discard')}
          message={tr('unsaved')}
          cancelLabel={tr('keep')}
          confirmLabel={tr('discardButton')}
          cancel={() => setDiscard(false)}
          confirm={() => {
            setDiscard(false);
            setRaw(null);
            setView('fields');
          }}
          confirmId="resource-json-discard"
        />
      )}
    </div>
  );
}
