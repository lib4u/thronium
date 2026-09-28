import RuleActions from './RuleActions';
import RuleConditions from './RuleConditions';
import { InlineError, Field } from '../shared/ui/controls';
import { Input, Button } from '../shared/ui/controls';
import './Catalog.css';
import './RuleEditor.css';
import { Modal } from '../ui';
import type { useRuleEditor } from './useRuleEditor';
import DiscardDialog from './DiscardDialog';
import { limits } from '../shared/api/generated/limits.ts';
export default function RuleEditorView({ controller }: { controller: ReturnType<typeof useRuleEditor> }) {
  const {
    busy,
    config,
    discard,
    error,
    guard,
    language,
    name,
    requestClose,
    creating,
    setDirty,
    setName,
    submit,
    tab,
    tr,
  } = controller;
  return (
    <Modal
      className="route-rule-modal"
      title={tr(creating ? 'newRule' : 'editRule')}
      description={tr(config.type === 'logical' ? 'order' : 'ruleHint')}
      initialFocus="#rule-name"
      close={requestClose}
      closeLabel={tr('close')}
      footer={
        <>
          <Button className="button secondary" disabled={busy} onClick={requestClose}>
            {tr('cancel')}
          </Button>
          <Button
            className="button primary"
            id="rule-save"
            type="submit"
            form="route-rule-form"
            disabled={busy || discard}
          >
            {tr(busy ? 'saving' : 'saveRule')}
          </Button>
        </>
      }
    >
      <DiscardDialog guard={guard} language={language} />
      <form
        id="route-rule-form"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <Field className="feature-field" label={tr('ruleName')}>
          <Input
            id="rule-name"
            className="text-input"
            maxLength={limits.maxNameBytes}
            placeholder={tr('nameExample')}
            value={name}
            disabled={busy}
            onChange={(e) => {
              setName(e.target.value);
              setDirty(true);
            }}
          />
        </Field>
        <RuleConditions controller={controller} />
        {tab !== 'json' && <RuleActions controller={controller} />}
        {error && (
          <InlineError className="desktop-inline-error" role="alert">
            {error}
          </InlineError>
        )}
      </form>
    </Modal>
  );
}
