import {
  Button,
  Checkbox,
  InlineError,
  Input,
  Section,
  Select,
  Field as FormField,
} from '../shared/ui/controls';
import { Icon } from '../shared/ui/Icon';
import { Modal } from '../shared/ui/Modal';
import { translate, type Language } from '../shared/i18n/index.ts';
import { get, label, type Config, type Field } from '../profiles/schema.ts';
import {
  advancedSections,
  autoSelectWords,
  defaultAutoSelectConfig,
  durationOptions,
  intervalPresets,
  reuseTtlPresets,
} from './autoSelectModel.ts';
import { useAutoSelectConfig } from './useAutoSelectConfig.ts';
import { groupName } from '../groups/groupModel';
import type { Snapshot } from '../api';
import './AutoSelectConfig.css';

const optionLabels: Record<string, Parameters<typeof translate>[1]> = {
  rotate: 'library.by_interval_564b177',
  connection: 'library.by_connection_3b511af',
};

function ConfigField({
  field,
  config,
  language,
  change,
}: {
  field: Field;
  config: Config;
  language: Language;
  change(path: string, value: unknown): void;
}) {
  const value = get(config, field.path);
  const id = 'auto-select-' + field.path;
  const title = label(field.label, language);
  if (field.kind === 'bool')
    return (
      <label className="setting-toggle auto-select-toggle">
        <Checkbox
          id={id}
          type="checkbox"
          checked={value === true}
          onChange={(e) => change(field.path, e.target.checked)}
        />
        <span>{title}</span>
      </label>
    );
  if (field.options)
    return (
      <FormField className="feature-field" label={title}>
        <Select
          id={id}
          className="text-input"
          value={String(value ?? field.options[0])}
          onChange={(e) => change(field.path, e.target.value)}
        >
          {field.options.map((option) => (
            <option key={String(option)} value={String(option)}>
              {optionLabels[String(option)]
                ? translate(language, optionLabels[String(option)])
                : String(option)}
            </option>
          ))}
        </Select>
      </FormField>
    );
  const number = field.kind === 'number';
  return (
    <label className={`feature-field${field.wide ? ' auto-select-wide' : ''}`}>
      <span>{title}</span>
      <Input
        id={id}
        className="text-input"
        type={number ? 'number' : field.path === 'url' ? 'url' : 'text'}
        required={['url', 'timeout', 'reuse_ttl'].includes(field.path)}
        aria-describedby={field.hint ? id + '-hint' : undefined}
        min={field.min}
        max={field.max}
        value={value === undefined || value === null ? '' : String(value)}
        onChange={(e) =>
          change(
            field.path,
            number ? (e.target.value === '' ? undefined : Number(e.target.value)) : e.target.value,
          )
        }
      />
      {field.hint && (
        <small className="field-help" id={id + '-hint'}>
          {label(field.hint, language)}
        </small>
      )}
    </label>
  );
}

export default function AutoSelectConfig({
  snapshot,
  close,
  refresh,
  translateError,
}: {
  snapshot: Snapshot;
  close: () => void;
  refresh: () => Promise<void>;
  translateError(e: unknown): string;
}) {
  const language = snapshot.preferences.language;
  const t = (key: keyof typeof autoSelectWords) => translate(language, autoSelectWords[key]);
  const { config, change, failover, setFailover, sourceGroupId, setSourceGroupId, reset, save, busy, error } =
    useAutoSelectConfig(snapshot, close, refresh);
  const groups = [...snapshot.groups].sort((a, b) => Number(b.subscribed) - Number(a.subscribed));
  const missingSource = sourceGroupId !== null && !groups.some((group) => group.id === sourceGroupId);
  const reuseTtl = String(config.reuse_ttl ?? defaultAutoSelectConfig.reuse_ttl);
  const interval = String(config.interval ?? defaultAutoSelectConfig.interval);
  return (
    <Modal
      title={t('dialogTitle')}
      description={t('dialogDescription')}
      close={close}
      className="auto-select-config"
      initialFocus="#auto-select-source"
      footer={
        <>
          <Button
            type="button"
            className="button secondary"
            id="auto-select-cancel"
            onClick={close}
            disabled={busy}
          >
            {t('cancel')}
          </Button>
          <Button
            type="submit"
            form="auto-select-settings-form"
            className="button primary"
            id="auto-select-save"
            disabled={busy}
          >
            {t('save')}
          </Button>
        </>
      }
    >
      {error && (
        <InlineError role="alert" className="desktop-inline-error" id="auto-select-config-error">
          {translateError(error)}
        </InlineError>
      )}
      <form
        id="auto-select-settings-form"
        onSubmit={(event) => {
          event.preventDefault();
          void save();
        }}
      >
        <fieldset disabled={busy} className="auto-select-fields">
          <FormField className="feature-field" label={t('source')}>
            <Select
              id="auto-select-source"
              value={sourceGroupId ?? ''}
              aria-describedby="auto-select-source-hint"
              onChange={(event) => setSourceGroupId(event.target.value || null)}
            >
              <option value="">{t('allGroups')}</option>
              {missingSource && (
                <option value={sourceGroupId} disabled>
                  {t('sourceDeleted')}
                </option>
              )}
              {groups.map((group) => (
                <option key={group.id} value={group.id}>
                  {groupName(group, language)}
                </option>
              ))}
            </Select>
            <small className="field-help" id="auto-select-source-hint">
              {t('sourceHint')}
            </small>
          </FormField>
          <label className="setting-toggle auto-select-failover">
            <span>
              <strong>{t('failover')}</strong>
              <small id="auto-select-failover-hint" className="field-help">
                {t('failoverHint')}
              </small>
            </span>
            <Checkbox
              id="auto-select-failover"
              role="switch"
              checked={failover}
              aria-describedby="auto-select-failover-hint"
              onChange={(event) => setFailover(event.target.checked)}
            />
          </label>
          <div className="settings-field-grid auto-select-presets">
            <FormField className="feature-field" label={t('remember')}>
              <Select
                id="auto-select-reuse_ttl"
                value={reuseTtl}
                onChange={(event) => change('reuse_ttl', event.target.value)}
              >
                {durationOptions(reuseTtlPresets, reuseTtl, language).map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </Select>
            </FormField>
            <FormField className="feature-field" label={t('interval')}>
              <Select
                id="auto-select-interval"
                value={interval}
                disabled={!failover}
                onChange={(event) => change('interval', event.target.value)}
              >
                {durationOptions(intervalPresets, interval, language).map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </Select>
            </FormField>
          </div>
          <p className="auto-select-info" role="note">
            <Icon name="info" />
            <span>{t('info')}</span>
          </p>
          <Section title={t('advanced')} className="auto-select-advanced" id="auto-select-advanced">
            <div className="auto-select-advanced-body">
              {advancedSections(config).map((section) => (
                <section key={section.id} className="auto-select-config-section">
                  <h3>{label(section.label, language)}</h3>
                  <div className="settings-field-grid">
                    {section.fields.map((field) => (
                      <ConfigField
                        key={field.path}
                        field={field}
                        config={config}
                        language={language}
                        change={change}
                      />
                    ))}
                  </div>
                </section>
              ))}
              <Button type="button" variant="text" id="auto-select-reset" onClick={reset}>
                {t('reset')}
              </Button>
            </div>
          </Section>
        </fieldset>
      </form>
    </Modal>
  );
}
