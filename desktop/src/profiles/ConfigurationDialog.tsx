import { formatJson, Field } from '../shared/ui/controls';
import { JsonEditor, InlineError } from '../shared/ui/controls';
import { Button, Select } from '../shared/ui/controls';
import { useMessageState } from '../shared/i18n/react';
import { messageRef } from '../shared/i18n/message';
import { translate, type Language } from '../shared/i18n/index.ts';
import { errorCode } from '../shared/api/errors.ts';
import { useMemo, useRef, useState } from 'react';
import { command, type Draft, type Preferences } from '../api';
import { ConfirmDialog, Icon, Modal } from '../ui';
import './ConfigurationDialog.css';
import { text as uiText } from '../i18n';
import ExportDialog from './ExportDialog';
import { protocolLabel } from '../library/rowData';
import { limits } from '../shared/api/generated/limits.ts';

export default function ConfigurationDialog({
  draft: initialDraft,
  language,
  runningId,
  preferences,
  close,
  changed,
  translateError,
}: {
  draft: import('../shared/api/generated/commands').EditableProfile;
  preferences: Preferences;
  language: Language;
  runningId: string | null;
  close(): void;
  changed(): Promise<void>;
  translateError(e: unknown): string;
}) {
  const t = (key: 'profileReload' | 'profileReloadConfirm' | 'profile_configuration_changed') =>
    uiText(language, key);
  const [draft, setDraft] = useState(initialDraft);
  const [conflict, setConflict] = useState(false);
  const [confirmReload, setConfirmReload] = useState(false);
  const submitting = useRef(false);
  function fail(error: unknown) {
    if (errorCode(error) === 'profile_configuration_changed') {
      setConflict(true);
      setError(messageRef('errors.profile_configuration_changed'));
    } else setError(error);
  }
  async function reload() {
    if (busy || submitting.current || !draft.id) return;
    submitting.current = true;
    setBusy(true);
    try {
      const latest = await command('profile', { id: draft.id });
      setDraft(latest);
      setText(JSON.stringify(latest.config, null, 2));
      setSharingPolicy(latest.vpnPolicy);
      setView('source');
      setParts([]);
      setPart(0);
      setError('');
      setStatus('');
      setConflict(false);
      setConfirmReload(false);
    } catch (error) {
      fail(error);
    } finally {
      submitting.current = false;
      setBusy(false);
    }
  }
  async function changeCore(core: string) {
    if (busy || submitting.current || !['default', 'xray', 'sing-box'].includes(core)) return;
    submitting.current = true;
    setBusy(true);
    setError('');
    try {
      const latest = await command('saveProfileCore', {
        id: draft.id,
        expectedRevision: draft.expectedRevision,
        core: core === 'default' ? null : core === 'xray' ? 'xray' : 'sing-box',
      });
      setDraft(latest);
      await changed();
      setStatus(messageRef('profiles.core_saved_for_the_next_connection_7f456d1'));
    } catch (error) {
      fail(error);
    } finally {
      submitting.current = false;
      setBusy(false);
    }
  }
  const [sharing, setSharing] = useState(false);
  const [sharingPolicy, setSharingPolicy] = useState<Draft['vpnPolicy']>(draft.vpnPolicy);
  const [text, setText] = useState(() => JSON.stringify(draft.config, null, 2));
  const [busy, setBusy] = useState(false);
  const [confirmClose, setConfirmClose] = useState(false);
  const [error, setError] = useMessageState(language, translateError);
  const [status, setStatus] = useMessageState(language, translateError);
  const [view, setView] = useState<'source' | 'preview' | 'active'>('source');
  const [parts, setParts] = useState<{ name: string; config: Draft['config'] }[]>([]);
  const [part, setPart] = useState(0);
  const parsed = useMemo(() => {
    try {
      const value = JSON.parse(text);
      return value && typeof value === 'object' && !Array.isArray(value) ? (value as Draft['config']) : null;
    } catch {
      return null;
    }
  }, [text]);
  const tooLarge = new TextEncoder().encode(text).length > limits.maxConfigBytes;
  const dirty = !parsed || JSON.stringify(parsed) !== JSON.stringify(draft.config);
  const displayed = view === 'source' ? parsed : parts[part]?.config;
  async function show(next: typeof view) {
    if (busy) return;
    setError('');
    setStatus('');
    if (next === 'source') {
      setView(next);
      return;
    }
    setBusy(true);
    try {
      const result = await command('connectionConfiguration', {
        id: draft.id,
        active: next === 'active',
      });
      setParts(result.parts);
      setPart(0);
      setView(next);
    } catch (e) {
      setError(
        errorCode(e) === 'active_configuration_unavailable'
          ? messageRef('profiles.the_active_configuration_is_unavailable_while_di_1ffca1b')
          : e,
      );
    } finally {
      setBusy(false);
    }
  }
  const requestClose = () => {
    if (!busy) {
      if (dirty) setConfirmClose(true);
      else close();
    }
  };
  async function openSharing() {
    if (busy || !parsed) return;
    setBusy(true);
    setError('');
    try {
      const current = draft.id ? await command('profile', { id: draft.id }) : draft;
      setSharingPolicy(current.vpnPolicy);
      setSharing(true);
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  async function act(action: 'check' | 'save' | 'file' | 'clipboard') {
    if (busy || submitting.current || !displayed || (view === 'source' && tooLarge)) return;
    if (view !== 'source' && (action === 'save' || action === 'check')) return;
    submitting.current = true;
    setBusy(true);
    setError('');
    setStatus('');
    try {
      if (view === 'source' && draft.vpnPolicy && (action === 'file' || action === 'clipboard'))
        throw Error('vpn_policy_export_requires_bundle');
      if (action === 'check') {
        await command('checkProfile', { ...draft, config: displayed });
        setStatus(
          draft.kind === 'external-core'
            ? messageRef('profiles.launch_parameters_and_executable_checked_socks5__7d8c2e2')
            : messageRef('profiles.configuration_accepted_by_the_core_3e3f736'),
        );
      } else if (action === 'save') {
        await command('saveProfileConfiguration', {
          id: draft.id,
          expectedRevision: draft.expectedRevision,
          config: displayed,
        });
        await changed();
        close();
      } else {
        const result = await command('exportConfiguration', {
          config: displayed,
          destination: action,
          ...(view === 'source' && draft.id ? { sourceProfileId: draft.id } : {}),
        });
        if (result.status === 'saved') setStatus(messageRef('profiles.file_saved_391e905'));
        if (result.status === 'copied') setStatus(messageRef('profiles.copied_to_clipboard_4cddbf1'));
      }
    } catch (e) {
      fail(e);
    } finally {
      submitting.current = false;
      setBusy(false);
    }
  }
  const disabled = busy || !displayed || (view === 'source' && tooLarge);
  return (
    <Modal
      inert={sharing}
      className="configuration-modal"
      title={
        view === 'source'
          ? translate(language, 'profiles.server_configuration_1ec9897')
          : translate(language, 'profiles.connection_configuration_8e89332')
      }
      description={draft.name}
      initialFocus="#configuration-json"
      close={requestClose}
      closeLabel={translate(language, 'profiles.close_c9a286c')}
      footer={
        <>
          <Button
            className="button secondary"
            id="configuration-copy"
            disabled={disabled || (view === 'source' && !!draft.vpnPolicy)}
            onClick={() => void act('clipboard')}
          >
            <Icon name="copy" />
            {translate(language, 'profiles.copy_e2d2d65')}
          </Button>
          <Button
            className="button secondary"
            id="configuration-export"
            disabled={disabled || (view === 'source' && !!draft.vpnPolicy)}
            onClick={() => void act('file')}
          >
            <Icon name="download" />
            {translate(language, 'profiles.export_to_file_1356a5c')}
          </Button>
          {view === 'source' && !['chain', 'auto-selector', 'external-core'].includes(draft.kind) && (
            <Button
              className="button secondary"
              id="configuration-share"
              disabled={disabled}
              onClick={() => void openSharing()}
            >
              {draft.vpnPolicy
                ? translate(language, 'profiles.full_profile_export_ad964fb')
                : translate(language, 'profiles.link_qr_wg_cdf8109')}
            </Button>
          )}
          <span className="filter-spacer" />
          <Button className="text-button" disabled={busy} onClick={requestClose}>
            {translate(language, 'profiles.cancel_bf4c449')}
          </Button>
          {view === 'source' && (
            <Button
              className="button primary"
              id="configuration-save"
              disabled={disabled || !dirty}
              onClick={() => void act('save')}
            >
              <Icon name="check" />
              {translate(language, 'profiles.save_9cd85bd')}
            </Button>
          )}
        </>
      }
    >
      {view === 'source' &&
        ['sing-box-outbound', 'xray-outbound'].includes(draft.kind) &&
        (draft.config.type === 'vless' || draft.config.protocol === 'vless') && (
          <Field className="feature-field" label={translate(language, 'profiles.vless_core_d336ca0')}>
            <Select
              id="profile-vless-core"
              className="text-input"
              disabled={busy}
              value={draft.vlessCore || 'default'}
              onChange={(e) => void changeCore(e.target.value)}
            >
              <option value="default">
                {translate(language, 'profiles.default_de0b656')} (
                {preferences.vlessCore === 'xray' ? 'Xray' : 'sing-box'})
              </option>
              <option value="xray">Xray</option>
              <option value="sing-box">sing-box</option>
            </Select>
          </Field>
        )}
      <div
        className="configuration-views"
        role="group"
        aria-label={translate(language, 'profiles.configuration_source_359ed1e')}
      >
        {(['source', 'preview', 'active'] as const).map((v) => (
          <Button
            key={v}
            id={`configuration-${v}`}
            className="text-button"
            aria-pressed={view === v}
            disabled={busy || (v === 'active' && runningId !== draft.id)}
            onClick={() => void show(v)}
          >
            {v === 'source'
              ? translate(language, 'profiles.server_772c781')
              : v === 'preview'
                ? translate(language, 'profiles.next_connection_50bcaca')
                : translate(language, 'profiles.currently_running_cde2c79')}
          </Button>
        ))}
      </div>
      {view === 'source' && draft.vpnPolicy && (
        <p className="field-hint" id="configuration-policy-hint">
          {translate(language, 'profiles.the_server_json_does_not_include_the_vpn_routing_d18404c')}
        </p>
      )}
      {view !== 'source' && (
        <>
          <p className="field-hint configuration-runtime-hint">
            {view === 'active'
              ? translate(language, 'profiles.configuration_sent_to_the_running_core_pending_c_6357353')
              : translate(language, 'profiles.preview_from_the_saved_server_and_current_settin_f627ade')}
          </p>
          <div
            className="configuration-views"
            role="group"
            aria-label={translate(language, 'profiles.core_17e16aa')}
          >
            {parts.map((p, i) => (
              <Button
                className="text-button"
                aria-pressed={part === i}
                key={p.name}
                onClick={() => setPart(i)}
              >
                {protocolLabel(p.name, language)}
              </Button>
            ))}
          </div>
        </>
      )}
      <div className="configuration-toolbar">
        <label htmlFor="configuration-json">JSON</label>
        <span className="filter-spacer" />
        {view === 'source' && (
          <>
            <Button
              className="text-button"
              id="configuration-format"
              disabled={disabled}
              onClick={() => setText(formatJson(text))}
            >
              {translate(language, 'profiles.format_65b1d52')}
            </Button>
            <Button
              className="text-button"
              id="configuration-check"
              disabled={disabled}
              onClick={() => void act('check')}
            >
              {translate(language, 'profiles.check_3b08b46')}
            </Button>
          </>
        )}
      </div>
      <JsonEditor
        id="configuration-json"
        className="text-input mono"
        spellCheck={false}
        autoComplete="off"
        autoCapitalize="off"
        wrap="off"
        aria-describedby="configuration-hint"
        aria-invalid={view === 'source' && (!parsed || tooLarge)}
        value={view === 'source' ? text : JSON.stringify(displayed, null, 2)}
        readOnly={view !== 'source'}
        disabled={busy}
        onChange={(e) => {
          setText(e.target.value);
          setError('');
          setStatus('');
        }}
      />
      <p className="field-hint" id="configuration-hint">
        {translate(language, 'profiles.the_json_includes_passwords_and_keys_export_uses_9fb938d')}
      </p>
      {((view === 'source' && (!parsed || tooLarge)) || error) && (
        <InlineError className="desktop-inline-error" role="alert">
          {view === 'source' && tooLarge
            ? translate(language, 'profiles.configuration_size_limit')
            : view === 'source' && !parsed
              ? translate(language, 'profiles.enter_a_valid_json_object_9526bac')
              : error}
        </InlineError>
      )}
      {conflict && (
        <Button
          id="configuration-reload"
          className="button secondary"
          disabled={busy}
          onClick={() => setConfirmReload(true)}
        >
          {t('profileReload')}
        </Button>
      )}
      {confirmReload && (
        <ConfirmDialog
          title={t('profileReloadConfirm')}
          cancelLabel={translate(language, 'profiles.keep_editing_7c292c4')}
          confirmLabel={t('profileReload')}
          busy={busy}
          error={error}
          cancel={() => setConfirmReload(false)}
          confirm={() => void reload()}
        />
      )}
      {status && (
        <p className="import-valid" id="configuration-status" role="status">
          {status}
        </p>
      )}
      {sharing && parsed && (
        <ExportDialog
          drafts={[
            {
              ...draft,
              vpnPolicy: sharingPolicy,
              config: parsed,
              ...(parsed.type === 'vless' || parsed.protocol === 'vless'
                ? { vlessCore: preferences.vlessOverrides[draft.id || ''] || preferences.vlessCore }
                : {}),
            },
          ]}
          language={language}
          close={() => setSharing(false)}
          translateError={translateError}
        />
      )}
      {confirmClose && (
        <ConfirmDialog
          title={translate(language, 'profiles.discard_unsaved_changes_2326ec7')}
          message={translate(language, 'profiles.changes_in_this_editor_will_be_lost_704fc47')}
          cancelLabel={translate(language, 'profiles.keep_editing_7c292c4')}
          confirmLabel={translate(language, 'profiles.discard_6febe61')}
          cancel={() => setConfirmClose(false)}
          confirm={close}
        />
      )}
    </Modal>
  );
}
