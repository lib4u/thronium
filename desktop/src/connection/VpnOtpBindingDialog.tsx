import { useMessageState } from '../shared/i18n/react';
import { InlineError, Field } from '../shared/ui/controls';
import { Button, Select } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import type * as Wire from '../shared/api/generated/commands';
import { useEffect, useRef, useState } from 'react';
import { command, type Profile } from '../api';
import { Modal } from '../ui';
import { vpnOtpError } from './vpnOtpMessages';

type OtpRow = Wire.VpnBindingOtpRow;
type BindingView = Wire.VpnOtpBinding;

export default function VpnOtpBindingDialog({
  profile,
  language,
  close,
  changed,
}: {
  profile: Profile;
  language: string;
  close(): void;
  changed(): Promise<void>;
}) {
  const [view, setView] = useState<BindingView>();
  const [rows, setRows] = useState<OtpRow[]>([]);
  const [selected, setSelected] = useState('');
  const [mode, setMode] = useState<'auto-live' | 'auto-start'>('auto-live');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useMessageState(language, (e) => vpnOtpError(e, language));
  const mounted = useRef(false);
  const sequence = useRef(0);
  const submitting = useRef(false);
  const row = rows.find((item) => item.id === selected);
  const modeSupported = mode === 'auto-start' ? !!view?.startSupported : !!view?.supported;
  const selectedSupported = modeSupported && !(row?.type === 'hotp' && view?.hotpSupported === false);
  const dirty =
    !!view &&
    (selected !== (view.binding?.otpId || '') ||
      (!!selected && mode !== (view.binding?.mode || 'auto-live')));
  const busy = loading || saving;

  async function load(reset: boolean) {
    const ticket = ++sequence.current;
    setLoading(true);
    setError('');
    try {
      const [next, entries] = await Promise.all([
        command('getVpnOtpBinding', { profileId: profile.id }),
        command('otpList'),
      ]);
      if (!mounted.current || sequence.current !== ticket) return;
      setView(next);
      setRows(entries);
      if (reset) {
        setSelected(next.binding?.otpId || '');
        // A profile whose credentials carry {otp} can only be served before Start.
        setMode(next.binding?.mode || (next.startSupported && !next.supported ? 'auto-start' : 'auto-live'));
      }
    } catch (e) {
      if (mounted.current && sequence.current === ticket) setError(e);
    } finally {
      if (mounted.current && sequence.current === ticket) setLoading(false);
    }
  }
  useEffect(() => {
    mounted.current = true;
    void load(true);
    return () => {
      mounted.current = false;
      sequence.current++;
    };
  }, [profile.id]);

  async function save() {
    if (!view || busy || submitting.current || !dirty || (selected && (!row || !selectedSupported))) return;
    submitting.current = true;
    setSaving(true);
    setError('');
    try {
      await command('saveVpnOtpBinding', {
        profileId: profile.id,
        editToken: view.editToken,
        otpId: selected || null,
        otpRevision: row?.revision || null,
        mode: selected ? mode : undefined,
      });
      await changed();
      if (mounted.current) close();
    } catch (e) {
      if (mounted.current) setError(e);
    } finally {
      submitting.current = false;
      if (mounted.current) setSaving(false);
    }
  }
  return (
    <Modal
      className="vpn-otp-modal"
      title={translate(language, 'connection.automatic_one_time_code_1addf02')}
      description={profile.name}
      initialFocus="#vpn-otp-entry"
      close={() => {
        if (!saving) close();
      }}
      closeLabel={translate(language, 'connection.close_c9a286c')}
      footer={
        <>
          <Button type="button" className="text-button" id="vpn-otp-close" disabled={saving} onClick={close}>
            {translate(language, 'connection.cancel_bf4c449')}
          </Button>
          <Button
            type="button"
            className="button primary"
            id="vpn-otp-save"
            disabled={busy || !dirty || (!!selected && (!row || !selectedSupported))}
            onClick={() => void save()}
          >
            {translate(language, 'connection.save_9cd85bd')}
          </Button>
        </>
      }
    >
      <p className="field-hint">
        {translate(language, 'connection.use_a_saved_otp_entry_to_answer_this_vpn_server__73c3d0c')}
      </p>
      <Field className="feature-field" label={translate(language, 'connection.otp_entry_bfff792')}>
        <Select
          className="text-input"
          id="vpn-otp-entry"
          disabled={busy || !view}
          value={selected}
          onChange={(e) => {
            setSelected(e.target.value);
            setError('');
          }}
        >
          <option value="">{translate(language, 'connection.do_not_use_b154be7')}</option>
          {!!selected && !row && (
            <option value={selected} disabled>
              {translate(language, 'connection.entry_no_longer_available_1a6fe6a')}
            </option>
          )}
          {rows.map((entry) => (
            <option
              key={entry.id}
              value={entry.id}
              disabled={!view?.supported || (entry.type === 'hotp' && view.hotpSupported === false)}
            >
              {[entry.issuer, entry.name].filter(Boolean).join(' · ') ||
                translate(language, 'connection.unnamed_entry_fa23f8c')}{' '}
              ({entry.type.toUpperCase()})
            </option>
          ))}
        </Select>
      </Field>
      {!!selected && (
        <Field className="feature-field" label={translate(language, 'connection.vpn_otp_mode')}>
          <Select
            className="text-input"
            id="vpn-otp-mode"
            disabled={busy || !view}
            value={mode}
            onChange={(e) => {
              setMode(e.target.value as 'auto-live' | 'auto-start');
              setError('');
            }}
          >
            <option value="auto-live" disabled={!view?.supported}>
              {translate(language, 'connection.vpn_otp_mode_live')}
            </option>
            <option value="auto-start" disabled={!view?.startSupported}>
              {translate(language, 'connection.vpn_otp_mode_start')}
            </option>
          </Select>
        </Field>
      )}
      {!!selected && mode === 'auto-start' && (
        <p className="field-hint" id="vpn-otp-start-hint">
          {translate(language, 'connection.vpn_otp_start_hint')}
        </p>
      )}
      {!loading && !rows.length && (
        <p className="field-hint" id="vpn-otp-empty">
          {translate(language, 'connection.add_an_entry_in_settings_otp_codes_then_return_h_ab08416')}
        </p>
      )}
      {!!selected && (
        <p className="field-hint">
          {translate(language, 'connection.a_changed_binding_takes_effect_after_reconnectin_1c4ed95')}
        </p>
      )}
      {!!selected && (
        <p className="field-hint">
          {translate(language, 'connection.a_full_thronium_backup_includes_this_binding_and_254f9de')}
        </p>
      )}
      {row?.type === 'hotp' && (
        <p className="field-hint" id="vpn-otp-hotp-hint">
          {translate(language, 'connection.the_app_increments_and_saves_the_hotp_counter_be_7b8d8c6')}
        </p>
      )}
      {(mode === 'auto-start' ? view?.startReason : view?.reason) && (
        <p className="field-hint" id="vpn-otp-reason">
          {vpnOtpError(mode === 'auto-start' ? view?.startReason : view?.reason, language)}
        </p>
      )}
      {view?.hotpSupported === false &&
        rows.some((entry) => entry.type === 'hotp') &&
        view.reason !== 'vpn_otp_platform_unsupported' && (
          <p className="field-hint">{vpnOtpError('vpn_otp_platform_unsupported', language)}</p>
        )}
      {loading && <p role="status">{translate(language, 'connection.loading_d08c833')}</p>}
      {error && (
        <InlineError className="desktop-inline-error" id="vpn-otp-error" role="alert">
          {error}
        </InlineError>
      )}
      {error && (
        <Button
          type="button"
          className="text-button"
          id="vpn-otp-reload"
          disabled={busy}
          onClick={() => void load(false)}
        >
          {translate(language, 'connection.reload_saved_data_a1d6dc5')}
        </Button>
      )}
    </Modal>
  );
}
