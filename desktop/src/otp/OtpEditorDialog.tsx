import { InlineError, Field } from '../shared/ui/controls';
import { Button, Input, Checkbox, Select, NumberField } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import { Modal } from '../ui';
import { Draft } from './OtpModel';
import type { useOtpController } from './useOtpController';
import { limits } from '../shared/api/generated/limits.ts';
export default function OtpEditorDialog({ controller }: { controller: ReturnType<typeof useOtpController> }) {
  const { busy, close, editor, error, field, language, save, setShowSecret, showSecret } = controller;
  if (!editor) return null;
  const cancel = (
    <Button type="button" className="button secondary" disabled={busy} onClick={close}>
      {translate(language, 'otp.cancel_bf4c449')}
    </Button>
  );
  return (
    <Modal
      title={
        editor.id
          ? translate(language, 'otp.edit_authenticator_entry_4445e51')
          : translate(language, 'otp.add_authenticator_entry_1632c4c')
      }
      close={close}
      closeLabel={translate(language, 'otp.cancel_bf4c449')}
      footer={
        <>
          {cancel}
          <Button className="button primary" id="otp-save" form="otp-editor" disabled={busy}>
            {translate(language, 'otp.save_9cd85bd')}
          </Button>
        </>
      }
    >
      <form
        id="otp-editor"
        className="otp-form"
        onSubmit={(e) => {
          e.preventDefault();
          void save();
        }}
      >
        <Field className="feature-field" label={translate(language, 'otp.name_account_28cbd8a')}>
          <Input
            className="text-input"
            id="otp-name"
            maxLength={limits.maxOtpLabelBytes}
            disabled={busy}
            value={editor.value.name}
            onChange={(e) => field('name', e.target.value)}
          />
        </Field>
        <Field className="feature-field" label={translate(language, 'otp.issuer_cdeeacf')}>
          <Input
            className="text-input"
            id="otp-issuer"
            maxLength={limits.maxOtpLabelBytes}
            disabled={busy}
            value={editor.value.issuer}
            onChange={(e) => field('issuer', e.target.value)}
          />
        </Field>
        <Field className="feature-field" label={translate(language, 'otp.base32_secret_dbe1382')}>
          <Input
            className="text-input"
            id="otp-secret"
            type={showSecret ? 'text' : 'password'}
            autoComplete="off"
            spellCheck={false}
            maxLength={limits.maxOtpSecretTextBytes}
            required
            disabled={busy}
            value={editor.value.secret}
            onChange={(e) => field('secret', e.target.value)}
          />
        </Field>
        <label className="import-toggle">
          <Checkbox type="checkbox" checked={showSecret} onChange={(e) => setShowSecret(e.target.checked)} />
          {translate(language, 'otp.show_secret_8d0007e')}
        </label>
        <div className="otp-form-grid">
          <Field className="feature-field" label={translate(language, 'otp.type_756c9a6')}>
            <Select
              className="text-input"
              id="otp-type"
              disabled={busy}
              value={editor.value.type}
              onChange={(e) => field('type', e.target.value as Draft['type'])}
            >
              <option value="totp">TOTP</option>
              <option value="hotp">HOTP</option>
            </Select>
          </Field>
          <Field className="feature-field" label={translate(language, 'otp.algorithm_ba28e54')}>
            <Select
              className="text-input"
              id="otp-algorithm"
              disabled={busy}
              value={editor.value.algorithm}
              onChange={(e) => field('algorithm', e.target.value as Draft['algorithm'])}
            >
              {['SHA1', 'SHA256', 'SHA512'].map((v) => (
                <option key={v}>{v}</option>
              ))}
            </Select>
          </Field>
          <Field className="feature-field" label={translate(language, 'otp.digits_de1d27b')}>
            <NumberField
              className="text-input"
              id="otp-digits"
              type="number"
              min={limits.otpDigitsMin}
              max={limits.otpDigitsMax}
              required
              disabled={busy}
              value={editor.value.digits}
              onChange={(e) => field('digits', Number(e.target.value))}
            />
          </Field>
          {editor.value.type === 'totp' ? (
            <Field className="feature-field" label={translate(language, 'otp.period_seconds_5887f3d')}>
              <NumberField
                className="text-input"
                id="otp-period"
                type="number"
                min={limits.otpPeriodSecondsMin}
                max={limits.otpPeriodSecondsMax}
                required
                disabled={busy}
                value={editor.value.period}
                onChange={(e) => field('period', Number(e.target.value))}
              />
            </Field>
          ) : (
            <Field className="feature-field" label={translate(language, 'otp.counter_e4184c4')}>
              <Input
                className="text-input"
                id="otp-counter"
                inputMode="numeric"
                pattern="[0-9]+"
                maxLength={limits.maxOtpCounterDigits}
                required
                disabled={busy}
                value={editor.value.counter}
                onChange={(e) => field('counter', e.target.value)}
              />
            </Field>
          )}
        </div>
        {error && (
          <InlineError className="desktop-inline-error" role="alert">
            {error}
          </InlineError>
        )}
      </form>
    </Modal>
  );
}
