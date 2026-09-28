import { useMessageState } from '../shared/i18n/react';
import { InlineError } from '../shared/ui/controls';
import { Checkbox, Button } from '../shared/ui/controls';
import { translate, type Language } from '../shared/i18n/index.ts';
import { errorCode } from '../shared/api/errors.ts';
import { useEffect, useRef, useState } from 'react';
import { command } from '../api';
import type { WarpConfig } from './config';
import './Generator.css';

export default function WarpGenerator({
  language,
  disabled,
  useConfig,
  translateError,
  profile = false,
}: {
  language: Language;
  disabled: boolean;
  useConfig(config: WarpConfig): void;
  translateError(e: unknown): string;
  profile?: boolean;
}) {
  const [accepted, setAccepted] = useState(false),
    [pending, setPending] = useState(false),
    [cancelling, setCancelling] = useState(false),
    [result, setResult] = useState<WarpConfig>(),
    [error, setError] = useMessageState(language, translateError);
  const owner = useRef<string | undefined>(undefined),
    cancelRequested = useRef(false);
  useEffect(
    () => () => {
      const requestId = owner.current;
      owner.current = undefined;
      if (requestId) void command('cancelWarpRegistration', { requestId }).catch(() => {});
    },
    [],
  );
  async function generate() {
    if (disabled || owner.current || !accepted) return;
    const requestId = crypto.randomUUID();
    owner.current = requestId;
    cancelRequested.current = false;
    setPending(true);
    setCancelling(false);
    setError('');
    setResult(undefined);
    try {
      const config = await command('registerWarp', { requestId, acceptTerms: true });
      if (owner.current === requestId && !cancelRequested.current) setResult(config);
    } catch (e) {
      if (owner.current === requestId) {
        const code = errorCode(e);
        if (!['warp_cancelled', 'warp_request_finished'].includes(code)) setError(e);
      }
    } finally {
      if (owner.current === requestId) {
        owner.current = undefined;
        setPending(false);
        setCancelling(false);
      }
    }
  }
  async function cancel() {
    const requestId = owner.current;
    if (!requestId) return;
    cancelRequested.current = true;
    setCancelling(true);
    try {
      await command('cancelWarpRegistration', { requestId });
    } catch (e) {
      setError(e);
      setCancelling(false);
    }
  }
  return (
    <div className="warp-generator" data-warp-generator>
      <h3>{translate(language, 'settings.create_warp_configuration_37d082a')}</h3>
      <p className="field-hint">
        {translate(language, 'settings.registers_a_wireguard_public_key_with_cloudflare_c604929')}
      </p>
      <label className="warp-consent">
        <Checkbox
          type="checkbox"
          data-warp-terms
          checked={accepted}
          disabled={pending || disabled}
          onChange={(e) => setAccepted(e.target.checked)}
        />
        <span>{translate(language, 'settings.i_accept_the_cloudflare_application_terms_2f38bd5')}</span>
      </label>
      <Button
        type="button"
        className="text-button"
        data-warp-open-terms
        onClick={() => void command('openWarpTerms').catch((e) => setError(e))}
      >
        {translate(language, 'settings.read_cloudflare_terms_0fc547a')}
      </Button>
      <div className="warp-actions">
        <Button
          type="button"
          className="button secondary"
          data-warp-generate
          disabled={disabled || pending || !accepted}
          onClick={() => void generate()}
        >
          {pending
            ? translate(language, 'settings.creating_4228f03')
            : translate(language, 'settings.create_configuration_5ad3b9e')}
        </Button>
        {pending && (
          <Button
            type="button"
            className="text-button"
            data-warp-cancel
            disabled={cancelling}
            onClick={() => void cancel()}
          >
            {cancelling
              ? translate(language, 'settings.cancelling_4bcce1c')
              : translate(language, 'settings.cancel_bf4c449')}
          </Button>
        )}
      </div>
      {result && (
        <div className="warp-result" data-warp-result>
          <dl>
            <dt>{translate(language, 'settings.server_772c781')}</dt>
            <dd>{result.endpoint}</dd>
            <dt>{translate(language, 'settings.interface_addresses_6c75e0c')}</dt>
            <dd>{result.addresses.join(', ')}</dd>
          </dl>
          <p className="field-hint">
            {profile
              ? translate(language, 'settings.fills_this_profile_with_the_new_key_addresses_an_bcff5c2')
              : translate(language, 'settings.fills_the_warp_fields_save_settings_then_enable__cad49bf')}
          </p>
          <Button
            type="button"
            className="button secondary"
            data-warp-use
            disabled={disabled}
            onClick={() => {
              useConfig(result);
              setResult(undefined);
            }}
          >
            {translate(language, 'settings.use_in_this_form_98e6475')}
          </Button>
        </div>
      )}
      {error && (
        <InlineError role="alert" className="desktop-inline-error">
          {error}
        </InlineError>
      )}
    </div>
  );
}
