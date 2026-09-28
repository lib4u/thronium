import { useMessageState } from '../shared/i18n/react';
import { InlineError } from '../shared/ui/controls';
import { Button, Input } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import { useEffect, useRef, useState } from 'react';
import { command, type VpnStatus } from '../api';
import { Modal } from '../ui';
import {
  credentialsError,
  credentialsKey,
  isCurrentCredentials,
  validCredentials,
  type CredentialRequest,
  type CredentialView,
} from './vpnCredentials';
import './vpnAuth.css';
import { limits } from '../shared/api/generated/limits.ts';

export default function VpnCredentialsDialog({
  request,
  label,
  status,
  language,
  close,
  refresh,
}: {
  request: CredentialRequest;
  label: string;
  status: VpnStatus;
  language: string;
  close(): void;
  refresh(): Promise<void>;
}) {
  const [view, setView] = useState<CredentialView>();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useMessageState(language, (e) => credentialsError(e, language));
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [reload, setReload] = useState(0);
  const mounted = useRef(false),
    action = useRef(false);
  const current = isCurrentCredentials(status, request),
    key = credentialsKey(request);
  const live = useRef({ current, key });
  live.current = { current, key };
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  useEffect(() => {
    let disposed = false;
    setView(undefined);
    setUsername('');
    setPassword('');
    setLoading(current);
    if (current) setError('');
    if (current)
      void command('vpnCredentials', request)
        .then((next) => {
          if (disposed || !live.current.current || live.current.key !== key || credentialsKey(next) !== key)
            return;
          setView(next);
          setUsername(next.username);
        })
        .catch((e) => {
          if (!disposed) setError(e);
        })
        .finally(() => {
          if (!disposed) setLoading(false);
        });
    return () => {
      disposed = true;
    };
  }, [key, current, reload]);
  async function cancel() {
    if (action.current) return;
    action.current = true;
    setBusy(true);
    setPassword('');
    try {
      if (view && current) await command('cancelVpnCredentials', { ...request, editToken: view.editToken });
    } catch {
      /* Closing never restarts the connection; a stale edit token needs no action. */
    } finally {
      action.current = false;
      if (mounted.current) close();
    }
  }
  async function submit() {
    if (action.current || !current || !view || !validCredentials(username, password)) return;
    action.current = true;
    setBusy(true);
    setError('');
    const payload = { ...request, editToken: view.editToken, username, password };
    setPassword('');
    setView(undefined);
    try {
      await command('restartVpnCredentials', payload);
      if (mounted.current) close();
      await refresh();
    } catch (e) {
      if (mounted.current) setError(e);
      await refresh().catch(() => {});
    } finally {
      action.current = false;
      if (mounted.current) setBusy(false);
    }
  }
  const disabled = busy || loading || !current || !view;
  return (
    <Modal
      title={translate(language, 'connection.retry_vpn_sign_in_b3572cf')}
      description={label}
      className="vpn-auth-modal"
      close={() => void cancel()}
      closeLabel={translate(language, 'connection.cancel_bf4c449')}
      initialFocus="#vpn-credentials-username"
      footer={
        <>
          <Button
            type="button"
            className="button secondary"
            id="vpn-credentials-cancel"
            disabled={busy}
            onClick={() => void cancel()}
          >
            {translate(language, 'connection.cancel_bf4c449')}
          </Button>
          <Button
            type="submit"
            form="vpn-credentials-form"
            className="button primary"
            id="vpn-credentials-submit"
            disabled={disabled || !validCredentials(username, password)}
          >
            {translate(language, 'connection.reconnect_48b2bc9')}
          </Button>
        </>
      }
    >
      <p className="field-hint">
        {translate(language, 'connection.the_server_rejected_the_saved_credentials_enter__a50d5a4')}
      </p>
      {!current && <p role="status">{credentialsError('vpn_credentials_unavailable', language)}</p>}
      {loading && <p role="status">{translate(language, 'connection.loading_d08c833')}</p>}
      {busy && <p role="status">{translate(language, 'connection.applying_c9d97c2')}</p>}
      {current && view && (
        <form
          id="vpn-credentials-form"
          autoComplete="off"
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <label className="field">
            <span>{translate(language, 'connection.username_6aa87e9')}</span>
            <Input
              id="vpn-credentials-username"
              className="text-input"
              value={username}
              maxLength={limits.maxVpnCredentialBytes}
              disabled={disabled}
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              onChange={(e) => setUsername(e.target.value)}
            />
          </label>
          <label className="field">
            <span>{translate(language, 'connection.password_8714570')}</span>
            <Input
              id="vpn-credentials-password"
              className="text-input"
              type="password"
              value={password}
              maxLength={limits.maxVpnCredentialBytes}
              disabled={disabled}
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          {!!(username || password) && !validCredentials(username, password) && (
            <InlineError className="desktop-inline-error" role="alert">
              {credentialsError('vpn_credentials_invalid', language)}
            </InlineError>
          )}
        </form>
      )}
      {error && (
        <InlineError id="vpn-credentials-error" className="desktop-inline-error" role="alert">
          {error}
        </InlineError>
      )}
      {error && current && !busy && (
        <Button
          type="button"
          className="text-button"
          id="vpn-credentials-reload"
          onClick={() => setReload((old) => old + 1)}
        >
          {translate(language, 'connection.reload_sign_in_request_38f39b9')}
        </Button>
      )}
    </Modal>
  );
}
