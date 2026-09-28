import { LoadingState } from '../shared/ui/controls';
import { InlineError } from '../shared/ui/controls';
import { Input, Button, Select } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index';
import { useMessageState } from '../shared/i18n/react';
import { useEffect, useRef, useState } from 'react';
import { command, type VpnChallenge, type VpnChallengeRequest, type VpnStatus } from '../api';
import { Modal } from '../ui';
import {
  answerRequest,
  canAnswer,
  challengeExpired,
  challengeKey,
  initialAnswers,
  isCurrentChallenge,
  type Answers,
} from './vpnAuth';
import { vpnError, vpnText } from './vpnMessages';
import './vpnAuth.css';
import { limits } from '../shared/api/generated/limits.ts';

type Props = {
  request: VpnChallengeRequest;
  label: string;
  status: VpnStatus;
  language: string;
  close(): void;
  refresh(): Promise<void>;
};
export default function VpnAuthDialog({ request, label, status, language, close, refresh }: Props) {
  const t = (key: Parameters<typeof vpnText>[0]) => vpnText(key, language);
  const [challenge, setChallenge] = useState<VpnChallenge>();
  const [answers, setAnswers] = useState<Answers>({ username: '', password: '', secret: '', fields: {} });
  const [url, setUrl] = useState('');
  const [error, setError] = useMessageState(language, (value) => vpnError(value, language));
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [reload, setReload] = useState(0);
  const [now, setNow] = useState(Date.now());
  const mounted = useRef(false);
  const action = useRef(false);
  const key = challengeKey(request);
  const current = isCurrentChallenge(status, request);
  const live = useRef({ current, key });
  live.current = { current, key };
  useEffect(() => {
    mounted.current = true;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => {
      mounted.current = false;
      clearInterval(timer);
    };
  }, []);
  useEffect(() => {
    let disposed = false;
    setLoading(true);
    setError('');
    setChallenge(undefined);
    setUrl('');
    setAnswers({ username: '', password: '', secret: '', fields: {} });
    if (!current) {
      setLoading(false);
      return;
    }
    void command('vpnChallenge', request)
      .then(async (next) => {
        if (disposed || !live.current.current || live.current.key !== key || challengeKey(next) !== key)
          return;
        if (challengeExpired(next)) {
          setChallenge({ ...next, username: '', message: '', banner: '', error: '', fields: [] });
          return;
        }
        setChallenge(next);
        setAnswers(initialAnswers(next));
        if (next.kind === 'open-url') {
          try {
            const address = await command('vpnChallengeUrl', request);
            if (!disposed && live.current.current && live.current.key === key && !challengeExpired(next))
              setUrl(address);
          } catch (e) {
            if (!disposed) setError(e);
          }
        }
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
  }, [key, reload, current]);
  // Do not retain answers on a stopped connection, replaced request or expired challenge.
  const expired = !!challenge && challengeExpired(challenge, now);
  useEffect(() => {
    if (!current || expired) {
      setAnswers({ username: '', password: '', secret: '', fields: {} });
      setUrl('');
      if (!current) setChallenge(undefined);
      else
        setChallenge((previous) =>
          previous
            ? { ...previous, username: '', message: '', banner: '', error: '', fields: [] }
            : undefined,
        );
      if (expired) close();
    }
  }, [current, expired]);
  async function run(name: 'submitVpnChallenge' | 'cancelVpnChallenge' | 'openVpnChallengeUrl') {
    if (action.current || !current || expired) return;
    action.current = true;
    setBusy(true);
    setError('');
    try {
      const payload =
        name === 'submitVpnChallenge' && challenge ? answerRequest(challenge, answers) : request;
      await command(name, payload);
      if (!mounted.current) return;
      if (name === 'cancelVpnChallenge') {
        close();
        await refresh();
        return;
      }
      if (name === 'submitVpnChallenge') {
        setAnswers({ username: '', password: '', secret: '', fields: {} });
        setChallenge(undefined);
        setSubmitted(true);
      }
      await refresh();
    } catch (e) {
      if (mounted.current) setError(e);
    } finally {
      action.current = false;
      if (mounted.current) setBusy(false);
    }
  }
  const disabled = loading || busy || submitted || !current || expired;
  function field(label: string, name: 'username' | 'password' | 'secret', type: 'text' | 'password') {
    return (
      <label className="field" key={name}>
        <span>{label}</span>
        <Input
          id={`vpn-auth-${name}`}
          name={`vpn-${name}`}
          className="text-input"
          type={type}
          value={answers[name]}
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          maxLength={limits.maxVpnCredentialBytes}
          disabled={disabled}
          onChange={(e) => setAnswers((old) => ({ ...old, [name]: e.target.value }))}
        />
      </label>
    );
  }
  return (
    <Modal
      title={t('title')}
      description={label}
      close={close}
      closeLabel={t('close')}
      className="vpn-auth-modal"
      footer={
        <>
          <Button
            id="vpn-auth-cancel"
            type="button"
            className="text-button danger"
            disabled={busy || !current || expired}
            onClick={() => void run('cancelVpnChallenge')}
          >
            {t('cancel')}
          </Button>
          <Button id="vpn-auth-close" type="button" className="button secondary" onClick={close}>
            {t('close')}
          </Button>
          {challenge?.kind === 'open-url' ? (
            <Button
              id="vpn-auth-browser"
              type="button"
              className="button primary"
              disabled={disabled || !url}
              onClick={() => void run('openVpnChallengeUrl')}
            >
              {t('openBrowser')}
            </Button>
          ) : (
            <Button
              id="vpn-auth-submit"
              type="submit"
              form="vpn-auth-form"
              className="button primary"
              disabled={disabled || !challenge || !canAnswer(challenge)}
            >
              {t('submit')}
            </Button>
          )}
        </>
      }
    >
      <div data-vpn-auth-key={key}>
        {error && (
          <InlineError className="desktop-inline-error" role="alert">
            {error}
          </InlineError>
        )}
        {!current ? (
          <p role="status">{t('unavailable')}</p>
        ) : expired ? (
          <p role="status">{t('expired')}</p>
        ) : loading || submitted ? (
          <LoadingState>{t('connecting')}</LoadingState>
        ) : null}
        {current && !expired && challenge && (
          <form
            id="vpn-auth-form"
            autoComplete="off"
            onSubmit={(e) => {
              e.preventDefault();
              if (canAnswer(challenge)) void run('submitVpnChallenge');
            }}
          >
            {challenge.banner && <p className="vpn-server-text">{challenge.banner}</p>}
            {challenge.message && <p className="vpn-server-text">{challenge.message}</p>}
            {challenge.error && (
              <InlineError className="vpn-server-text desktop-inline-error" role="alert">
                {challenge.error}
              </InlineError>
            )}
            {challenge.kind === 'credentials' && (
              <>
                {field(t('username'), 'username', 'text')}
                {field(t('password'), 'password', 'password')}
                {field(t('secret'), 'secret', challenge.echo ? 'text' : 'password')}
              </>
            )}
            {challenge.kind === 'secret' &&
              field(t('secret'), 'secret', challenge.echo ? 'text' : 'password')}
            {challenge.kind === 'form' &&
              canAnswer(challenge) &&
              challenge.fields.map((entry, index) => (
                <label className="field" key={entry.submissionKey}>
                  <span>{entry.label || entry.name || entry.submissionKey}</span>
                  {entry.kind === 'select' ? (
                    <Select
                      className="text-input"
                      id={`vpn-auth-field-${index}`}
                      data-vpn-field={entry.submissionKey}
                      disabled={disabled}
                      value={answers.fields[entry.submissionKey] ?? ''}
                      onChange={(e) =>
                        setAnswers((old) => ({
                          ...old,
                          fields: { ...old.fields, [entry.submissionKey]: e.target.value },
                        }))
                      }
                    >
                      {!entry.options.some((o) => o.value === answers.fields[entry.submissionKey]) && (
                        <option value="" disabled>
                          —
                        </option>
                      )}
                      {entry.options.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label || option.value}
                        </option>
                      ))}
                    </Select>
                  ) : (
                    <Input
                      className="text-input"
                      id={`vpn-auth-field-${index}`}
                      data-vpn-field={entry.submissionKey}
                      type={entry.kind === 'password' ? 'password' : 'text'}
                      value={answers.fields[entry.submissionKey] ?? ''}
                      autoComplete="off"
                      autoCapitalize="none"
                      spellCheck={false}
                      maxLength={limits.maxVpnCredentialBytes}
                      disabled={disabled}
                      onChange={(e) =>
                        setAnswers((old) => ({
                          ...old,
                          fields: { ...old.fields, [entry.submissionKey]: e.target.value },
                        }))
                      }
                    />
                  )}
                </label>
              ))}
            {challenge.kind === 'browser' ? (
              <p role="status">{t('browserUnsupported')}</p>
            ) : challenge.kind === 'open-url' ? (
              <>
                <p>{t('browserHint')}</p>
                {url && (
                  <p id="vpn-auth-url" className="vpn-server-text mono">
                    {url}
                  </p>
                )}
              </>
            ) : (
              !canAnswer(challenge) && <p role="status">{t('unsupported')}</p>
            )}
            {challenge.deadline > 0 && (
              <p id="vpn-auth-deadline" className="field-hint">
                {t('expires')}: {Math.max(0, challenge.deadline - Math.floor(now / 1000))}{' '}
                {translate(language, 'common.seconds_short')}
              </p>
            )}
          </form>
        )}
        {error && current && !busy && !submitted && (
          <Button
            id="vpn-auth-reload"
            type="button"
            className="text-button"
            onClick={() => setReload((old) => old + 1)}
          >
            {t('reload')}
          </Button>
        )}
        <p className="field-hint">{t('closeHint')}</p>
      </div>
    </Modal>
  );
}
