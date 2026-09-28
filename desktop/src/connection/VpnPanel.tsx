import { Button } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import type { Profile, VpnChallengeRequest, VpnStatus } from '../api';
import { vpnError, vpnText } from './vpnMessages';
import { vpnEndpointLabel } from './vpnAuth';
import VpnTunnelDetails from './VpnTunnelDetails';
import type { CredentialRequest } from './vpnCredentials';
import './vpnAuth.css';

export default function VpnPanel({
  status,
  profile,
  language,
  busy,
  open,
  openCredentials,
}: {
  status: VpnStatus;
  profile?: Profile;
  language: string;
  busy: boolean;
  open(request: VpnChallengeRequest): void;
  openCredentials(request: CredentialRequest): void;
}) {
  if (!status.endpoints.length && !status.error) return null;
  const t = (key: Parameters<typeof vpnText>[0]) => vpnText(key, language);
  return (
    <section className="vpn-endpoints" aria-label={t('endpoints')}>
      <h2>{t('endpoints')}</h2>
      {status.error && <p role="status">{vpnError(status.error, language)}</p>}
      {status.endpoints.map((endpoint) => (
        <article key={endpoint.tag} data-vpn-endpoint={endpoint.tag} data-vpn-state={endpoint.state}>
          <div>
            <strong>{vpnEndpointLabel(endpoint.tag, profile)}</strong>
            <small>{endpoint.protocol}</small>
          </div>
          <p role="status">
            {t(
              endpoint.state === 'auth-pending'
                ? 'pending'
                : endpoint.state === 'connected'
                  ? 'connected'
                  : endpoint.state === 'error'
                    ? 'error'
                    : endpoint.state === 'connecting'
                      ? 'connecting'
                      : 'unknown',
            )}
          </p>
          {endpoint.error && <p className="field-hint">{vpnError(endpoint.error, language)}</p>}
          {endpoint.tunnel && <VpnTunnelDetails tunnel={endpoint.tunnel} language={language} />}
          {endpoint.otp && (
            <p className="field-hint" data-vpn-otp-state={endpoint.otp.state} role="status">
              {endpoint.otp.error ? vpnError(endpoint.otp.error, language) : t(`otp_${endpoint.otp.state}`)}
            </p>
          )}
          {endpoint.authFailed && <p className="field-hint">{t('vpn_auth_failed')}</p>}
          {endpoint.state === 'error' && endpoint.authFailed && !endpoint.challengeId && status.sessionId && (
            <Button
              className="button secondary"
              data-vpn-credentials={endpoint.tag}
              disabled={busy}
              onClick={() => openCredentials({ sessionId: status.sessionId!, endpointTag: endpoint.tag })}
            >
              {translate(language, 'connection.retry_sign_in_4d30429')}
            </Button>
          )}
          {endpoint.challengeId && status.sessionId && (
            <Button
              className="button secondary"
              data-vpn-open={endpoint.tag}
              disabled={busy}
              onClick={() =>
                open({
                  sessionId: status.sessionId!,
                  endpointTag: endpoint.tag,
                  challengeId: endpoint.challengeId!,
                })
              }
            >
              {t('open')}
            </Button>
          )}
        </article>
      ))}
    </section>
  );
}
