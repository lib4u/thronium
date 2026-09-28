import { Select, Field } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import { LegacyReviewData } from './LegacyReviewModel';
import type { useLegacyReview } from './useLegacyReview';
import './LegacyResources.css';
export default function LegacyVpnReview({ controller }: { controller: ReturnType<typeof useLegacyReview> }) {
  const { busy, changeScopes, data, language, t } = controller;

  return (
    <section id="legacy-vpn-bindings-review">
      <Field className="feature-field" label={t('vpnBindingChoice')}>
        <Select
          className="text-input legacy-review-choice"
          id="legacy-vpn-bindings-choice"
          disabled={busy}
          value={data.scopes.vpnBindings || 'require-choice'}
          onChange={(e) =>
            changeScopes({
              ...data.scopes,
              vpnBindings: e.target.value as LegacyReviewData['scopes']['vpnBindings'],
            })
          }
        >
          <option value="require-choice">{t('vpnBindingUnchosen')}</option>
          <option value="automatic">{t('vpnBindingAuto')}</option>
          {data.scopes.vpnBindings === 'auto-live' && (
            <option value="auto-live">{t('vpnBindingAfterPrompt')}</option>
          )}
          <option value="manual">{t('vpnBindingManual')}</option>
        </Select>
      </Field>
      <p className="field-hint" id="legacy-vpn-bindings-hint">
        {t(data.scopes.vpnBindings === 'manual' ? 'vpnBindingManualHint' : 'vpnBindingHint')}
      </p>
      {(data.vpnBindings || []).length > 0 && (
        <ul className="import-warnings" id="legacy-vpn-bindings-list">
          {data.vpnBindings!.slice(0, 50).map((row) => (
            <li key={row.sourceId}>
              {row.name} →{' '}
              {row.otpName || translate(language, 'backups.otp_entry_number', { id: row.otpSourceId })}
              {row.mode && (
                <small>
                  {' '}
                  — {t(row.mode === 'auto-start' ? 'vpnBindingBeforeStart' : 'vpnBindingAfterPrompt')}
                </small>
              )}
              {!row.manualAllowed && <small> — {t('vpnBindingManualUnavailable')}</small>}
            </li>
          ))}
        </ul>
      )}
      <p id="legacy-vpn-bindings-count">
        {t('vpnBindingsPlanned')}: {data.vpnBindingsPlanned || 0}
      </p>
    </section>
  );
}
