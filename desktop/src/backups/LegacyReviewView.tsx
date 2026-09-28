import LegacyResources from './LegacyResources';
import LegacySelectorReview from './LegacySelectorReview';
import LegacyVpnReview from './LegacyVpnReview';
import { InlineError } from '../shared/ui/controls';
import { Checkbox } from '../shared/ui/controls';
import { isVpnOtpError, vpnOtpError } from '../connection/vpnOtpMessages';
import { catalogError } from '../shared/i18n/message';
import { settingsScopes, messageKeys } from './LegacyReviewModel';
import type { useLegacyReview } from './useLegacyReview';
import './LegacyResources.css';
export default function LegacyReviewView({ controller }: { controller: ReturnType<typeof useLegacyReview> }) {
  const {
    busy,
    changeScopes,
    chosenSettings,
    data,
    fieldLabel,
    hasSettings,
    language,
    selectorChoiceNeeded,
    t,
    translateError,
    vpnChoiceNeeded,
  } = controller;
  return (
    <div id="legacy-import-review">
      <p id="legacy-import-source">
        {t('source')}: {t('profiles')} — {data.inventory.profiles}, {t('groups')} — {data.inventory.groups}.
      </p>
      <fieldset className="legacy-import-scopes" disabled={busy}>
        <legend>{t('chooseScopes')}</legend>
        <label className="import-toggle">
          <Checkbox
            type="checkbox"
            id="legacy-scope-profiles"
            checked={data.scopes.profiles}
            disabled={!data.inventory.parts.profiles}
            onChange={(e) => changeScopes({ ...data.scopes, profiles: e.target.checked })}
          />
          {t('profileScope')}
        </label>
        <label className="import-toggle">
          <Checkbox
            type="checkbox"
            id="legacy-scope-routes"
            checked={data.scopes.routes}
            disabled={!data.inventory.parts.routes}
            onChange={(e) => changeScopes({ ...data.scopes, routes: e.target.checked })}
          />
          {t('routeScope')}
        </label>
        <label className="import-toggle">
          <Checkbox
            type="checkbox"
            id="legacy-scope-otp"
            checked={!!data.scopes.otp}
            disabled={!data.inventory.parts.otp}
            onChange={(e) => changeScopes({ ...data.scopes, otp: e.target.checked })}
          />
          {t('otpScope')}
        </label>
        {settingsScopes.map((group) => (
          <label className="import-toggle" key={group}>
            <Checkbox
              type="checkbox"
              id={`legacy-scope-settings-${group}`}
              checked={!!chosenSettings[group]}
              disabled={!data.inventory.parts.settings}
              onChange={(e) =>
                changeScopes({ ...data.scopes, settings: { ...chosenSettings, [group]: e.target.checked } })
              }
            />
            {t(`settings_${group}`)}
          </label>
        ))}
        <label className="import-toggle">
          <Checkbox
            id="legacy-scope-icons"
            type="checkbox"
            checked={!!data.scopes.icons}
            disabled={!data.inventory.parts.icons}
            onChange={(e) => changeScopes({ ...data.scopes, icons: e.target.checked })}
          />
          {t('iconsScope')}
        </label>
      </fieldset>
      {data.scopes.profiles && (data.autoSelectorCount || 0) > 0 && (
        <LegacySelectorReview controller={controller} />
      )}
      {data.scopes.profiles && (data.vpnBindingCount || 0) > 0 && <LegacyVpnReview controller={controller} />}
      {data.scopes.profiles && <p>{t('scope')}</p>}
      {(data.scopes.profiles || data.scopes.routes) && (
        <p>{t(data.scopes.routes ? 'routeScopeHint' : 'network')}</p>
      )}
      {data.scopes.profiles && (data.externalCoreCount || 0) > 0 && (
        <p id="legacy-external-count">
          {t('externalPlanned')}: {data.externalCoreCount}
        </p>
      )}
      <LegacyResources controller={controller} />
      {data.scopes.routes && <p className="field-hint">{t('routeValidation')}</p>}
      {data.scopes.routes && data.routeCount > 0 && (
        <p id="legacy-route-count">
          {t('routePlanned')}: {data.routeCount}
        </p>
      )}
      {data.scopes.otp && (
        <>
          <p className="field-hint">{t('otpScopeHint')}</p>
          {(data.otpCount || 0) > 0 && (
            <p id="legacy-otp-count">
              {t('otpPlanned')}: {data.otpCount}
            </p>
          )}
        </>
      )}
      {data.scopes.icons && (
        <div id="legacy-icons-review">
          <p className="field-hint">{t('iconsHint')}</p>
          <p>
            {t('iconsPlanned')}: {data.iconCount || 0}
          </p>
        </div>
      )}
      {(data.trafficBuckets || 0) > 0 && (
        <p id="legacy-traffic-count">
          {t('trafficPlanned')}: {data.trafficBuckets}
        </p>
      )}
      {chosenSettings.network && (
        <p className="field-hint" id="legacy-network-hint">
          {t('networkImportHint')}
        </p>
      )}
      {chosenSettings.subscriptions && (
        <p className="field-hint" id="legacy-subscriptions-hint">
          {t('subscriptionImportHint')}
        </p>
      )}
      {chosenSettings.warp && (
        <p className="field-hint" id="legacy-warp-hint">
          {t('warpHint')}
        </p>
      )}
      {chosenSettings.geodata && (
        <p className="field-hint" id="legacy-geodata-hint">
          {t('geodataHint')}
        </p>
      )}
      {(chosenSettings.inbound ||
        chosenSettings.presets ||
        chosenSettings.intercept ||
        chosenSettings.tun ||
        chosenSettings.core) && (
        <p className="field-hint" id="legacy-runtime-hint">
          {t('runtimeImportHint')}
        </p>
      )}
      {chosenSettings.system && (
        <p className="field-hint" id="legacy-system-hint">
          {t('systemImportHint')}
        </p>
      )}
      {hasSettings && (
        <div id="legacy-settings-review">
          <p className="field-hint">{t('settingsScopeHint')}</p>
          <p id="legacy-settings-count">
            {t('settingsPlanned')}: {data.settingsCount || 0}
          </p>
          <ul id="legacy-settings-fields">
            {settingsScopes
              .filter((group) => chosenSettings[group])
              .flatMap((group) =>
                (data.settingsGroups?.[group]?.fields || []).map((id) => <li key={id}>{fieldLabel(id)}</li>),
              )}
          </ul>
        </div>
      )}
      {data.scopes.routes && data.requirements.length > 0 && (
        <div id="legacy-route-requirements">
          <p>{t('routeRequirements')}</p>
          <ul>
            {data.requirements.map((code) => (
              <li key={code}>{translateError(code)}</li>
            ))}
          </ul>
        </div>
      )}
      <p className="field-hint">{t('deferred')}</p>
      <dl className="desktop-details" id="legacy-import-deferred">
        {(
          [
            ['routing', 'routes'],
            ['settings', 'settings'],
            ['otp', 'otp'],
            ['icons', 'icons'],
          ] as const
        )
          .filter(
            ([, field]) =>
              (field !== 'routes' || !data.scopes.routes) &&
              (field !== 'otp' || !data.scopes.otp) &&
              (field !== 'icons' || !data.scopes.icons),
          )
          .map(([word, field]) => (
            <div key={field} className="legacy-review-row">
              <dt>
                {t(
                  word === 'settings'
                    ? hasSettings
                      ? 'remainingSettings'
                      : data.scopes.routes
                        ? 'settingsGeneral'
                        : word
                    : word,
                )}
              </dt>
              <dd>
                {field === 'settings' && hasSettings
                  ? (data.settingsDeferred ?? data.inventory.settings)
                  : data.inventory[field]}
              </dd>
            </div>
          ))}
      </dl>
      {!data.canApply && (
        <InlineError className="desktop-inline-error" id="legacy-import-blocked" role="alert">
          {t(
            !data.scopes.profiles &&
              !data.scopes.routes &&
              !data.scopes.otp &&
              !data.scopes.icons &&
              !hasSettings &&
              (data.inventory.parts.profiles ||
                data.inventory.parts.routes ||
                data.inventory.parts.otp ||
                data.inventory.parts.icons ||
                data.inventory.parts.settings)
              ? 'selectScope'
              : selectorChoiceNeeded
                ? 'legacy_selector_snapshot_choice_required'
                : vpnChoiceNeeded
                  ? 'legacy_vpn_bindings_choice_required'
                  : 'unsupported',
          )}
        </InlineError>
      )}
      {data.issues.length > 0 && (
        <>
          <p>{t('notes')}</p>
          <ul className="import-warnings" id="legacy-import-issues">
            {data.issues.slice(0, 50).map((issue, i) => (
              <li key={i}>
                <strong>
                  {(issue.entity === 'settings' && issue.name ? fieldLabel(issue.name) : issue.name) ||
                    `${t(issue.entity === 'profile' ? 'profile' : issue.entity === 'group' ? 'group' : issue.entity === 'route' ? 'route' : issue.entity === 'otp' ? 'otp' : 'database')}${issue.sourceId === null ? '' : ` #${issue.sourceId}`}`}
                </strong>
                :{' '}
                {isVpnOtpError(issue.code)
                  ? vpnOtpError(issue.code, language)
                  : !Object.prototype.hasOwnProperty.call(messageKeys, issue.code) &&
                      catalogError(language, issue.code)
                    ? catalogError(language, issue.code)
                    : t(
                        issue.code === 'legacy_import_no_profiles'
                          ? 'noProfiles'
                          : ['legacy_import_incompatible', 'backup_too_large'].includes(issue.code)
                            ? 'incompatible'
                            : Object.prototype.hasOwnProperty.call(messageKeys, issue.code)
                              ? (issue.code as keyof typeof messageKeys)
                              : 'conversion',
                      )}
              </li>
            ))}
          </ul>
          {data.issues.length > 50 && (
            <p className="field-hint">
              {t('more')}: {data.issues.length - 50}
            </p>
          )}
        </>
      )}
    </div>
  );
}
