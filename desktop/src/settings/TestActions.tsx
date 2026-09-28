import { FormActions, InlineError } from '../shared/ui/controls';
import { Button } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import type { Snapshot } from '../api';
import { context, countryLabel, summary } from './testActionsModel.ts';
import { useTestActions } from './useTestActions.ts';

export default function TestActions({
  snapshot,
  translateError,
  profileId,
  internet = true,
}: {
  snapshot: Snapshot;
  translateError(e: unknown): string;
  profileId?: string;
  internet?: boolean;
}) {
  const language = snapshot.preferences.language;
  const selected = profileId || snapshot.selected;
  const profile = snapshot.profiles.find((p) => p.id === selected);
  const supported = profile?.ipSpeedSupported === true;
  const { busy, error, result, run, cancel } = useTestActions(selected, language, translateError);
  return (
    <div className="settings-test-actions">
      <p className="field-hint">
        {translate(language, 'settings.tests_use_the_saved_server_vless_core_choice_and_c167d51')}
      </p>
      {profile && (
        <p className="field-hint" id="diagnostics-profile">
          {translate(language, 'settings.server_772c781')}: <strong>{profile.name}</strong>
        </p>
      )}
      {profile && !supported && (
        <p className="field-hint" id="diagnostics-unsupported">
          {translate(language, 'settings.ip_and_speed_tests_are_unavailable_for_this_serv_409abfe')}
        </p>
      )}
      {profile?.vpn && (
        <p className="field-hint">
          {translate(language, 'settings.openvpn_and_openconnect_tests_wait_for_vpn_readi_eaf1ba3')}
        </p>
      )}
      <FormActions className="feature-toolbar">
        {internet && (
          <Button
            type="button"
            id="diagnostics-internet"
            className="button secondary"
            disabled={!!busy}
            onClick={() => void run('testInternet')}
          >
            {translate(language, 'settings.check_internet_without_proxy_c7c22c5')}
          </Button>
        )}
        <Button
          type="button"
          id="diagnostics-ip"
          className="button secondary"
          disabled={!!busy || !supported || !snapshot.coreAvailable}
          onClick={() => void run('testIp')}
        >
          {translate(language, 'settings.check_ip_and_country_c9490f9')}
        </Button>
        <Button
          type="button"
          id="diagnostics-speed"
          className="button secondary"
          disabled={!!busy || !supported || !snapshot.coreAvailable}
          onClick={() => void run('testSpeed')}
        >
          {translate(language, 'settings.test_speed_38ae742')}
        </Button>
        {busy && (
          <Button type="button" id="diagnostics-cancel" className="text-button" onClick={() => void cancel()}>
            {translate(language, 'settings.stop_f399d23')}
          </Button>
        )}
      </FormActions>
      <p className="field-hint">
        {translate(language, 'settings.ip_and_country_are_determined_through_ip2locatio_dd951dd')}
      </p>
      {busy && (
        <p role="status" id="diagnostics-progress">
          {translate(language, 'settings.testing_d9a2935')}
        </p>
      )}
      {error && (
        <InlineError role="alert" className="desktop-inline-error">
          {error}
        </InlineError>
      )}
      {result && (
        <div role="status" id="settings-test-result">
          {result.ip ? (
            <dl className="desktop-details">
              <dt>{translate(language, 'settings.exit_ip_5992273')}</dt>
              <dd id="diagnostics-exit-ip">{result.ip}</dd>
              <dt>{translate(language, 'settings.country_b2a6dd4')}</dt>
              <dd id="diagnostics-country">
                {countryLabel(result, language)}
                {result.countryCode ? ` (${result.countryCode})` : ''}
              </dd>
            </dl>
          ) : (
            <p>{summary(result, language)}</p>
          )}
          {result.testedAt && (
            <p className="field-hint" id="diagnostics-context">
              {context(result, language)}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
