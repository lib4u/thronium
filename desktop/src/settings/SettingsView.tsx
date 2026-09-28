import { SearchField } from '../shared/ui/controls';
import { Button } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import { Icon } from '../ui';
import BackupPanel from '../backups/Panel';
import OtpPanel from '../otp/Panel';
import RouteSettings from './RouteSettings';
import TestActions from './TestActions';
import ExtraActions from './ExtraActions';
import StorageLocation from './StorageLocation';
import GroupsDialog from '../groups/GroupsDialog';
import SubscriptionDialog from '../groups/SubscriptionDialog';
import UpdatesDialog from '../groups/UpdatesDialog';
import './Settings.css';
import { groupName } from '../groups/groupModel';
import { sections } from './SettingsCatalog';
import type { useSettingsController } from './useSettingsController';
import SettingsSearchResults from './SettingsSearchResults';
import SettingsForm from './SettingsForm';
export default function SettingsView({
  controller,
}: {
  controller: ReturnType<typeof useSettingsController>;
}) {
  const {
    active,
    backupRestored,
    busy,
    changed,
    dialogs,
    dnsNavigated,
    dnsTarget,
    dnsVisited,
    drafts,
    group,
    jobs,
    openSection,
    query,
    search,
    sec,
    sectionFields,
    changeSearch,
    snapshot,
    subscription,
    translateError,
  } = controller;
  return (
    <div
      className="settings-page"
      data-navigation-locked={
        busy || Object.values(drafts).some((values) => Object.keys(values).length > 0) || undefined
      }
    >
      <div className="page-heading">
        <div>
          <h1>{translate(snapshot.preferences.language, 'settings.settings_118c0c9')}</h1>
          <p className="subtitle">
            {translate(
              snapshot.preferences.language,
              'settings.connection_core_and_application_preferences_66b3674',
            )}
          </p>
        </div>
      </div>
      <SearchField
        className="settings-search"
        id="settings-search"
        placeholder={translate(
          snapshot.preferences.language,
          'settings.find_a_setting_for_example_dns_or_mtu_0d2e6c4',
        )}
        aria-label={translate(snapshot.preferences.language, 'settings.search_settings_f67a880')}
        value={search}
        onChange={(e) => changeSearch(e.target.value)}
      />
      <div className="settings-workbench">
        <nav
          className="settings-sections"
          aria-label={translate(snapshot.preferences.language, 'settings.settings_categories_4a0c07c')}
        >
          {sections.map((s) => (
            <Button
              key={s[0]}
              data-settings-section={s[0]}
              className={active === s[0] ? 'active' : ''}
              aria-current={active === s[0] ? 'page' : undefined}
              onClick={() => {
                openSection(s[0]);
              }}
            >
              <Icon name={s[1]} />
              <span>{translate(snapshot.preferences.language, s[2])}</span>
              {Object.keys(drafts[s[0]] ?? {}).length > 0 && <i className="settings-draft-dot" />}
            </Button>
          ))}
        </nav>
        <div id="settings-content">
          {query ? (
            <SettingsSearchResults controller={controller} />
          ) : (
            <>
              {active !== 'backup' && active !== 'otp' && (
                <section className="feature-panel settings-category">
                  <div className="feature-panel-head">
                    <div>
                      <h2>{translate(snapshot.preferences.language, sec[2])}</h2>
                      <p>{translate(snapshot.preferences.language, sec[3])}</p>
                    </div>
                  </div>
                  {!!sectionFields.length && <SettingsForm controller={controller} />}
                  {['logging', 'system'].includes(active) && (
                    <ExtraActions
                      key={active}
                      section={active}
                      language={snapshot.preferences.language}
                      translateError={translateError}
                    />
                  )}
                  {active === 'system' && (
                    <StorageLocation
                      language={snapshot.preferences.language}
                      sealing={snapshot.sealing}
                      translateError={translateError}
                    />
                  )}
                  {active === 'testing' && (
                    <TestActions snapshot={snapshot} translateError={translateError} />
                  )}
                  {active === 'subscriptions' && (
                    <div className="settings-subscriptions">
                      {snapshot.groups
                        .filter((g) => g.subscribed)
                        .map((g) => (
                          <Button
                            className="settings-subscription"
                            key={g.id}
                            onClick={() => dialogs.editGroup(g.id)}
                          >
                            <Icon name="link" />
                            <span>
                              <strong>{groupName(g, snapshot.preferences.language)}</strong>
                              <small>
                                {translate(
                                  snapshot.preferences.language,
                                  'settings.subscription_parameters_fab8eb4',
                                )}
                              </small>
                            </span>
                            <Icon name="chevron-right" />
                          </Button>
                        ))}
                      <Button className="button secondary" onClick={dialogs.addGroup}>
                        {translate(snapshot.preferences.language, 'settings.manage_subscriptions_174bc0b')}
                      </Button>
                    </div>
                  )}
                </section>
              )}
              {active === 'backup' && (
                <BackupPanel snapshot={snapshot} changed={backupRestored} translateError={translateError} />
              )}
              {active === 'otp' && (
                <OtpPanel language={snapshot.preferences.language} translateError={translateError} />
              )}
            </>
          )}
          {dnsVisited && (
            <div hidden={active !== 'dns' || !!query}>
              <RouteSettings
                requested={dnsTarget}
                navigated={dnsNavigated}
                snapshot={snapshot}
                changed={changed}
                translateError={translateError}
              />
            </div>
          )}
        </div>
      </div>
      {group !== undefined && (
        <GroupsDialog
          snapshot={snapshot}
          update={dialogs.updateSubscription}
          updates={dialogs.showJobs}
          initialGroupId={group || undefined}
          initialAction={group ? 'edit' : undefined}
          close={dialogs.closeGroups}
          changed={changed}
          translateError={translateError}
        />
      )}
      {subscription && snapshot.groups.some((g) => g.id === subscription) && (
        <SubscriptionDialog
          group={snapshot.groups.find((g) => g.id === subscription)!}
          language={snapshot.preferences.language}
          changed={changed}
          close={dialogs.closeSubscription}
          translateError={translateError}
        />
      )}
      {jobs && (
        <UpdatesDialog
          snapshot={snapshot}
          changed={changed}
          close={dialogs.closeJobs}
          review={dialogs.updateSubscription}
          translateError={translateError}
        />
      )}
    </div>
  );
}
