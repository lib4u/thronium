import SettingsField from './SettingsField';
import { Section } from '../shared/ui/controls';
import { FormActions, InlineError } from '../shared/ui/controls';
import { Button } from '../shared/ui/controls';
import { translate, translateOptional } from '../shared/i18n/index.ts';
import { platform } from '../shared/platform.ts';
import { Message } from '../shared/i18n/react';
import { Icon } from '../ui';
import { methodHint } from '../probes/messages';
import WarpGenerator from '../warp/Generator';
import GeoAssets from './GeoAssets';
import { Field, fields, subgroups, groups } from './SettingsCatalog';
import type { useSettingsController } from './useSettingsController';

/** The saveable fields of the open settings section, with conflict resolution and save controls. */
export default function SettingsForm({
  controller,
}: {
  controller: ReturnType<typeof useSettingsController>;
}) {
  const {
    active,
    assetBusyChanged,
    base,
    busy,
    conflict,
    dirty,
    discardDrafts,
    drafts,
    error,
    geoSourcesChanged,
    notice,
    openSection,
    openSetting,
    pingMethod,
    resolveConflict,
    runtimeLocked,
    save,
    saved,
    sectionFields,
    sectionGroups,
    snapshot,
    translateError,
    useWarp,
  } = controller;
  function control(f: Field) {
    return <SettingsField key={f.id} f={f} controller={controller} />;
  }
  return (
    <form
      id="settings-form"
      onSubmit={(e) => {
        e.preventDefault();
        void save();
      }}
      noValidate
    >
      {active === 'inbound' && (
        <p className="field-hint">
          {snapshot.systemProxy.active
            ? translate(snapshot.preferences.language, 'settings.system_proxy_is_active_7b2118f')
            : translate(snapshot.preferences.language, 'settings.system_proxy_is_inactive_d53f192')}
        </p>
      )}
      {active === 'tun' && (
        <p className="field-hint">
          {translate(
            snapshot.preferences.language,
            platform === 'windows'
              ? snapshot.tunSupported
                ? 'settings.windows_tun_runs_in_the_service'
                : 'settings.windows_tun_needs_the_service'
              : snapshot.tunSupported
                ? 'settings.linux_tun_requests_rights_through_a_system_dialo_72625c5'
                : 'settings.tun_integration_is_unavailable_on_this_platform_485475a',
          )}
        </p>
      )}
      {sectionGroups.map((group, i) => (
        <Section
          title={
            <>
              {active === 'appearance' && group === 'main'
                ? translate(snapshot.preferences.language, 'settings.appearance_d5f19b7')
                : translateOptional(snapshot.preferences.language, groups[group]) || group}
            </>
          }
          className="editor-card settings-card"
          key={active + group}
          id={subgroups(group).length ? 'settings-' + group : undefined}
          open={i === 0}
        >
          {subgroups(group).length ? (
            <>
              {subgroups(group).map((subgroup) => (
                <section
                  className="settings-subgroup"
                  key={subgroup}
                  aria-labelledby={group + '-group-' + subgroup}
                >
                  <h3 id={group + '-group-' + subgroup}>
                    {subgroup === 'main'
                      ? translate(snapshot.preferences.language, 'settings.logs_c8ae4cf')
                      : translateOptional(snapshot.preferences.language, groups[subgroup]) || subgroup}
                  </h3>
                  <div className="settings-field-grid">
                    {sectionFields.filter((f) => f.group === group && f.subgroup === subgroup).map(control)}
                  </div>
                  {group === 'xray' && subgroup === 'geodata' && (
                    <GeoAssets
                      geoip={String(drafts.core?.xray_geoip_url ?? saved.core?.xray_geoip_url ?? '')}
                      geosite={String(drafts.core?.xray_geosite_url ?? saved.core?.xray_geosite_url ?? '')}
                      language={snapshot.preferences.language}
                      disabled={busy || !base}
                      busyChanged={assetBusyChanged}
                      sourcesChanged={geoSourcesChanged}
                      translateError={translateError}
                    />
                  )}
                </section>
              ))}
              {group === 'singbox' && (
                <>
                  <p className="field-hint">
                    {translate(
                      snapshot.preferences.language,
                      'settings.tcp_and_mux_defaults_apply_to_supported_sing_box_aa66c7e',
                    )}
                  </p>
                  <div className="settings-related">
                    <Button
                      type="button"
                      className="text-button"
                      data-settings-link="presets"
                      onClick={() => openSetting('presets', 'setting-mux_default_on')}
                    >
                      {translate(snapshot.preferences.language, 'settings.open_connection_presets_986e1d1')}
                      <Icon name="chevron-right" />
                    </Button>
                    <Button
                      type="button"
                      className="text-button"
                      data-settings-link="dns"
                      onClick={() => openSection('dns')}
                    >
                      {translate(snapshot.preferences.language, 'settings.open_dns_settings_32f28e7')}
                      <Icon name="chevron-right" />
                    </Button>
                  </div>
                </>
              )}
              <p className="field-hint">
                {translate(
                  snapshot.preferences.language,
                  'settings.explicit_profile_settings_take_priority_complete_0e6e839',
                )}
              </p>
            </>
          ) : (
            <div className="settings-field-grid">
              {sectionFields.filter((f) => f.group === group).map(control)}
            </div>
          )}
          {group === 'warp' && (
            <WarpGenerator
              language={snapshot.preferences.language}
              disabled={busy || !base}
              translateError={translateError}
              useConfig={useWarp}
            />
          )}
          {group === 'ping' && (
            <p className="field-hint">{methodHint(pingMethod, snapshot.preferences.language)}</p>
          )}
        </Section>
      ))}
      {runtimeLocked && (
        <p className="field-hint">
          {translate(
            snapshot.preferences.language,
            'settings.disconnect_before_changing_these_settings_17d47ef',
          )}
        </p>
      )}
      {['core', 'presets', 'security', 'intercept', 'logging'].includes(active) && (
        <p className="field-hint">
          {translate(
            snapshot.preferences.language,
            'settings.core_parameters_apply_on_the_next_connection_91870ab',
          )}
        </p>
      )}
      {active === 'dns' && (
        <p className="field-hint">
          {translate(
            snapshot.preferences.language,
            'settings.server_tags_refer_to_the_active_routing_profile__8572658',
          )}
        </p>
      )}
      {active === 'presets' && (
        <p className="field-hint">
          {translate(
            snapshot.preferences.language,
            'settings.explicit_profile_values_take_priority_over_these_3776437',
          )}
        </p>
      )}
      {conflict?.section === active && (
        <div className="settings-conflict" role="alert">
          <p>
            <Message
              language={snapshot.preferences.language}
              id="settings.conflict_fields"
              values={{
                fields: (
                  <strong>
                    {conflict.fields
                      .map(
                        (id) =>
                          translateOptional(
                            snapshot.preferences.language,
                            fields.find((f) => f.id === id)?.label,
                          ) || id,
                      )
                      .join(', ')}
                  </strong>
                ),
              }}
            />
          </p>
          <FormActions className="feature-toolbar">
            <Button
              id="settings-conflict-current"
              type="button"
              className="button secondary"
              disabled={busy}
              onClick={() => void resolveConflict(false)}
            >
              {translate(snapshot.preferences.language, 'settings.use_saved_values_7442bcc')}
            </Button>
            <Button
              id="settings-conflict-mine"
              type="button"
              className="button primary"
              disabled={busy}
              onClick={() => void resolveConflict(true)}
            >
              {translate(snapshot.preferences.language, 'settings.save_my_values_cae7c09')}
            </Button>
          </FormActions>
        </div>
      )}
      {error && (
        <InlineError className="desktop-inline-error" role="alert">
          {error}
        </InlineError>
      )}
      <div className="settings-save">
        <span role="status">
          {notice ||
            (dirty
              ? translate(snapshot.preferences.language, 'settings.unsaved_changes_707bc44')
              : translate(
                  snapshot.preferences.language,
                  'settings.changes_are_saved_with_the_button_6221607',
                ))}
        </span>
        <Button type="button" className="text-button" disabled={busy} onClick={discardDrafts}>
          {translate(snapshot.preferences.language, 'settings.reset_changes_ce00db4')}
        </Button>
        <Button
          className="button primary"
          id="settings-save"
          disabled={busy || !base || !dirty || conflict?.section === active || runtimeLocked}
        >
          {busy
            ? translate(snapshot.preferences.language, 'settings.saving_65d31c1')
            : translate(snapshot.preferences.language, 'settings.save_settings_f1f5ec1')}
        </Button>
      </div>
    </form>
  );
}
