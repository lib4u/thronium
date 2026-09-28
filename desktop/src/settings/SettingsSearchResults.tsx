import { Button } from '../shared/ui/controls';
import { translate, translateOptional } from '../shared/i18n/index.ts';
import { Icon } from '../ui';
import { sections, inputId } from './SettingsCatalog';
import type { useSettingsController } from './useSettingsController';

/** Settings, DNS objects and special pages matching the search query. */
export default function SettingsSearchResults({
  controller,
}: {
  controller: ReturnType<typeof useSettingsController>;
}) {
  const { dnsMatches, found, openDnsObject, openSetting, snapshot, specialMatches } = controller;
  return (
    <div className="settings-search-results">
      {found.map((f) => (
        <Button
          className=""
          key={f.id}
          data-settings-result={f.id}
          onClick={() => {
            openSetting(f.section, inputId(f));
          }}
        >
          <span>
            <strong>{translate(snapshot.preferences.language, f.label)}</strong>
            <small>
              {translateOptional(
                snapshot.preferences.language,
                sections.find((s) => s[0] === f.section)?.[2],
              )}
            </small>
          </span>
          <Icon name="chevron-right" />
        </Button>
      ))}
      {dnsMatches.map((f) => (
        <Button
          className=""
          key={'dns-' + f.path}
          data-settings-result={'dns_' + f.path}
          onClick={() => {
            openDnsObject('dns', f.path);
          }}
        >
          <span>
            <strong>{translate(snapshot.preferences.language, f.label)}</strong>
            <small>DNS</small>
          </span>
          <Icon name="chevron-right" />
        </Button>
      ))}
      {specialMatches.map((s) => (
        <Button
          className=""
          key={s[1]}
          onClick={() => {
            openDnsObject(s[0], s[1]);
          }}
        >
          <span>
            <strong>{translate(snapshot.preferences.language, s[2])}</strong>
          </span>
          <Icon name="chevron-right" />
        </Button>
      ))}
      {!found.length && !dnsMatches.length && !specialMatches.length && (
        <p className="resource-empty">
          {translate(snapshot.preferences.language, 'settings.no_matching_settings_b7528d7')}
        </p>
      )}
    </div>
  );
}
