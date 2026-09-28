import { useMessageState } from '../shared/i18n/react';
import { Input, Select } from '../shared/ui/controls';
import { translate, type Language } from '../shared/i18n/index.ts';
import type * as Wire from '../shared/api/generated/commands';
import { useEffect, useState, type InputHTMLAttributes } from 'react';
import { command } from '../api';

type Kind = 'geoip' | 'geosite';
type Sources = Wire.GeodataAssetSources;
type Props = {
  kind: Kind;
  label: string;
  value: string;
  language: Language;
  version: number;
  inputProps: InputHTMLAttributes<HTMLInputElement> & { id: string };
  change(value: string): void;
  translateError(e: unknown): string;
  invalid: boolean;
};
export default function GeoSourceInput({
  kind,
  label,
  value,
  language,
  version,
  inputProps,
  change,
  translateError,
  invalid,
}: Props) {
  const [sources, setSources] = useState<Sources>(),
    [error, setError] = useMessageState(language, translateError);
  useEffect(() => {
    let active = true;
    void command('xrayGeodataSources')
      .then((value) => {
        if (active) {
          setSources(value);
          setError('');
        }
      })
      .catch((error) => {
        if (active) setError(error);
      });
    return () => {
      active = false;
    };
  }, [version]);
  return (
    <div className="feature-field">
      <label htmlFor={inputProps.id}>{label}</label>
      <Input
        {...inputProps}
        className="text-input"
        type="text"
        autoComplete="off"
        spellCheck={false}
        value={value}
        onChange={(e) => change(e.target.value)}
      />
      <Select
        className="text-input"
        data-geo-source={kind}
        aria-label={translate(language, 'settings.choose_source_28c6bc8') + label}
        disabled={inputProps.disabled || !sources}
        value=""
        onChange={(e) => {
          if (e.target.value) change(e.target.value);
        }}
      >
        <option value="" disabled>
          {translate(language, 'settings.choose_a_source_or_recent_url_441d526')}
        </option>
        <optgroup label={translate(language, 'settings.included_sources_6cc9f26')}>
          {sources?.providers.map((provider) => (
            <option key={provider.name} value={provider[kind]} title={provider[kind]}>
              {provider.name}
            </option>
          ))}
        </optgroup>
        {!!sources?.history[kind].length && (
          <optgroup label={translate(language, 'settings.recent_urls_26becb5')}>
            {sources.history[kind].map((url) => (
              <option key={url} value={url}>
                {url}
              </option>
            ))}
          </optgroup>
        )}
      </Select>
      <small className="setting-description">
        {translate(language, 'settings.the_last_five_custom_urls_used_for_downloads_are_073b103')}
      </small>
      {(error || invalid) && (
        <small className="desktop-inline-error">
          {error || translate(language, 'settings.check_this_value_fd0a171')}
        </small>
      )}
    </div>
  );
}
