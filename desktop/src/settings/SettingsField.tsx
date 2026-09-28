import { Switch, Select, Textarea, Input, SecretField, Field as FormField } from '../shared/ui/controls';
import { languageName, translate, translateOptional } from '../shared/i18n/index.ts';
import { formatPercent } from '../shared/i18n/format.ts';
import GeoSourceInput from './GeoSourceInput';
import { BASE_FONT_SIZE, FONT_SIZE_PRESETS, Field, inputId, options } from './SettingsCatalog';
import type { useSettingsController } from './useSettingsController';
import { usesTestUrl } from '../probes/messages';
export default function SettingsField({
  f,
  controller,
}: {
  f: Field;
  controller: Pick<
    ReturnType<typeof useSettingsController>,
    | 'active'
    | 'assetBusy'
    | 'base'
    | 'busy'
    | 'conflict'
    | 'drafts'
    | 'edit'
    | 'fieldErrors'
    | 'fieldValue'
    | 'geoSourcesVersion'
    | 'pingMethod'
    | 'runtimeLocked'
    | 'snapshot'
    | 'translateError'
  >;
}) {
  const {
    active,
    assetBusy,
    base,
    busy,
    conflict,
    drafts,
    edit,
    fieldErrors,
    fieldValue,
    geoSourcesVersion,
    pingMethod,
    runtimeLocked,
    snapshot,
    translateError,
  } = controller;

  if (f.id === 'test_url' && !usesTestUrl(pingMethod)) return null;
  const id = inputId(f),
    value = fieldValue(f),
    label = translate(snapshot.preferences.language, f.label),
    disabled =
      busy ||
      !base ||
      (assetBusy && ['xray_geoip_url', 'xray_geosite_url'].includes(f.id)) ||
      (!!f.dependsOn &&
        (f.dependsValue !== undefined
          ? (drafts[active]?.[f.dependsOn] ?? base?.[f.dependsOn]) !== f.dependsValue
          : !(drafts[active]?.[f.dependsOn] ?? base?.[f.dependsOn]))) ||
      (!!f.disabledWhen &&
        f.disabledWhen.values.includes(
          drafts[active]?.[f.disabledWhen.field] ?? base?.[f.disabledWhen.field],
        )) ||
      runtimeLocked;
  const props = {
    id,
    'data-setting': f.id,
    'aria-label': label,
    'aria-invalid': fieldErrors.has(f.id) || undefined,
    'data-conflict': (conflict?.section === active && conflict.fields.includes(f.id)) || undefined,
    disabled,
  };
  if (['xray_geoip_url', 'xray_geosite_url'].includes(f.id))
    return (
      <GeoSourceInput
        key={f.id}
        kind={f.id === 'xray_geoip_url' ? 'geoip' : 'geosite'}
        label={label}
        value={String(value)}
        language={snapshot.preferences.language}
        version={geoSourcesVersion}
        inputProps={props}
        change={(value) => edit(f, value)}
        translateError={translateError}
        invalid={fieldErrors.has(f.id)}
      />
    );
  if (f.kind === 'bool')
    return (
      <label className="setting-toggle" key={f.id}>
        <span>
          {label}
          {f.hint && (
            <small className="setting-description">{translate(snapshot.preferences.language, f.hint)}</small>
          )}
        </span>
        <Switch
          {...props}
          role="switch"
          type="checkbox"
          checked={value === true}
          onChange={(e) => edit(f, e.target.checked)}
        />
      </label>
    );
  if (f.id === 'font_size')
    return (
      <FormField key={f.id} className="feature-field" label={label}>
        <Select
          {...props}
          className="text-input"
          value={String(value)}
          onChange={(e) => edit(f, e.target.value)}
        >
          {[...new Set([...FONT_SIZE_PRESETS, Number(value)])]
            .sort((a, b) => a - b)
            .map((size) => (
              <option key={size} value={size}>
                {formatPercent(Math.round((size / BASE_FONT_SIZE) * 100), snapshot.preferences.language)}
                {size === BASE_FONT_SIZE
                  ? translate(snapshot.preferences.language, 'settings.default_0e362f1')
                  : ''}
              </option>
            ))}
        </Select>
        <small className="setting-description">
          {translateOptional(snapshot.preferences.language, f.hint)}
        </small>
      </FormField>
    );
  return (
    <label key={f.id} className={`feature-field ${['list', 'json'].includes(f.kind) ? 'settings-wide' : ''}`}>
      <span>{label}</span>
      {f.options ? (
        <Select
          {...props}
          className="text-input"
          value={String(value)}
          onChange={(e) => edit(f, e.target.value)}
        >
          {f.options.map((o) => (
            <option
              key={o}
              value={o}
              disabled={
                f.id === 'connection_mode' &&
                ((o === 'tun' && !snapshot.tunSupported) ||
                  (o === 'system-proxy' && !snapshot.systemProxy.available))
              }
            >
              {f.id === 'singbox_mux_limits'
                ? o === 'default'
                  ? translate(snapshot.preferences.language, 'settings.from_connection_presets_6c3d95c')
                  : translate(snapshot.preferences.language, 'settings.limit_connections_6a6bf16')
                : f.group === 'singbox' && o === 'default'
                  ? translate(snapshot.preferences.language, 'settings.core_default_ef7d5ce')
                  : f.id === 'ping_method' && o === 'auto'
                    ? translate(snapshot.preferences.language, 'settings.auto_http_s_tcp_icmp_a455dac')
                    : f.id === 'xray_log_mask_address' && o === 'full'
                      ? translate(snapshot.preferences.language, 'settings.mask_the_entire_address_362b318')
                      : f.id === 'periodic_tests_kind' && (o === 'ip' || o === 'speed')
                        ? translate(
                            snapshot.preferences.language,
                            o === 'ip' ? 'settings.periodic_kind_ip' : 'settings.periodic_kind_speed',
                          )
                        : f.id === 'language'
                          ? languageName(String(o))
                          : translateOptional(snapshot.preferences.language, options[o]) ||
                            o ||
                            translate(snapshot.preferences.language, 'settings.default_4d4d367')}
            </option>
          ))}
        </Select>
      ) : ['list', 'json'].includes(f.kind) ? (
        <Textarea
          {...props}
          rows={f.kind === 'json' ? 5 : 3}
          className={`text-input ${f.kind === 'json' ? 'mono' : ''}`}
          spellCheck={false}
          value={String(value)}
          onChange={(e) => edit(f, e.target.value)}
        />
      ) : f.kind === 'secret' ? (
        <SecretField
          {...props}
          className="text-input"
          value={String(value)}
          placeholder={translate(snapshot.preferences.language, 'settings.default_4d4d367')}
          onChange={(e) => edit(f, e.target.value)}
        />
      ) : (
        <Input
          {...props}
          className="text-input"
          type={f.kind === 'number' ? 'number' : 'text'}
          inputMode={f.kind === 'number' ? 'numeric' : undefined}
          min={f.min}
          max={f.max}
          step={1}
          autoComplete="off"
          spellCheck={false}
          value={String(value)}
          placeholder={translate(snapshot.preferences.language, 'settings.default_4d4d367')}
          onChange={(e) => edit(f, e.target.value)}
        />
      )}{' '}
      {f.hint && (
        <small className="setting-description">{translate(snapshot.preferences.language, f.hint)}</small>
      )}
      {fieldErrors.has(f.id) && (
        <small className="desktop-inline-error">
          {translate(snapshot.preferences.language, 'settings.check_this_value_fd0a171')}
        </small>
      )}
    </label>
  );
}
