// The always-on quick auto-select: its identity, default settings and the
// configurator sections. Field lists come from the profile schema, so nothing
// about which settings exist is duplicated here.
import type * as Wire from '../shared/api/generated/commands';
import { locale, translate, type Language } from '../shared/i18n/index.ts';
import { definitions, sections, type Config, type Section } from '../profiles/schema.ts';
import { defaults } from '../shared/api/generated/defaults.ts';

export const AUTO_SELECT_ID = 'auto-select';

export const autoSelectWords = {
  title: 'library.auto_select_title',
  hint: 'library.auto_select_hint',
  configure: 'library.auto_select_configure',
  dialogTitle: 'library.auto_select_dialog_title',
  dialogDescription: 'library.auto_select_dialog_description',
  recommended: 'library.auto_select_recommended',
  unavailable: 'library.auto_select_unavailable_hint',
  source: 'library.auto_select_source',
  sourceHint: 'library.auto_select_source_hint',
  sourceDeleted: 'library.auto_select_source_deleted',
  allGroups: 'library.all_groups_f7d603c',
  failover: 'library.auto_select_failover',
  failoverHint: 'library.auto_select_failover_hint',
  remember: 'library.auto_select_remember',
  interval: 'library.auto_select_check_interval',
  info: 'library.auto_select_connection_info',
  advanced: 'library.auto_select_advanced',
  reset: 'library.auto_select_reset',
  checking: 'library.auto_select_checking',
  searching: 'connection.auto_select_searching',
  save: 'common.save',
  cancel: 'common.cancel_bf4c449',
} as const;

const definition = definitions.find((d) => d.id === 'autoselector')!;

/** Defaults come from the shared profile schema used by all profile editors. */
/** The quick pool's health settings as a new library has them (engine default). */
export const defaultAutoSelectConfig: Config = structuredClone(
  defaults.preferences.autoSelect.config,
) as Config;

/** Shared advanced fields, excluding the two basic duration controls. */
export function advancedSections(config: Config): Section[] {
  return sections(definition, config)
    .filter((s) => s.id === 'health' || s.id === 'balance')
    .map((section) => ({
      ...section,
      fields: section.fields
        .filter((field) => !['interval', 'reuse_ttl'].includes(field.path))
        .map((field) =>
          field.path === 'url' || field.path === 'connectivity_url'
            ? { ...field, wide: true }
            : field.path === 'timeout'
              ? { ...field, hint: 'library.auto_select_timeout_hint' as const }
              : field.path === 'tolerance' || field.path === 'dial_retries'
                ? { ...field, min: 1 }
                : field,
        ),
    }));
}
export const configSections = advancedSections;

type DurationPreset = { value: string; amount: number; unit: 'second' | 'minute' | 'hour' };
export const reuseTtlPresets: readonly DurationPreset[] = [
  { value: '0s', amount: 0, unit: 'second' },
  { value: '10m', amount: 10, unit: 'minute' },
  { value: '30m', amount: 30, unit: 'minute' },
  { value: '1h', amount: 1, unit: 'hour' },
  { value: '3h', amount: 3, unit: 'hour' },
  { value: '24h', amount: 24, unit: 'hour' },
];
export const intervalPresets: readonly DurationPreset[] = [
  { value: '30s', amount: 30, unit: 'second' },
  { value: '1m', amount: 1, unit: 'minute' },
  { value: '120s', amount: 2, unit: 'minute' },
  { value: '5m', amount: 5, unit: 'minute' },
  { value: '10m', amount: 10, unit: 'minute' },
];

function durationMs(value: string): number | null {
  let end = 0;
  let total = 0;
  const scale: Record<string, number> = { ms: 1, s: 1000, m: 60000, h: 3600000 };
  for (const match of value.matchAll(/(\d+(?:\.\d+)?)(ms|s|m|h)/g)) {
    if (match.index !== end) return null;
    end += match[0].length;
    total += Number(match[1]) * scale[match[2]];
  }
  return end > 0 && end === value.length && Number.isFinite(total) ? total : null;
}

/** Match equivalent durations while keeping the saved spelling until edited. */
export function durationOptions(presets: readonly DurationPreset[], saved: string, language: Language) {
  const duration = durationMs(saved);
  let matched = false;
  const options = presets.map((preset) => {
    const same = duration !== null && durationMs(preset.value) === duration;
    matched ||= same;
    return {
      value: same ? saved : preset.value,
      label:
        preset.amount === 0
          ? translate(language, 'library.auto_select_no_memory')
          : new Intl.NumberFormat(locale(language), {
              style: 'unit',
              unit: preset.unit,
              unitDisplay: 'long',
            }).format(preset.amount),
    };
  });
  if (!matched)
    options.push({
      value: saved,
      label: translate(language, 'library.auto_select_other_duration', { value: saved }),
    });
  return options;
}

export function autoSelectHint(language: Language, failover: boolean): string {
  return translate(language, failover ? 'library.auto_select_hint' : 'library.auto_select_hint_connect_only');
}

export function editableQuickConfig(saved: Config): Config {
  const config = { ...defaultAutoSelectConfig, ...structuredClone(saved) };
  // Legacy zero means Core's default, not disabled retries or zero tolerance.
  if (config.tolerance === 0) config.tolerance = 100;
  if (config.dial_retries === 0) config.dial_retries = 2;
  return config;
}

/** A display row for the virtual pool, so the connection card can show it. */
export function autoSelectSummary(language: Language): Wire.ProfileSummary {
  const name = translate(language, autoSelectWords.title);
  return {
    id: AUTO_SELECT_ID,
    name,
    // Virtual profile: it must not be assigned to a user-owned group.
    groupId: AUTO_SELECT_ID,
    kind: 'auto-selector',
    protocol: name,
    address: '',
    favorite: false,
    poolEligible: false,
    vpn: false,
  };
}
