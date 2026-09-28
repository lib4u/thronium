import { translate, isMessageKey, type Language } from '../shared/i18n/index.ts';
import { label } from '../profiles/schema';
import settingsCatalog from '../../contracts/settings.catalog.json';
import { settingsScopes, LegacyReviewData, messageKeys } from './LegacyReviewModel';
export function useLegacyReview({
  data,
  language,
  busy,
  changeScopes,
  chooseResource,
  translateError,
}: {
  data: LegacyReviewData;
  language: Language;
  busy: boolean;
  changeScopes(scopes: LegacyReviewData['scopes']): void;
  chooseResource(id: string): void;
  translateError(e: unknown): string;
}) {
  const t = (key: keyof typeof messageKeys) => label(messageKeys[key], language);
  const chosenSettings = data.scopes.settings || {};
  const hasSettings = settingsScopes.some((group) => chosenSettings[group]);
  const fieldLabel = (id: string) => {
    if (id === 'xray_geoip_url_history') return t('historyGeoip');
    if (id === 'xray_geosite_url_history') return t('historyGeosite');
    const field = settingsCatalog.find((field) => field.id === id);
    return field && isMessageKey(field.label) ? translate(language, field.label) : id;
  };
  const vpnChoiceNeeded =
    data.scopes.profiles &&
    (data.vpnBindingCount || 0) > 0 &&
    (!data.scopes.vpnBindings || data.scopes.vpnBindings === 'require-choice');
  const selectorChoiceNeeded =
    data.scopes.profiles && (data.autoSelectorCount || 0) > 0 && data.scopes.autoSelectors !== 'last-built';
  return {
    busy,
    changeScopes,
    chooseResource,
    chosenSettings,
    data,
    fieldLabel,
    hasSettings,
    language,
    selectorChoiceNeeded,
    t,
    translateError,
    vpnChoiceNeeded,
  };
}
