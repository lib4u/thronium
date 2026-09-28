// Generated catalog imports; text belongs to desktop/locales.
import enCommon from '../../../../locales/en/common.json' with { type: 'json' };
import enConnection from '../../../../locales/en/connection.json' with { type: 'json' };
import enLibrary from '../../../../locales/en/library.json' with { type: 'json' };
import enProfiles from '../../../../locales/en/profiles.json' with { type: 'json' };
import enImports from '../../../../locales/en/imports.json' with { type: 'json' };
import enSubscriptions from '../../../../locales/en/subscriptions.json' with { type: 'json' };
import enRouting from '../../../../locales/en/routing.json' with { type: 'json' };
import enSettings from '../../../../locales/en/settings.json' with { type: 'json' };
import enDiagnostics from '../../../../locales/en/diagnostics.json' with { type: 'json' };
import enBackups from '../../../../locales/en/backups.json' with { type: 'json' };
import enOtp from '../../../../locales/en/otp.json' with { type: 'json' };
import enNative from '../../../../locales/en/native.json' with { type: 'json' };
import enErrors from '../../../../locales/en/errors.json' with { type: 'json' };
import ruCommon from '../../../../locales/ru/common.json' with { type: 'json' };
import ruConnection from '../../../../locales/ru/connection.json' with { type: 'json' };
import ruLibrary from '../../../../locales/ru/library.json' with { type: 'json' };
import ruProfiles from '../../../../locales/ru/profiles.json' with { type: 'json' };
import ruImports from '../../../../locales/ru/imports.json' with { type: 'json' };
import ruSubscriptions from '../../../../locales/ru/subscriptions.json' with { type: 'json' };
import ruRouting from '../../../../locales/ru/routing.json' with { type: 'json' };
import ruSettings from '../../../../locales/ru/settings.json' with { type: 'json' };
import ruDiagnostics from '../../../../locales/ru/diagnostics.json' with { type: 'json' };
import ruBackups from '../../../../locales/ru/backups.json' with { type: 'json' };
import ruOtp from '../../../../locales/ru/otp.json' with { type: 'json' };
import ruNative from '../../../../locales/ru/native.json' with { type: 'json' };
import ruErrors from '../../../../locales/ru/errors.json' with { type: 'json' };
function qualify<N extends string, T extends Record<string, string>>(namespace: N, values: T): { [K in keyof T as `${N}.${K & string}`]: T[K] } {
  return Object.fromEntries(Object.entries(values).map(([key, value]) => [`${namespace}.${key}`, value])) as { [K in keyof T as `${N}.${K & string}`]: T[K] };
}
const en = {...qualify('common', enCommon), ...qualify('connection', enConnection), ...qualify('library', enLibrary), ...qualify('profiles', enProfiles), ...qualify('imports', enImports), ...qualify('subscriptions', enSubscriptions), ...qualify('routing', enRouting), ...qualify('settings', enSettings), ...qualify('diagnostics', enDiagnostics), ...qualify('backups', enBackups), ...qualify('otp', enOtp), ...qualify('native', enNative), ...qualify('errors', enErrors)};
const ru = {...qualify('common', ruCommon), ...qualify('connection', ruConnection), ...qualify('library', ruLibrary), ...qualify('profiles', ruProfiles), ...qualify('imports', ruImports), ...qualify('subscriptions', ruSubscriptions), ...qualify('routing', ruRouting), ...qualify('settings', ruSettings), ...qualify('diagnostics', ruDiagnostics), ...qualify('backups', ruBackups), ...qualify('otp', ruOtp), ...qualify('native', ruNative), ...qualify('errors', ruErrors)};
export type MessageKey = keyof typeof en;
export type Catalog = Readonly<Record<MessageKey, string>>;
export const sourceLanguage = "en";
export const languages = [{"code":"en","locale":"en-US","name":"English","installer":"English"},{"code":"ru","locale":"ru-RU","name":"Русский","installer":"Russian"}] as const;
export type Language = (typeof languages)[number]['code'];
export const catalogs: Readonly<Record<Language, Catalog>> = { "en": en, "ru": ru };
