import { limits } from '../limits.ts';
import { catalogs, languages, sourceLanguage, type Language, type MessageKey } from './generated/catalogs.ts';
export type { Language, MessageKey } from './generated/catalogs.ts';
export { languages, sourceLanguage } from './generated/catalogs.ts';
export type MessageParams = Readonly<Record<string, string | number>>;
const has = (object: object, key: string) => Object.prototype.hasOwnProperty.call(object, key);
const isLanguage = (language: string): language is Language => has(catalogs, language);
/** A supported language; anything else falls back to the source language. */
export const languageCode = (language: string): Language =>
  isLanguage(language) ? language : sourceLanguage;
export const locale = (language: string): string =>
  languages.find((entry) => entry.code === languageCode(language))?.locale ?? sourceLanguage;
export const languageName = (language: string): string =>
  languages.find((entry) => entry.code === language)?.name ?? language;
/** The language after `language` in the manifest order, wrapping around. */
export const nextLanguage = (language: string): Language => {
  const index = languages.findIndex((entry) => entry.code === languageCode(language));
  return languages[(index + 1) % languages.length].code;
};
export const isMessageKey = (key: string): key is MessageKey => has(catalogs[sourceLanguage], key);

const byteUnits = ['common.unit_b', 'common.unit_kib', 'common.unit_mib', 'common.unit_gib'] as const;
/** An engine limit a catalog message names as a placeholder, such as `{maxChainHops}`. */
function limitText(language: string, name: string): string | undefined {
  let value: unknown = has(limits, name) ? limits[name as keyof typeof limits] : undefined;
  if (typeof value !== 'number') return undefined;
  let unit = 0;
  if (name.endsWith('Bytes'))
    while (unit < byteUnits.length - 1 && value >= 1024 && value % 1024 === 0) {
      value /= 1024;
      unit += 1;
    }
  // Ports and MTUs are identifiers, written without digit grouping.
  const grouping = !/Port|Mtu/.test(name);
  const text = new Intl.NumberFormat(locale(language), { useGrouping: grouping }).format(value as number);
  return name.endsWith('Bytes') ? `${text} ${translate(language, byteUnits[unit])}` : text;
}
/** The catalog text; placeholders come from `params`, then from engine limits. */
export function translate(language: string, key: MessageKey, params: MessageParams = {}): string {
  const text = catalogs[languageCode(language)][key];
  return text.replace(
    /\{(\w+)\}/g,
    (placeholder, name: string) =>
      (has(params, name) ? String(params[name]) : limitText(language, name)) ?? placeholder,
  );
}
// Splits a message around its placeholders so callers can place rich values
// (for example emphasized text) without gluing sentence fragments together.
export function translateParts<T>(
  language: string,
  key: MessageKey,
  values: Readonly<Record<string, T>>,
): (string | T)[] {
  return translate(language, key)
    .split(/(\{\w+\})/)
    .filter(Boolean)
    .map((part) => {
      const name = /^\{(\w+)\}$/.exec(part)?.[1];
      return name !== undefined && Object.prototype.hasOwnProperty.call(values, name) ? values[name] : part;
    });
}
export const translator = (language: string) => (key: MessageKey, params?: MessageParams) =>
  translate(language, key, params);
export function translateOptional(language: string, key?: MessageKey): string | undefined {
  return key === undefined ? undefined : translate(language, key);
}

export type PluralKey = MessageKey extends infer K ? (K extends `${infer Base}_one` ? Base : never) : never;
export function plural(language: string, key: PluralKey, count: number): string {
  const category = new Intl.PluralRules(locale(language)).select(count);
  const candidate = `${key}_${category}`;
  const resolved = isMessageKey(candidate) ? candidate : (`${key}_other` as MessageKey);
  return translate(language, resolved, { count: new Intl.NumberFormat(locale(language)).format(count) });
}
