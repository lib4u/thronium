import { resolveMessage } from './message';
import { createContext, Fragment, useContext, useState, useCallback, type ReactNode } from 'react';
import {
  languageCode,
  sourceLanguage,
  translateParts,
  translator,
  type Language,
  type MessageKey,
} from './index';
const LocaleContext = createContext<Language>(sourceLanguage);
export function LocaleProvider({ language, children }: { language: string; children: ReactNode }) {
  return <LocaleContext.Provider value={languageCode(language)}>{children}</LocaleContext.Provider>;
}
const useLanguage = () => useContext(LocaleContext);
export const useTranslation = () => translator(useLanguage());

// Store the error or message reference, then resolve it with the current locale.
// Changing language never replaces the form's draft or repeats the failed action.
export function useMessageState(language: string, fallback: (value: unknown) => string) {
  const [value, update] = useState<unknown>('');
  const set = useCallback((next: unknown) => update(() => next), []);
  return [resolveMessage(language, value, fallback), set] as const;
}

export function Message({
  language,
  id,
  values,
}: {
  language: string;
  id: MessageKey;
  values: Readonly<Record<string, ReactNode>>;
}) {
  return (
    <>
      {translateParts(language, id, values).map((part, index) => (
        <Fragment key={index}>{part}</Fragment>
      ))}
    </>
  );
}
