import { isMessageKey, translate, type MessageKey, type MessageParams } from './index.ts';
export type MessageRef = { kind: 'message'; key: MessageKey; params?: MessageParams };
export const messageRef = (key: MessageKey, params?: MessageParams): MessageRef => ({
  kind: 'message',
  key,
  params,
});
/** The catalog text of a registered error code (`errors.<code>`), when one exists. */
export function catalogError(language: string, code: string): string | undefined {
  const key = `errors.${code}`;
  return isMessageKey(key) ? translate(language, key) : undefined;
}
export class LocalizedError extends Error {
  readonly key: MessageKey;
  readonly params?: MessageParams;
  constructor(key: MessageKey, params?: MessageParams) {
    super(key);
    this.name = 'LocalizedError';
    this.key = key;
    this.params = params;
  }
}
export function resolveMessage(
  language: string,
  value: unknown,
  fallback: (value: unknown) => string,
): string {
  if (value === '' || value === undefined || value === null) return '';
  if (value instanceof LocalizedError) return translate(language, value.key, value.params);
  if (
    typeof value === 'object' &&
    'kind' in value &&
    value.kind === 'message' &&
    'key' in value &&
    typeof value.key === 'string' &&
    isMessageKey(value.key)
  ) {
    const message = value as MessageRef;
    return translate(language, message.key, message.params);
  }
  return fallback(value);
}
