import { translate, type Language } from '../shared/i18n/index.ts';
import { limits } from '../shared/limits.ts';
// Xray encodes WebSocket and HTTPUpgrade early data in the path query.
export const wsPath = 'streamSettings.wsSettings.path';
export const httpUpgradePath = 'streamSettings.httpupgradeSettings.path';
export type EarlyDataTransport = 'ws' | 'httpupgrade';
export const wsBuffer = '$xrayWsEarlyData';
export const maxXrayEarlyData = limits.maxXrayEarlyData;
export type WsIssue = 'invalidPath' | 'ambiguousQuery' | 'invalidValue' | 'pathRequired';
type Parsed = {
  prefix: string;
  fragment: string;
  query: string | null;
  tokens: string[];
  index: number;
  value: number;
};
const decode = (value: string) =>
  value
    .replace(/\+/g, ' ')
    .replace(/%([\da-f]{2})/gi, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)));
function split(path: unknown): Parsed {
  if (path === undefined) path = '';
  // eslint-disable-next-line no-control-regex -- Reject literal control characters before parsing an imported URL path.
  if (typeof path !== 'string' || /[\u0000-\u001f\u007f]/.test(path) || /%(?![\da-f]{2})/i.test(path))
    throw Error('invalidPath');
  const hash = path.indexOf('#'),
    fragment = hash < 0 ? '' : path.slice(hash),
    head = hash < 0 ? path : path.slice(0, hash);
  const question = head.indexOf('?'),
    prefix = question < 0 ? head : head.slice(0, question),
    query = question < 0 ? null : head.slice(question + 1);
  // Edit relative WS paths only. Authority/scheme forms can make Go's URL
  // parser fail or use opaque URL semantics; keep those in the raw Path field.
  if (prefix.startsWith('//') || /^[^/]*:/.test(prefix)) throw Error('invalidPath');
  const tokens = query === null || query === '' ? [] : query.split('&');
  // Go's query parser rejects literal semicolons; do not rewrite a partially parsed query.
  if (query?.includes(';')) throw Error('ambiguousQuery');
  const indices = tokens.flatMap((token, index) => (decode(token.split('=', 1)[0]) === 'ed' ? [index] : []));
  if (indices.length > 1) throw Error('ambiguousQuery');
  const index = indices[0] ?? -1;
  let value = 0;
  if (index >= 0) {
    const token = tokens[index],
      equals = token.indexOf('='),
      text = equals < 0 ? '' : decode(token.slice(equals + 1));
    if (!/^\d+$/.test(text) || !Number.isSafeInteger(Number(text)) || Number(text) > maxXrayEarlyData)
      throw Error('invalidValue');
    value = Number(text);
  }
  return { prefix, fragment, query, tokens, index, value };
}
export function inspectWsEarlyData(path: unknown): { value: number | null; issue: WsIssue | null } {
  try {
    return { value: split(path).value, issue: null };
  } catch (error) {
    return { value: null, issue: (error as Error).message as WsIssue };
  }
}
export function editWsEarlyData(path: unknown, text: string): string | undefined {
  const trimmed = text.trim();
  if (
    trimmed !== '' &&
    (!/^\d+$/.test(trimmed) || !Number.isSafeInteger(Number(trimmed)) || Number(trimmed) > maxXrayEarlyData)
  )
    throw Error('invalidValue');
  const value = trimmed === '' ? 0 : Number(trimmed),
    parsed = split(path);
  if (value > 0 && parsed.prefix.trim() === '') throw Error('pathRequired');
  if (value === parsed.value && !(value === 0 && parsed.index >= 0)) return path as string | undefined;
  const tokens = [...parsed.tokens];
  if (value === 0) {
    if (parsed.index < 0) return path as string | undefined;
    tokens.splice(parsed.index, 1);
  } else if (parsed.index >= 0) tokens[parsed.index] = `ed=${value}`;
  else {
    const query = parsed.query ?? '';
    return (
      parsed.prefix +
      '?' +
      query +
      (query && !query.endsWith('&') ? '&' : '') +
      `ed=${value}` +
      parsed.fragment
    );
  }
  return parsed.prefix + (tokens.length ? '?' + tokens.join('&') : '') + parsed.fragment;
}
export function wsEarlyDataText(
  key: 'label' | 'hint' | WsIssue,
  language: Language,
  transport: EarlyDataTransport = 'ws',
): string {
  const messages = {
    label: 'profiles.websocket_early_data_bytes_471e808',
    hint: 'profiles.early_data_hint',
    invalidPath: 'profiles.correct_the_websocket_path_to_change_early_data_7caa517',
    ambiguousQuery: 'profiles.the_path_has_ambiguous_query_parameters_correct__01d2c32',
    invalidValue: 'profiles.early_data_invalid',
    pathRequired: 'profiles.enter_a_websocket_path_first_for_example_978f207',
  } as const;
  return translate(language, messages[key], {
    transport: transport === 'httpupgrade' ? 'HTTPUpgrade' : 'WebSocket',
  });
}
