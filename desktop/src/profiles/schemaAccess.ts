import type { Config, Field } from './schemaFields.ts';

// Reading, writing and text conversion of configuration values by JSON path.
export function get(config: unknown, path: string): unknown {
  // Display the known boolean representation produced by older URI imports.
  if (path === 'tls.tls_tricks.mixedcase_sni') {
    const tricks = get(config, 'tls.tls_tricks');
    if (typeof tricks === 'boolean') return tricks;
  }
  const value = path
    .split('.')
    .reduce<unknown>(
      (v, key) =>
        key === 'enabled' && typeof v === 'boolean'
          ? v
          : v !== null && typeof v === 'object' && Object.prototype.hasOwnProperty.call(v, key)
            ? (v as Config)[key]
            : undefined,
      config,
    );
  // Older imported profiles use an empty core SNI as a frozen Off switch.
  if (path === 'tls.spoof_enabled' && value === undefined && get(config, 'tls.spoof') === '') return false;
  return value;
}
export function set(config: Config, path: string, value: unknown): Config {
  if (path === 'tls.tls_tricks.mixedcase_sni') {
    const tricks = get(config, 'tls.tls_tricks');
    // A property on an array disappears in JSON. Leave malformed imported
    // values intact for correction in JSON instead of silently losing the edit.
    if (
      tricks !== undefined &&
      tricks !== null &&
      typeof tricks !== 'boolean' &&
      (typeof tricks !== 'object' || Array.isArray(tricks))
    )
      throw Error('invalid_field_value');
  }
  if (path.startsWith('tls_fragment.')) {
    const fragment = get(config, 'tls_fragment');
    if (
      fragment !== undefined &&
      (fragment === null || typeof fragment !== 'object' || Array.isArray(fragment))
    )
      throw Error('invalid_field_value');
  }
  const keys = path.split('.');
  if (keys.some((k) => ['__proto__', 'prototype', 'constructor'].includes(k)))
    throw Error('invalid_field_path');
  const root = structuredClone(config);
  let current = root;
  for (let i = 0; i < keys.length - 1; i++) {
    const key = keys[i];
    if (!current[key] || typeof current[key] !== 'object') current[key] = /^\d+$/.test(keys[i + 1]) ? [] : {};
    current = current[key] as Config;
  }
  if (value === undefined) delete current[keys[keys.length - 1]];
  else current[keys[keys.length - 1]] = value;
  // An empty custom object masks global inheritance. Remove it only after an
  // explicit field edit empties it; preserve every unknown sibling otherwise.
  if (path.startsWith('tls_fragment.') && Object.keys(current).length === 0) delete root.tls_fragment;
  // Default removes just this switch. Keep any unknown sibling properties.
  if (path === 'tls.tls_tricks.mixedcase_sni' && value === undefined && Object.keys(current).length === 0) {
    delete (root.tls as Config).tls_tricks;
  }
  // Only an explicit Default action releases the old empty-SNI Off sentinel.
  // A nonempty per-profile SNI keeps its normal priority over the preset.
  if (path === 'tls.spoof_enabled' && value === undefined) {
    if (current.spoof === '') delete current.spoof;
    if (current.spoof_method === '') delete current.spoof_method;
  }
  return root;
}
export function format(field: Field, value: unknown): string {
  if (value === undefined || value === null) return '';
  if (field.kind === 'json') return JSON.stringify(value, null, 2);
  if (Array.isArray(value) && ['list', 'numbers'].includes(field.kind)) return value.join('\n');
  if (typeof value === 'object') return JSON.stringify(value, null, 2);
  return String(value);
}
export function parse(field: Field, text: string): unknown {
  if (text === '' || (!text.trim() && !['text', 'secret'].includes(field.kind))) return undefined;
  if (field.kind === 'json') return JSON.parse(text);
  if (field.kind === 'bool') return text === 'true';
  if (field.kind === 'select') return field.options?.find((v) => String(v) === text) ?? text;
  if (field.kind === 'list')
    return text
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);
  if (field.kind === 'number') {
    const number = Number(text);
    if (
      !Number.isSafeInteger(number) ||
      number < (field.min ?? 0) ||
      number > (field.max ?? Number.MAX_SAFE_INTEGER)
    )
      throw Error('invalid_number');
    return number;
  }
  if (field.kind === 'numbers') {
    const numbers = text
      .trim()
      .split(/[\s,]+/)
      .map(Number);
    if (numbers.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) throw Error('invalid_bytes');
    return numbers;
  }
  if (field.kind === 'mark') {
    const value = text.trim();
    if (!/^(?:\d+|0[xX][0-9a-fA-F]+)$/.test(value)) throw Error('invalid_mark');
    const number = Number(value);
    if (!Number.isSafeInteger(number) || number > 4294967295) throw Error('invalid_mark');
    return /^0x/i.test(value) ? value : number;
  }
  if (field.kind === 'string-range') {
    if (!/^\d+(?:-\d+)?$/.test(text)) throw Error('invalid_range');
    const parts = text.split('-').map(Number);
    if (
      parts.some((n) => !Number.isSafeInteger(n) || n < (field.min ?? 0) || n > (field.max ?? 65535)) ||
      parts[0] > parts[parts.length - 1]
    )
      throw Error('invalid_range');
    return text;
  }
  if (field.kind === 'range') {
    if (!/^\d+(?:-\d+)?$/.test(text)) throw Error('invalid_range');
    const parts = text.split('-').map(Number);
    if (
      parts.some((n) => !Number.isSafeInteger(n) || n > 4294967295) ||
      (parts.length > 1 && parts[0] > parts[1])
    )
      throw Error('invalid_range');
    return parts.length === 1 ? parts[0] : text;
  }
  return text;
}
