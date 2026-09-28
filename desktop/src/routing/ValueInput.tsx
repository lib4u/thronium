import type { ChangeEvent } from 'react';
import { Input, SecretField, SecretText, Select, Textarea } from '../shared/ui/controls';
import { translate, type Language } from '../shared/i18n/index.ts';

type Control = {
  id?: string;
  disabled?: boolean;
  'aria-label'?: string;
  'aria-invalid'?: true;
  onChange(event: ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>): void;
} & Record<`data-${string}`, string>;

/**
 * The control of one rule or resource value: a three-state choice for flags,
 * a list of options, a text area for lists and JSON, or a line of text. Rule
 * conditions, logical conditions and DNS resources render values the same way.
 */
export default function ValueInput({
  kind,
  text,
  language,
  control,
  options,
  optionLabel = (value) => value,
  multiline = ['list', 'numbers', 'json', 'hosts', 'integers'].includes(kind),
  rows,
  placeholder,
  mono = false,
  secret = false,
  shown,
  onShownChange,
}: {
  kind: string;
  text: string;
  language: Language;
  control: Control;
  options?: readonly string[];
  optionLabel?(value: string): string;
  multiline?: boolean;
  rows?: number;
  placeholder?: string;
  mono?: boolean;
  secret?: boolean;
  shown?: boolean;
  onShownChange?(shown: boolean): void;
}) {
  const inherited = translate(language, 'routing.default_4d4d367');
  if (kind === 'bool')
    return (
      <Select className="text-input" value={text} {...control}>
        <option value="">{inherited}</option>
        <option value="true">{translate(language, 'routing.yes_0a80c56')}</option>
        <option value="false">{translate(language, 'routing.no_3f7ce4a')}</option>
      </Select>
    );
  if (options)
    return (
      <Select className="text-input" value={text} {...control}>
        <option value="">{inherited}</option>
        {options
          .filter((value) => value !== '')
          .map((value) => (
            <option key={value} value={value}>
              {optionLabel(value)}
            </option>
          ))}
        {text && !options.includes(text) && <option value={text}>{optionLabel(text)}</option>}
      </Select>
    );
  const common = { value: text, spellCheck: false, autoComplete: 'off', ...control };
  if (multiline) {
    const area = {
      ...common,
      className: `text-input${mono ? ' mono field-multiline' : ''}`,
      rows: rows ?? (kind === 'json' ? 4 : Math.min(5, text.split('\n').length)),
      wrap: 'off',
      placeholder: placeholder ?? (kind === 'json' ? '{ … }' : undefined),
    };
    return secret ? (
      <SecretText {...area} shown={shown} onShownChange={onShownChange} />
    ) : (
      <Textarea {...area} />
    );
  }
  return secret ? (
    <SecretField {...common} className="text-input" shown={shown} onShownChange={onShownChange} />
  ) : (
    <Input
      {...common}
      className="text-input"
      inputMode={kind === 'number' ? 'numeric' : undefined}
      placeholder={placeholder}
    />
  );
}
