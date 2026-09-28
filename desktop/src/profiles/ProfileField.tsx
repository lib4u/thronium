import { Field as FormField, SecretField, SecretText } from '../shared/ui/controls';
import { Select, Textarea, Input } from '../shared/ui/controls';
import { get, format, label, type Field } from './schema';
import { secretPath } from './EditorModel';
import type { useProfileEditor } from './useProfileEditor';
export default function ProfileField({
  field,
  controller,
}: {
  field: Field;
  controller: Pick<
    ReturnType<typeof useProfileEditor>,
    'busy' | 'change' | 'current' | 'language' | 'parsed' | 'revealed' | 'setRevealed' | 'tr'
  >;
}) {
  const { busy, change, current, language, parsed, revealed, setRevealed, tr } = controller;

  const text = current.buffers[field.path] ?? format(field, get(parsed, field.path));
  const isSecret = field.kind === 'secret' || secretPath.test(field.path);
  const multiline = ['list', 'numbers', 'json'].includes(field.kind) || text.includes('\n');
  const fieldId = 'field-' + field.path.replace(/\./g, '-');
  const isInvalid = current.invalid[field.path];
  const value = {
    id: fieldId,
    'data-field': field.path,
    value: text,
    disabled: !parsed || busy,
    'aria-invalid': isInvalid || undefined,
    'aria-describedby': isInvalid ? fieldId + '-error' : field.hint ? fieldId + '-hint' : undefined,
    onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) =>
      change(field, e.target.value),
  };
  return (
    <FormField
      id={fieldId}
      label={label(field.label, language)}
      hint={field.hint ? label(field.hint, language) : undefined}
      error={isInvalid ? tr('fieldError') : undefined}
      className={`feature-field ${field.wide || multiline ? 'span-all' : ''}`}
      key={field.path}
    >
      {field.kind === 'bool' ? (
        <Select className="text-input" {...value}>
          <option value="">{field.unsetLabel ? label(field.unsetLabel, language) : tr('inherited')}</option>
          <option value="true">{tr('enabled')}</option>
          <option value="false">{tr('disabled')}</option>
        </Select>
      ) : field.kind === 'select' ? (
        <Select className="text-input" {...value}>
          {!field.options?.includes('') && <option value="">{tr('inherited')}</option>}
          {field.options?.map((v) => (
            <option key={v} value={String(v)}>
              {v === '' ? tr('inherited') : v}
            </option>
          ))}
          {text && !field.options?.some((v) => String(v) === text) && <option value={text}>{text}</option>}
        </Select>
      ) : multiline && isSecret ? (
        <SecretText
          rows={field.kind === 'json' ? 6 : 3}
          {...value}
          shown={!!revealed[field.path]}
          onShownChange={(shown) => setRevealed((old) => ({ ...old, [field.path]: shown }))}
        />
      ) : multiline ? (
        <Textarea
          className="text-input mono field-multiline"
          spellCheck={false}
          autoComplete="off"
          rows={field.kind === 'json' ? 6 : 3}
          {...value}
        />
      ) : isSecret ? (
        <SecretField
          className="text-input mono"
          {...value}
          shown={!!revealed[field.path]}
          onShownChange={(shown) => setRevealed((old) => ({ ...old, [field.path]: shown }))}
        />
      ) : (
        <Input
          className="text-input"
          type="text"
          inputMode={field.kind === 'number' ? 'numeric' : undefined}
          autoComplete="off"
          spellCheck={false}
          {...value}
        />
      )}
      {!isInvalid && ['range', 'list', 'mark'].includes(field.kind) && (
        <small className="field-hint">
          {tr(field.kind === 'range' ? 'rangeHint' : field.kind === 'mark' ? 'markHint' : 'listHint')}
        </small>
      )}
    </FormField>
  );
}
