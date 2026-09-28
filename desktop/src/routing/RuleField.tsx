import { Checkbox } from '../shared/ui/controls';
import ValueInput from './ValueInput';
import { commaValues, formatRuleValue, optionValues } from './ruleInput';
import { label } from '../profiles/schema';
import { type MatchField } from './model';
import { platform } from '../shared/platform.ts';

/** sing-box on Windows matches the executable's file name and path as Windows spells them. */
const windowsExamples: Partial<Record<string, Parameters<typeof label>[0]>> =
  platform === 'windows'
    ? {
        process_name: 'routing.windows_process_name_example_6bfd7fe',
        process_path: 'routing.windows_process_path_example_8fae8fb',
      }
    : {};
import type { useRuleEditor } from './useRuleEditor';
export default function RuleField({
  field,
  condition = false,
  controller,
}: {
  field: MatchField;
  condition?: boolean;
  controller: Pick<
    ReturnType<typeof useRuleEditor>,
    'buffers' | 'config' | 'language' | 'errors' | 'update' | 'busy' | 'tr'
  >;
}) {
  const { buffers, config, language, errors, update, busy, tr } = controller;
  const value = buffers[field.key] ?? formatRuleValue(field, config[field.key]);
  const control = {
    'data-route-field': field.key,
    'aria-label': label(field.label, language),
    'aria-invalid': errors[field.key] || undefined,
    disabled: busy,
    onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) =>
      update(field, e.target.value),
  };
  if (field.kind === 'bool' && !condition)
    return (
      <Checkbox
        type="checkbox"
        {...control}
        value={value}
        checked={value === 'true'}
        onChange={(e) => update(field, String(e.target.checked))}
      />
    );
  return (
    <ValueInput
      kind={field.kind}
      text={value}
      language={language}
      control={control as Parameters<typeof ValueInput>[0]['control']}
      options={condition ? undefined : optionValues[field.key]}
      placeholder={
        windowsExamples[field.key]
          ? label(windowsExamples[field.key]!, language)
          : ['list', 'numbers'].includes(field.kind)
            ? tr(commaValues(field) ? 'commaHint' : 'lineHint')
            : field.kind === 'json'
              ? undefined
              : tr('inherited')
      }
    />
  );
}
