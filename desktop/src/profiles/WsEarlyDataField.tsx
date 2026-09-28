import { Input } from '../shared/ui/controls';
import {
  editWsEarlyData,
  inspectWsEarlyData,
  wsEarlyDataText,
  type EarlyDataTransport,
  type WsIssue,
} from './wsEarlyData';
import type { Language } from '../shared/i18n/index.ts';

export default function WsEarlyDataField({
  path,
  buffer,
  invalid,
  disabled,
  language,
  transport = 'ws',
  change,
}: {
  path: unknown;
  transport?: EarlyDataTransport;
  buffer?: string;
  invalid?: boolean;
  disabled: boolean;
  language: Language;
  change(text: string): void;
}) {
  const id = `xray-${transport}-early-data`;
  const read = inspectWsEarlyData(path);
  let issue = read.issue;
  if (invalid) {
    try {
      editWsEarlyData(path, buffer ?? '');
    } catch (error) {
      issue = (error as Error).message as WsIssue;
    }
  }
  return (
    <div className="feature-field span-all" id={id + '-field'}>
      <label htmlFor={id}>{wsEarlyDataText('label', language, transport)}</label>
      <Input
        className="text-input"
        id={id}
        type="text"
        inputMode="numeric"
        autoComplete="off"
        spellCheck={false}
        value={buffer ?? (read.value === null ? '' : String(read.value))}
        disabled={disabled || !!read.issue}
        aria-invalid={!!invalid || undefined}
        aria-describedby={id + '-hint'}
        onChange={(event) => change(event.target.value)}
      />
      <small id={id + '-hint'} className={invalid ? 'field-error' : 'field-hint'}>
        {wsEarlyDataText(issue ?? 'hint', language, transport)}
      </small>
    </div>
  );
}
