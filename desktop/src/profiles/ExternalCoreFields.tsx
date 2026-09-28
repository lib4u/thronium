import { Input, Button, Textarea, NumberField, Select, Field } from '../shared/ui/controls';
import { translate, type Language } from '../shared/i18n/index.ts';
import type { Config } from './schema';
import { limits } from '../shared/api/generated/limits.ts';

export default function ExternalCoreFields({
  config,
  language,
  disabled,
  change,
  choose,
}: {
  config: Config;
  language: Language;
  disabled: boolean;
  change(config: Config): void;
  choose(): void;
}) {
  const text = (key: string) => (typeof config[key] === 'string' ? (config[key] as string) : '');
  // Keep empty arguments and arbitrary configuration text verbatim. The generic
  // protocol fields delete empty strings and therefore cannot edit this DTO.
  const update = (key: string, value: unknown) => change({ ...config, [key]: value });
  return (
    <div className="feature-fields" id="external-core-fields">
      <p className="field-hint span-all">
        {translate(language, 'profiles.local_proxy_tcp_the_program_must_run_in_the_fo_3e7f3e7')}
      </p>
      <Field
        className="feature-field span-all"
        htmlFor="external-core-path"
        label={translate(language, 'profiles.executable_file_4ef2899')}
      >
        <Input
          id="external-core-path"
          className="text-input mono"
          value={text('extra_core_path')}
          disabled={disabled}
          spellCheck={false}
          autoComplete="off"
          onChange={(e) => update('extra_core_path', e.target.value)}
        />
      </Field>
      <div className="span-all">
        <Button
          type="button"
          id="external-core-choose"
          className="button secondary"
          disabled={disabled}
          onClick={choose}
        >
          {translate(language, 'profiles.choose_file_1af7dfb')}
        </Button>
      </div>
      <Field
        className="feature-field span-all"
        htmlFor="external-core-args"
        label={translate(language, 'profiles.arguments_58ede83')}
      >
        <Textarea
          id="external-core-args"
          className="text-input mono field-multiline"
          value={text('extra_core_args')}
          disabled={disabled}
          rows={3}
          spellCheck={false}
          autoComplete="off"
          onChange={(e) => update('extra_core_args', e.target.value)}
        />
        <small className="field-hint">
          {translate(language, 'profiles.use_quotes_for_arguments_containing_spaces_s_ins_e1ab34d')}
        </small>
      </Field>
      <Field
        className="feature-field span-all"
        htmlFor="external-core-config"
        label={translate(language, 'profiles.configuration_file_contents_8dffc8b')}
      >
        <Textarea
          id="external-core-config"
          className="text-input mono field-multiline"
          value={text('extra_core_conf')}
          disabled={disabled}
          rows={8}
          spellCheck={false}
          autoComplete="off"
          onChange={(e) => update('extra_core_conf', e.target.value)}
        />
        <small className="field-hint">
          {translate(language, 'profiles.the_original_text_is_saved_unchanged_use_s_in_th_6087d3f')}
        </small>
      </Field>
      <Field
        className="feature-field"
        htmlFor="external-core-socks-address"
        label={translate(language, 'profiles.socks5_address_642cd18')}
      >
        <Input
          id="external-core-socks-address"
          className="text-input mono"
          value={text('socks_address')}
          disabled={disabled}
          spellCheck={false}
          autoComplete="off"
          onChange={(e) => update('socks_address', e.target.value)}
        />
        <small className="field-hint">127.0.0.1</small>
      </Field>
      <Field
        className="feature-field"
        htmlFor="external-core-socks-port"
        label={translate(language, 'profiles.socks5_port_81b1dd4')}
      >
        <NumberField
          id="external-core-socks-port"
          className="text-input"
          type="number"
          min={limits.externalPortMin}
          max={limits.externalPortMax}
          step={1}
          value={typeof config.socks_port === 'number' ? config.socks_port : ''}
          disabled={disabled}
          onChange={(e) => update('socks_port', e.target.value === '' ? null : Number(e.target.value))}
        />
        <small className="field-hint">
          {limits.externalPortMin}–{limits.externalPortMax}
        </small>
      </Field>
      <Field
        className="feature-field span-all"
        htmlFor="external-core-no-logs"
        label={translate(language, 'profiles.program_output_7d9dc7f')}
      >
        <Select
          id="external-core-no-logs"
          className="text-input"
          disabled={disabled}
          value={typeof config.no_logs === 'boolean' ? String(config.no_logs) : ''}
          onChange={(e) => update('no_logs', e.target.value === 'true')}
        >
          <option value="" disabled>
            {translate(language, 'profiles.choose_3dae513')}
          </option>
          <option value="true">{translate(language, 'profiles.do_not_write_to_the_log_7ed2452')}</option>
          <option value="false">{translate(language, 'profiles.write_to_the_log_fe32a2b')}</option>
        </Select>
      </Field>
    </div>
  );
}
