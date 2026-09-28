import { Field, InlineError, Button, Select } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import { command } from '../api';
import { Modal } from '../ui';
import type { Config } from '../profiles/schema';
import type { GeoSource } from './catalog';
import { limits } from '../shared/limits.ts';
import type { GeoController } from './useGeoPanel';

/** Contents of one geodata category, filtered by attribute, added as is or copied into an editable set. */
export default function GeoPreviewDialog({
  controller,
  source,
  preview,
}: {
  controller: GeoController;
  source: GeoSource;
  preview: { code: string; rules: Config[] };
}) {
  const { language, error, setPreview, attribute, setAttribute, setEditor, disabled, run, add, attrs } =
    controller;
  return (
    <Modal
      className="geo-preview-modal"
      title={`${source.kind}:${preview.code}${attribute ? '@' + attribute : ''}`}
      description={source.url}
      close={() => !disabled && setPreview(null)}
      footer={
        <>
          <Button
            className="button secondary"
            disabled={disabled}
            id="geo-make-copy"
            onClick={() => {
              const p = preview;
              void run(async () => {
                const rules = attribute
                  ? (
                      await command('geodataCategory', {
                        kind: source.kind,
                        url: source.url,
                        category: p.code + '@' + attribute,
                      })
                    ).rules
                  : p.rules;
                setEditor({
                  name: `${p.code}${attribute ? '@' + attribute : ''} · ${translate(language, 'routing.my_copy_6899896')}`,
                  rules,
                });
              });
            }}
          >
            {translate(language, 'routing.edit_a_copy_f80782d')}
          </Button>
          <Button
            className="button primary"
            id="geo-add-preview"
            disabled={disabled}
            onClick={() => void add([preview.code + (attribute ? '@' + attribute : '')])}
          >
            {translate(language, 'routing.add_category_95d3b6a')}
          </Button>
        </>
      }
    >
      <p className="geo-hint">
        {translate(language, 'routing.uses_the_destination_and_priority_selected_on_th_a8d9c3b')}
      </p>
      {attrs.length > 0 && (
        <Field className="feature-field" label={translate(language, 'routing.attribute_filter_3feef5a')}>
          <Select
            className="text-input"
            id="geo-attribute"
            disabled={disabled}
            value={attribute}
            onChange={(e) => {
              const value = e.target.value;
              void run(async () => {
                const result = await command('geodataCategory', {
                  kind: source.kind,
                  url: source.url,
                  category: preview.code + (value ? '@' + value : ''),
                });
                setAttribute(value);
                setPreview({ ...preview, rules: result.rules });
              });
            }}
          >
            <option value="">{translate(language, 'routing.all_entries_95bd09c')}</option>
            {attrs.map((a) => (
              <option key={a} value={a}>
                @{a}
              </option>
            ))}
          </Select>
        </Field>
      )}
      <p className="geo-hint">{translate(language, 'routing.preview_entries')}</p>
      <pre className="geo-preview-text">
        {JSON.stringify(
          preview.rules.map((r) =>
            Object.fromEntries(
              Object.entries(r).map(([k, v]) => [
                k,
                Array.isArray(v) ? v.slice(0, limits.maxPreviewEntries) : v,
              ]),
            ),
          ),
          null,
          2,
        )}
      </pre>
      {error && (
        <InlineError className="desktop-inline-error" role="alert">
          {error}
        </InlineError>
      )}
    </Modal>
  );
}
