import { SearchField, Button, Checkbox } from '../shared/ui/controls';
import { formatBytes, formatNumber, formatDateTime } from '../shared/i18n/format.ts';
import { plural, translate } from '../shared/i18n/index.ts';
import { Pager } from '../shared/ui/Pager';
import type { GeoSource } from './catalog';
import type { GeoController } from './useGeoPanel';

/** Categories of the loaded geodata database: search, selection and paging. */
export default function GeoCategories({
  controller,
  source,
}: {
  controller: GeoController;
  source: GeoSource;
}) {
  const {
    language,
    query,
    setQuery,
    page,
    setPage,
    selected,
    setSelected,
    disabled,
    inspect,
    found,
    pageSize,
    shown,
  } = controller;
  return (
    <>
      <div className="geo-meta">
        <strong>{plural(language, 'common.category_count', source.categories.length)}</strong>
        <span>{formatBytes(source.bytes, language)}</span>
        <span>
          {translate(language, 'routing.loaded_e9f1685')}:{' '}
          {formatDateTime(new Date(source.updatedAt * 1000), language)}
        </span>
      </div>
      <div className="geo-search">
        <SearchField
          id="geo-search"
          value={query}
          placeholder={translate(language, 'routing.find_ru_cn_ads_ai_openai_df499f2')}
          aria-label={translate(language, 'routing.find_category_cf32acd')}
          onChange={(e) => {
            setQuery(e.target.value);
            setPage(0);
          }}
        />
        <span>{formatNumber(found.length, language)}</span>
      </div>
      <div className="geo-suggestions">
        {['ru', 'cn', 'ir', 'ads', 'ai', 'openai', 'google', 'telegram'].map((q) => (
          <Button
            className="geo-chip"
            key={q}
            onClick={() => {
              setQuery(q);
              setPage(0);
            }}
          >
            {q}
          </Button>
        ))}
      </div>
      <div className="geo-category-list">
        {shown.map((c) => (
          <div className="geo-category-row" key={c.code}>
            <label>
              <Checkbox
                type="checkbox"
                disabled={disabled}
                data-geo-select={c.code}
                checked={selected.includes(c.code)}
                onChange={(e) =>
                  setSelected((old) =>
                    e.target.checked ? [...old, c.code] : old.filter((v) => v !== c.code),
                  )
                }
              />
              <span>
                <strong>{c.code}</strong>
                <small>
                  {plural(language, 'routing.entry_count', c.count)}
                  {c.attributes.length > 0 ? ` · @${c.attributes.join(', @')}` : ''}
                </small>
              </span>
            </label>
            <Button
              className="text-button"
              disabled={disabled}
              data-geo-preview={c.code}
              onClick={() => void inspect(c.code)}
            >
              {translate(language, 'routing.contents_8889522')}
            </Button>
          </div>
        ))}
      </div>
      {!found.length && (
        <p className="resource-empty">
          {translate(language, 'routing.no_matching_categories_in_this_database_try_anot_a7248a0')}
        </p>
      )}
      {found.length > pageSize && (
        <Pager
          className="geo-pagination"
          page={page}
          pages={Math.ceil(found.length / pageSize)}
          language={language}
          onChange={setPage}
        />
      )}
    </>
  );
}
