import { Section, Field, InlineError, Button, Select, Input } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import { Icon } from '../ui';
import { geoProviders, geoUrl, type GeoKind } from './catalog';
import CategoryEditor from './CategoryEditor';
import GeoCategories from './GeoCategories';
import GeoPreviewDialog from './GeoPreviewDialog';
import { builtInTargets, outboundProfiles, targetLabel } from './model';
import { useGeoPanel, type GeoPanelProps } from './useGeoPanel';

export default function GeoPanel(props: GeoPanelProps) {
  const controller = useGeoPanel(props);
  const {
    profile,
    profiles,
    language,
    translateError,
    kind,
    url,
    source,
    selected,
    target,
    setTarget,
    first,
    setFirst,
    busy,
    error,
    notice,
    preview,
    editor,
    setEditor,
    file,
    request,
    disabled,
    choices,
    changeSource,
    load,
    readFile,
    add,
    copy,
    used,
  } = controller;
  return (
    <section className="feature-panel geo-panel">
      <div className="feature-panel-head">
        <div>
          <h2>{translate(language, 'routing.geosite_geoip_categories_739f4db')}</h2>
          <p>{translate(language, 'routing.load_a_database_select_categories_and_assign_a_r_0c60256')}</p>
        </div>
        <Button
          className="button secondary"
          id="geo-new-copy"
          disabled={disabled}
          onClick={() =>
            setEditor({
              name: translate(language, 'routing.my_category_20be2af'),
              rules: [{ domain_suffix: ['example.com'] }],
            })
          }
        >
          <Icon name="plus" />
          {translate(language, 'routing.custom_category_0a3c5cc')}
        </Button>
      </div>
      {request.pending && (
        <Button className="text-button" id="geo-cancel" onClick={request.cancel}>
          {translate(language, 'routing.cancel_bf4c449')}
        </Button>
      )}
      <div className="geo-source-grid">
        <Field className="feature-field" label={translate(language, 'routing.database_811e5b0')}>
          <Select
            id="geo-kind"
            className="text-input"
            value={kind}
            disabled={disabled}
            onChange={(e) => {
              const k = e.target.value as GeoKind;
              const provider = geoProviders.find((p) => url === p[kind]);
              changeSource(geoUrl(k, provider?.id), k);
            }}
          >
            <option value="geosite">GeoSite · {translate(language, 'routing.domains_dedab10')}</option>
            <option value="geoip">GeoIP · {translate(language, 'routing.ip_addresses_db65d47')}</option>
          </Select>
        </Field>
        <Field className="feature-field" label={translate(language, 'routing.source_64835b1')}>
          <Select
            id="geo-provider"
            className="text-input"
            value={choices.some((c) => c.url === url) ? url : 'custom'}
            disabled={disabled}
            onChange={(e) => changeSource(e.target.value === 'custom' ? '' : e.target.value)}
          >
            {choices.map((c) => (
              <option key={c.url} value={c.url}>
                {c.name}
              </option>
            ))}
            <option value="custom">{translate(language, 'routing.custom_url_4d9a01c')}</option>
          </Select>
        </Field>
      </div>
      <Field
        className="feature-field"
        label={
          url.startsWith('local:')
            ? translate(language, 'routing.imported_file_ed266fb')
            : translate(language, 'routing.url_of_dat_file_0b1f36d')
        }
      >
        <Input
          id="geo-url"
          className="text-input"
          value={url}
          disabled={disabled || url.startsWith('local:')}
          placeholder="https://…/geosite.dat"
          spellCheck={false}
          onChange={(e) => changeSource(e.target.value)}
        />
      </Field>
      <div className="geo-toolbar">
        <Button
          id="geo-load"
          className="button primary"
          disabled={disabled || !url.trim()}
          onClick={() => void load()}
        >
          <Icon name="download" />
          {busy
            ? translate(language, 'routing.loading_b94ec3e')
            : translate(language, 'routing.open_database_38652b2')}
        </Button>
        <Button
          id="geo-refresh"
          className="button secondary"
          disabled={disabled || !url.trim() || url.startsWith('local:')}
          onClick={() => void load(true)}
        >
          <Icon name="refresh" />
          {translate(language, 'routing.download_update_37e18cf')}
        </Button>
        <Button
          className="button secondary"
          id="geo-import-file"
          disabled={disabled}
          onClick={() => file.current?.click()}
        >
          <Icon name="file" />
          {translate(language, 'routing.open_dat_5872503')}
        </Button>
        <Input
          className=""
          ref={file}
          type="file"
          accept=".dat"
          hidden
          onChange={(e) => {
            void readFile(e.target.files?.[0]);
            e.target.value = '';
          }}
        />
      </div>
      <p className="geo-hint">
        {translate(language, 'routing.default_sources_are_on_github_databases_are_cach_f65154f')}
      </p>
      {error && (
        <InlineError className="desktop-inline-error" role="alert">
          {error}
        </InlineError>
      )}
      {notice && (
        <p className="geo-notice" role="status">
          {notice}
        </p>
      )}
      {source && <GeoCategories controller={controller} source={source} />}
      <div className="geo-assignment">
        <Field className="feature-field" label={translate(language, 'routing.traffic_destination_f71bbb2')}>
          <Select
            id="geo-target"
            className="text-input"
            value={target}
            disabled={disabled}
            onChange={(e) => setTarget(e.target.value)}
          >
            {builtInTargets.map((value) => (
              <option key={value} value={value}>
                {targetLabel(value, profiles, language)}
              </option>
            ))}
            {outboundProfiles(profiles).map((p) => (
              <option key={p.id} value={'profile:' + p.id}>
                {p.name}
              </option>
            ))}
          </Select>
        </Field>
        <Field className="feature-field" label={translate(language, 'routing.priority_18345a9')}>
          <Select
            id="geo-position"
            className="text-input"
            value={first ? 'first' : 'last'}
            disabled={disabled}
            onChange={(e) => setFirst(e.target.value === 'first')}
          >
            <option value="first">{translate(language, 'routing.before_existing_rules_0942b80')}</option>
            <option value="last">{translate(language, 'routing.after_existing_rules_0f842bc')}</option>
          </Select>
        </Field>
        <Button
          className="button primary"
          id="geo-add"
          disabled={disabled || !selected.length || !source}
          onClick={() => void add()}
        >
          <Icon name="plus" />
          {translate(language, 'routing.add_6cb0cec')}
          {selected.length ? ` (${selected.length})` : ''}
        </Button>
      </div>
      {profile.mode !== 'rules' && (
        <p className="rules-notice">
          {translate(language, 'routing.categories_apply_in_by_rules_mode_1ff6815')}
        </p>
      )}
      {used.length > 0 && (
        <Section
          title={
            <>
              {translate(language, 'routing.sources_used_by_this_profile_25ff618')} · {used.length}
            </>
          }
          className="geo-used"
        >
          {used.map((s, i) => (
            <div className="geo-used-row" key={i}>
              <strong>
                {String(s.kind)}:{String(s.category)}
              </strong>
              <span>{String(s.url)}</span>
              <Button
                className="text-button"
                disabled={disabled}
                onClick={() => changeSource(String(s.url), s.kind as GeoKind)}
              >
                {translate(language, 'routing.open_source_00fd29d')}
              </Button>
            </div>
          ))}
        </Section>
      )}
      {preview && source && <GeoPreviewDialog controller={controller} source={source} preview={preview} />}
      {editor && (
        <CategoryEditor
          {...editor}
          language={language}
          translateError={translateError}
          close={() => setEditor(null)}
          save={copy}
        />
      )}
    </section>
  );
}
