import ImportSourceFields from './ImportSourceFields';
import { TabList, InlineError, Field } from '../shared/ui/controls';
import { Button, Input, Select, Checkbox } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import { Icon } from '../ui';
import type { useImportController } from './useImportController';
import { groupName } from '../groups/groupModel';
import { limits } from '../shared/api/generated/limits.ts';
export default function ImportView({ controller }: { controller: ReturnType<typeof useImportController> }) {
  const {
    Frame,
    accepted,
    address,
    busy,
    checks,
    chosen,
    close,
    error,
    errors,
    group,
    groups,
    hasWarnings,
    language,
    message,
    method,
    methodChanged,
    rename,
    review,
    rows,
    save,
    selected,
    setAccepted,
    setChosen,
    setGroup,
    setRows,
    setShown,
    shown,
    subscription,
    text,
    tr,
    validRows,
    validate,
    validating,
    warning,
  } = controller;
  return (
    <Frame
      className="desktop-import-modal"
      title={tr('title')}
      description={tr('hint')}
      close={() => {
        if (!busy && validating === null) close();
      }}
      closeLabel={tr('close')}
      footer={
        <>
          <Button className="text-button" disabled={busy || validating !== null} onClick={close}>
            {tr('cancel')}
          </Button>
          {rows === null ? (
            <Button
              className="button primary"
              id="import-review"
              disabled={busy || !text.trim()}
              onClick={review}
            >
              {tr(subscription?.automatic ? 'addSubscription' : 'review')}
              <Icon name="arrow-right" />
            </Button>
          ) : (
            <Button
              className="button primary"
              id="import-save"
              disabled={
                busy ||
                validating !== null ||
                !selected.length ||
                selected.some((r) => !r.draft?.name.trim()) ||
                (hasWarnings && !accepted)
              }
              onClick={() => void save()}
            >
              <Icon name="check" />
              {tr(busy ? 'importing' : 'import')} · {selected.length}
            </Button>
          )}
        </>
      }
    >
      {error && (
        <div className="desktop-inline-error" role="alert">
          {error}
        </div>
      )}
      {rows === null ? (
        <>
          <TabList
            className="import-method-tabs"
            aria-label={translate(language, 'profiles.import_method_5796e0e')}
            value={method}
            onChange={(value) => methodChanged?.(value)}
            disabled={busy}
            tabs={(['link', 'file', 'qr'] as const).map((value) => ({
              id: value,
              attributes: { id: `import-tab-${value}`, 'aria-controls': 'import-method-panel' },
              label: (
                <>
                  <Icon name={value} />
                  {value === 'link'
                    ? translate(language, 'profiles.by_link_949a7e6')
                    : value === 'file'
                      ? translate(language, 'profiles.from_file_a9a95a2')
                      : translate(language, 'profiles.qr_code_f15bdf0')}
                </>
              ),
            }))}
          />
          <ImportSourceFields controller={controller} />
          {busy && (
            <p role="status" className="field-hint">
              {translate(language, 'profiles.reading_content_1a2947d')}
            </p>
          )}
        </>
      ) : (
        <>
          <Field className="feature-field import-destination" label={tr('group')}>
            <Select
              id="import-group"
              className="text-input"
              value={group}
              disabled={busy || validating !== null}
              onChange={(e) => setGroup(e.target.value)}
            >
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {groupName(g, language)}
                </option>
              ))}
            </Select>
          </Field>
          <div className="import-summary">
            <div>
              <strong>
                {tr('found')}: {validRows.length}
              </strong>
              <span>
                {tr('errors')}: {errors}
              </span>
            </div>
            <Button
              className="text-button"
              disabled={busy || validating !== null}
              onClick={() => setRows(null)}
            >
              {tr('back')}
            </Button>
          </div>
          {validRows.length > 1 && (
            <label className="import-toggle">
              <Checkbox
                id="import-select-all"
                type="checkbox"
                checked={chosen.size === validRows.length}
                onChange={(e) => {
                  setChosen(new Set(e.target.checked ? validRows.map((r) => r.index) : []));
                  setAccepted(false);
                }}
              />
              {tr('selectAll')}
            </label>
          )}
          {!rows.length && <p>{tr('empty')}</p>}
          <div className="import-rows">
            {rows.map((row) => (
              <article
                className={`import-row ${row.error ? 'has-error' : ''}`}
                key={row.index}
                data-import-row={row.index}
              >
                {row.draft ? (
                  <>
                    <div className="import-row-main">
                      <Checkbox
                        className="import-select"
                        type="checkbox"
                        checked={chosen.has(row.index)}
                        aria-label={`${tr('selected')}: ${row.draft.name}`}
                        onChange={(e) => {
                          setChosen((old) => {
                            const next = new Set(old);
                            if (e.target.checked) next.add(row.index);
                            else next.delete(row.index);
                            return next;
                          });
                          setAccepted(false);
                        }}
                      />
                      <div>
                        <label>
                          <span className="sr-only">
                            {tr('name')} · {row.index}
                          </span>
                          <Input
                            className="text-input import-name"
                            value={row.draft.name}
                            maxLength={limits.maxNameBytes}
                            onChange={(e) => rename(row.index, e.target.value)}
                          />
                        </label>
                        <small>
                          {[
                            row.draft.config.amnezia_wg
                              ? 'AmneziaWG'
                              : row.draft.config.type || row.draft.config.protocol || row.draft.kind,
                            address(row.draft),
                          ]
                            .filter(Boolean)
                            .join(' · ')}
                        </small>
                      </div>
                    </div>
                    {row.warnings.length > 0 && (
                      <ul className="import-warnings">
                        {row.warnings.map((w) => (
                          <li key={w}>{warning(w)}</li>
                        ))}
                      </ul>
                    )}
                    <div className="import-row-actions">
                      <Button
                        className="text-button"
                        data-import-check={row.index}
                        disabled={busy || validating !== null}
                        onClick={() => void validate(row)}
                      >
                        {tr(validating === row.index ? 'checking' : 'check')}
                      </Button>
                      <Button
                        className="text-button"
                        data-import-json={row.index}
                        onClick={() =>
                          setShown((old) => {
                            const next = new Set(old);
                            if (next.has(row.index)) next.delete(row.index);
                            else next.add(row.index);
                            return next;
                          })
                        }
                      >
                        {tr(shown.has(row.index) ? 'hide' : 'json')}
                      </Button>
                    </div>
                    {checks[row.index]?.valid && (
                      <p className="import-valid" role="status">
                        {row.draft?.kind === 'external-core'
                          ? translate(
                              language,
                              'profiles.launch_parameters_and_executable_checked_socks5__7d8c2e2',
                            )
                          : tr('valid')}
                      </p>
                    )}
                    {checks[row.index]?.error && (
                      <InlineError className="desktop-inline-error" role="alert">
                        {checks[row.index].error}
                      </InlineError>
                    )}
                    {row.draft.vpnPolicy && (
                      <p className="field-hint import-vpn-policy">
                        {translate(
                          language,
                          'profiles.vpn_policy_advertised_routes_only_value0_vpn_dns_d76c981',
                          {
                            value0: row.draft.vpnPolicy.onlyAdvertisedRoutes
                              ? translate(language, 'profiles.yes_b6d6df7')
                              : translate(language, 'profiles.no_1a1d600'),
                            value1: row.draft.vpnPolicy.useTunnelDns
                              ? translate(language, 'profiles.yes_b6d6df7')
                              : translate(language, 'profiles.no_1a1d600'),
                            value2: row.draft.vpnPolicy.blockOutsideDns
                              ? translate(language, 'profiles.yes_b6d6df7')
                              : translate(language, 'profiles.no_1a1d600'),
                          },
                        )}
                      </p>
                    )}
                    {shown.has(row.index) && (
                      <pre className="import-json mono">{JSON.stringify(row.draft.config, null, 2)}</pre>
                    )}
                  </>
                ) : (
                  <InlineError role="alert">
                    {tr('line')} {row.index}: {message(row.error || 'invalid_content')}
                  </InlineError>
                )}
              </article>
            ))}
          </div>
          {hasWarnings && (
            <label className="import-toggle import-acknowledge">
              <Checkbox
                id="import-acknowledge"
                type="checkbox"
                checked={accepted}
                onChange={(e) => setAccepted(e.target.checked)}
              />
              {tr('acknowledge')}
            </label>
          )}
          <p className="field-hint">{tr('notTested')}</p>
        </>
      )}
    </Frame>
  );
}
