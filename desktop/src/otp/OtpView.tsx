import { messageRef } from '../shared/i18n/message';
import OtpImportDialog from './OtpImportDialog';
import OtpEditorDialog from './OtpEditorDialog';
import { InlineError, Field } from '../shared/ui/controls';
import { Button, Input, Select, Textarea } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import { command } from '../api';
import { ConfirmDialog, Modal } from '../ui';
import './Otp.css';
import { ExportFormat, empty } from './OtpModel';
import type { useOtpController } from './useOtpController';
import { Pager } from '../shared/ui/Pager';
export default function OtpView({ controller }: { controller: ReturnType<typeof useOtpController> }) {
  const {
    busy,
    close,
    codes,
    codesOnly,
    copy,
    dom,
    edit,
    editor,
    error,
    exportEntries,
    exported,
    importing,
    language,
    load,
    mounted,
    notice,
    page,
    pages,
    panel,
    paused,
    query,
    removing,
    reorder,
    rows,
    run,
    setEditor,
    setError,
    setExported,
    setImporting,
    setNotice,
    setPage,
    setQuery,
    setRemoving,
    setShowSecret,
    setText,
    shown,
    visible,
  } = controller;
  const cancel = (
    <Button type="button" className="button secondary" disabled={busy} onClick={close}>
      {translate(language, 'otp.cancel_bf4c449')}
    </Button>
  );
  return (
    <section
      ref={panel}
      className={`feature-panel otp-panel ${codesOnly ? 'otp-quick-panel' : ''}`}
      id={codesOnly ? 'otp-quick-panel' : 'otp-manager'}
    >
      {!codesOnly && (
        <div className="feature-panel-head">
          <h2>{translate(language, 'otp.authenticator_e3dd902')}</h2>
        </div>
      )}
      <p className="field-hint">
        {translate(language, 'otp.totp_codes_update_with_time_hotp_shows_the_curre_37b8d3a')}
      </p>
      <div className="otp-toolbar">
        {!codesOnly && (
          <>
            <Button
              className="button primary"
              id="otp-add"
              disabled={busy}
              onClick={() => {
                setEditor({ id: '', revision: '', value: empty() });
                setShowSecret(false);
                setError('');
              }}
            >
              {translate(language, 'otp.add_entry_414da08')}
            </Button>
            <Button
              className="button secondary"
              id="otp-import"
              disabled={busy}
              onClick={() => {
                setImporting(true);
                setText('');
                setError('');
              }}
            >
              {translate(language, 'otp.import_55fdc70')}
            </Button>
            <Button
              className="button secondary"
              id="otp-export-all"
              disabled={busy || !rows.length}
              onClick={() =>
                void exportEntries(
                  rows.map((row) => row.id),
                  'json',
                )
              }
            >
              {translate(language, 'otp.export_all_16e21ea')}
            </Button>
          </>
        )}
        <Button
          className="text-button"
          id={dom('otp-refresh')}
          disabled={busy}
          onClick={() => void run(load)}
        >
          {translate(language, 'otp.refresh_8c51022')}
        </Button>
      </div>
      <Field className="feature-field" label={translate(language, 'otp.search_entries_8604e6c')}>
        <Input
          className="text-input"
          id={dom('otp-search')}
          onKeyDown={(e) => {
            if (codesOnly && e.key === 'Enter' && !e.nativeEvent.isComposing && shown.length) {
              e.preventDefault();
              void copy(shown[0]);
            }
          }}
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setPage(0);
          }}
        />
      </Field>
      {notice && (
        <p role="status" id={dom('otp-notice')}>
          {notice}
        </p>
      )}
      {error && !paused && (
        <InlineError className="desktop-inline-error" role="alert">
          {error}
        </InlineError>
      )}
      {!visible.length && (
        <p id={dom('otp-empty')} className="resource-empty">
          {rows.length
            ? translate(language, 'otp.no_matching_entries_bc2fd36')
            : translate(language, 'otp.no_entries_yet_d5d3536')}
        </p>
      )}
      <div className="otp-list">
        {shown.map((row) => (
          <article className="otp-entry" data-otp-id={row.id} key={row.id}>
            <div className="otp-entry-heading">
              <strong>{row.name || row.issuer || translate(language, 'otp.unnamed_entry_fa23f8c')}</strong>
              <small>
                {row.issuer} · {row.type.toUpperCase()} · {row.algorithm}
              </small>
            </div>
            <div className="otp-code-row">
              <output className="otp-code" data-otp-code>
                {codes[row.id]?.code || '—'}
              </output>
              <span data-otp-remaining>
                {row.type === 'totp'
                  ? `${codes[row.id]?.secondsRemaining ?? '—'} ${translate(language, 'otp.s_2997657')}`
                  : `${translate(language, 'otp.counter_e4184c4')}: ${codes[row.id]?.counter ?? row.counter}`}
              </span>
              <Button
                className="button secondary"
                data-otp-copy
                disabled={busy}
                onClick={() => void copy(row)}
              >
                {translate(language, 'otp.copy_e2d2d65')}
              </Button>
            </div>
            {!codesOnly && (
              <div className="otp-entry-actions">
                <Button className="text-button" data-otp-edit disabled={busy} onClick={() => void edit(row)}>
                  {translate(language, 'otp.edit_0fd5c3c')}
                </Button>
                <Button
                  className="text-button"
                  data-otp-export
                  disabled={busy}
                  onClick={() => void exportEntries([row.id], 'uri')}
                >
                  {translate(language, 'otp.link_qr_0af1b9f')}
                </Button>
                <Button
                  className="text-button"
                  data-otp-up
                  aria-label={translate(language, 'otp.move_up_441b312')}
                  disabled={busy || rows[0]?.id === row.id}
                  onClick={() => void reorder(row, -1)}
                >
                  ↑
                </Button>
                <Button
                  className="text-button"
                  data-otp-down
                  aria-label={translate(language, 'otp.move_down_d672813')}
                  disabled={busy || rows[rows.length - 1]?.id === row.id}
                  onClick={() => void reorder(row, 1)}
                >
                  ↓
                </Button>
                <Button
                  className="text-button"
                  data-otp-delete
                  disabled={busy}
                  onClick={() => {
                    setRemoving(row);
                    setError('');
                  }}
                >
                  {translate(language, 'otp.delete_55f670b')}
                </Button>
              </div>
            )}
          </article>
        ))}
      </div>
      {pages > 1 && (
        <Pager
          className="otp-toolbar"
          page={Math.min(page, pages - 1)}
          pages={pages}
          language={language}
          onChange={setPage}
        />
      )}
      {editor && <OtpEditorDialog controller={controller} />}
      {importing && <OtpImportDialog controller={controller} />}
      {exported && (
        <Modal
          title={translate(language, 'otp.export_authenticator_entries_85f39b0')}
          close={close}
          closeLabel={translate(language, 'otp.close_c9a286c')}
          footer={
            <>
              {cancel}
              <Button
                className="button secondary"
                id="otp-export-copy"
                disabled={busy}
                onClick={() =>
                  void run(async () => {
                    await command('writeClipboard', { text: exported.text });
                    if (mounted.current) setNotice(messageRef('otp.export_copied_cbec184'));
                  })
                }
              >
                {translate(language, 'otp.copy_e2d2d65')}
              </Button>
              <Button
                className="button primary"
                id="otp-export-file"
                disabled={busy}
                onClick={() =>
                  void run(async () => {
                    await command('exportSharedText', {
                      text: exported.text,
                      format: exported.format === 'json' ? 'otp-json' : 'otp-links',
                      destination: 'file',
                    });
                  })
                }
              >
                {translate(language, 'otp.save_file_f57c7e9')}
              </Button>
            </>
          }
        >
          <p className="field-hint">
            {translate(language, 'otp.this_export_contains_the_secrets_needed_to_gener_49a3922')}
          </p>
          <Field className="feature-field" label={translate(language, 'otp.format_e00adff')}>
            <Select
              className="text-input"
              id="otp-export-format"
              disabled={busy}
              value={exported.format}
              onChange={(e) => void exportEntries(exported.ids, e.target.value as ExportFormat)}
            >
              <option value="json">{translate(language, 'otp.json_all_parameters_bfb16c6')}</option>
              <option value="uri" disabled={exported.ids.length !== 1}>
                {translate(language, 'otp.otpauth_link_one_entry_5846345')}
              </option>
              <option value="migration">Google Authenticator</option>
            </Select>
          </Field>
          {exported.format === 'migration' && (
            <p className="field-hint">
              {translate(language, 'otp.google_transfers_support_6_or_8_digits_and_a_30__74249dd')}
            </p>
          )}
          <Textarea
            className="text-input otp-import-text"
            id="otp-export-text"
            aria-label={translate(language, 'otp.otp_export_14fd433')}
            value={exported.text}
            readOnly
            spellCheck={false}
          />
          {exported.format !== 'json' && (
            <Button
              className="button secondary"
              id="otp-show-qr"
              disabled={busy}
              onClick={() =>
                void run(async () => {
                  const qr = await command('exportQr', {
                    text: exported.text,
                    destination: 'preview',
                  });
                  if (mounted.current) setExported({ ...exported, image: qr.image });
                })
              }
            >
              {translate(language, 'otp.show_qr_7d8dd74')}
            </Button>
          )}
          {exported.image && (
            <div className="otp-qr">
              <img
                id="otp-qr-image"
                src={exported.image}
                alt={translate(language, 'otp.authenticator_entry_qr_724aec6')}
              />
              <div className="otp-toolbar">
                {(['clipboard', 'file'] as const).map((destination) => (
                  <Button
                    className="button secondary"
                    key={destination}
                    disabled={busy}
                    onClick={() =>
                      void run(async () => {
                        await command('exportQr', { text: exported.text, destination });
                      })
                    }
                  >
                    {destination === 'file'
                      ? translate(language, 'otp.save_qr_c3c4d66')
                      : translate(language, 'otp.copy_qr_804a18b')}
                  </Button>
                ))}
              </div>
            </div>
          )}
          {notice && <p role="status">{notice}</p>}
          {error && (
            <InlineError className="desktop-inline-error" role="alert">
              {error}
            </InlineError>
          )}
        </Modal>
      )}
      {removing && (
        <ConfirmDialog
          title={translate(language, 'otp.delete_authenticator_entry_9b422d1')}
          message={removing.name || removing.issuer || translate(language, 'otp.unnamed_entry_fa23f8c')}
          cancelLabel={translate(language, 'otp.cancel_bf4c449')}
          confirmLabel={translate(language, 'otp.delete_55f670b')}
          confirmId="otp-delete-confirm"
          busy={busy}
          error={error}
          cancel={close}
          confirm={() =>
            void run(async () => {
              await command('otpRemove', { id: removing.id, revision: removing.revision });
              await load();
              if (mounted.current) setRemoving(undefined);
            })
          }
        />
      )}
    </section>
  );
}
