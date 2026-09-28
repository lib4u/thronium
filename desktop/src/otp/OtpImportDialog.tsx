import { InlineError } from '../shared/ui/controls';
import { Button, Input, Textarea } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import { messageRef } from '../shared/i18n/message';
import { command } from '../api';
import { Modal } from '../ui';
import type { useOtpController } from './useOtpController';
import { limits } from '../shared/api/generated/limits.ts';
export default function OtpImportDialog({ controller }: { controller: ReturnType<typeof useOtpController> }) {
  const {
    busy,
    close,
    error,
    language,
    load,
    mounted,
    readFile,
    receiveImport,
    run,
    setError,
    setImporting,
    setNotice,
    setText,
    text,
  } = controller;
  const cancel = (
    <Button type="button" className="button secondary" disabled={busy} onClick={close}>
      {translate(language, 'otp.cancel_bf4c449')}
    </Button>
  );
  return (
    <Modal
      title={translate(language, 'otp.import_authenticator_entries_d7e1b51')}
      close={close}
      closeLabel={translate(language, 'otp.cancel_bf4c449')}
      footer={
        <>
          {cancel}
          <Button
            className="button primary"
            id="otp-import-confirm"
            disabled={busy || !text.trim()}
            onClick={() =>
              void run(async () => {
                const result = await command('otpImport', { text });
                await load();
                if (mounted.current) {
                  setImporting(false);
                  setText('');
                  // A message reference: the notice is not an error to translate again.
                  setNotice(messageRef('otp.entries_added_count', { count: result.added }));
                }
              })
            }
          >
            {translate(language, 'otp.import_55fdc70')}
          </Button>
        </>
      }
    >
      <p className="field-hint">
        {translate(language, 'otp.paste_otpauth_links_base32_secrets_an_otp_json_e_f6ac458')}
      </p>
      <div className="otp-toolbar">
        <Button
          className="button secondary"
          id="otp-import-paste"
          disabled={busy}
          onClick={() =>
            void run(async () => {
              const value = await command('readClipboard');
              receiveImport(value);
            })
          }
        >
          {translate(language, 'otp.paste_text_b4acd65')}
        </Button>
        <label className="button secondary">
          {translate(language, 'otp.file_qr_image_6521283')}
          <Input
            className="sr-only"
            id="otp-import-file"
            type="file"
            disabled={busy}
            accept=".json,.txt,image/*"
            onChange={(e) => {
              void readFile(e.target.files?.[0]);
              e.target.value = '';
            }}
          />
        </label>
        <Button
          className="button secondary"
          id="otp-import-clipboard-qr"
          disabled={busy}
          onClick={() =>
            void run(async () => {
              const links = await command('readQrClipboard');
              receiveImport(links.join('\n'));
            })
          }
        >
          {translate(language, 'otp.clipboard_qr_79f86cb')}
        </Button>
        <Button
          className="button secondary"
          id="otp-import-screen-qr"
          disabled={busy}
          onClick={() =>
            void run(async () => {
              const links = await command('scanScreenQr');
              receiveImport(links.join('\n'));
            })
          }
        >
          {translate(language, 'otp.screen_qr_cb85981')}
        </Button>
      </div>
      <p className="field-hint" id="otp-import-batch-hint">
        {translate(language, 'otp.for_a_google_transfer_with_several_qr_codes_scan_6ee1dbc')}
      </p>
      <Button
        className="text-button"
        id="otp-import-clear"
        disabled={busy || !text}
        onClick={() => {
          setText('');
          setError('');
        }}
      >
        {translate(language, 'otp.clear_input_45daf68')}
      </Button>
      <Textarea
        className="text-input otp-import-text"
        id="otp-import-text"
        aria-label={translate(language, 'otp.otp_import_text_2842b01')}
        spellCheck={false}
        autoComplete="off"
        disabled={busy}
        value={text}
        maxLength={limits.maxOtpTextBytes}
        onChange={(e) => setText(e.target.value)}
      />
      {error && (
        <InlineError className="desktop-inline-error" role="alert">
          {error}
        </InlineError>
      )}
    </Modal>
  );
}
