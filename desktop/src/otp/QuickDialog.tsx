import { Button } from '../shared/ui/controls';
import { translate, type Language } from '../shared/i18n/index.ts';
import { Modal } from '../ui';
import OtpPanel from './Panel';

export default function OtpQuickDialog({
  language,
  close,
  translateError,
}: {
  language: Language;
  close(): void;
  translateError(e: unknown): string;
}) {
  return (
    <Modal
      title={translate(language, 'otp.otp_codes_83b6c30')}
      close={close}
      closeLabel={translate(language, 'otp.close_c9a286c')}
      initialFocus="#otp-quick-search"
      className="otp-quick-dialog"
      footer={
        <Button type="button" className="button secondary" id="otp-quick-close" onClick={close}>
          {translate(language, 'otp.close_c9a286c')}
        </Button>
      }
    >
      <OtpPanel language={language} translateError={translateError} codesOnly />
    </Modal>
  );
}
