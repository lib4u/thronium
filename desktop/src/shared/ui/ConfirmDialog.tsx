import { Modal } from './Modal';
import { Button, InlineError } from './controls';
export function ConfirmDialog({
  title,
  message,
  cancelLabel,
  confirmLabel,
  cancel,
  confirm,
  busy = false,
  error,
  confirmId,
  className = '',
}: {
  title: string;
  message?: string;
  cancelLabel: string;
  confirmLabel: string;
  cancel(): void;
  confirm(): void;
  busy?: boolean;
  error?: string;
  confirmId?: string;
  className?: string;
}) {
  return (
    <Modal
      title={title}
      description={message}
      role="alertdialog"
      initialFocus="[data-confirm-cancel]"
      className={`confirmation-modal ${className}`}
      close={() => {
        if (!busy) cancel();
      }}
      closeLabel={cancelLabel}
      footer={
        <>
          <Button
            type="button"
            className="button secondary"
            data-confirm-cancel
            autoFocus
            disabled={busy}
            onClick={cancel}
          >
            {cancelLabel}
          </Button>
          <Button
            type="button"
            className="button primary"
            loading={busy}
            data-confirm-accept
            id={confirmId}
            disabled={busy}
            onClick={confirm}
          >
            {confirmLabel}
          </Button>
        </>
      }
    >
      {error && (
        <InlineError className="desktop-inline-error" role="alert">
          {error}
        </InlineError>
      )}
    </Modal>
  );
}
