import { DialogHeader, DialogBody, DialogFooter } from './controls';
import { IconButton } from './controls';
import { useTranslation } from '../i18n/react';
import { createContext, useContext, useEffect, useId, useRef, type ReactNode, type Ref } from 'react';
import { createPortal } from 'react-dom';

const ModalDepth = createContext(0);
export type ModalProps = {
  title: string;
  description?: string;
  children?: ReactNode;
  footer?: ReactNode;
  navigation?: ReactNode;
  footerRef?: Ref<HTMLDivElement>;
  inert?: boolean;
  close(): void;
  className?: string;
  closeLabel?: string;
  role?: 'dialog' | 'alertdialog';
  initialFocus?: string;
};
export function Modal({
  title,
  description,
  children,
  footer,
  navigation,
  footerRef,
  inert,
  close,
  className = '',
  closeLabel,
  role = 'dialog',
  initialFocus,
}: ModalProps) {
  const t = useTranslation();
  const closeText = closeLabel || t('common.close');
  const ref = useRef<HTMLDialogElement>(null);
  const depth = useContext(ModalDepth);
  const id = useId();
  const dialogId = depth ? `modal-${id}` : 'main-modal';
  const titleId = depth ? `modal-title-${id}` : 'modal-title';
  const descriptionId = `modal-description-${id}`;
  useEffect(() => {
    const dialog = ref.current!,
      previous = document.activeElement;
    dialog.showModal();
    if (initialFocus) dialog.querySelector<HTMLElement>(initialFocus)?.focus({ preventScroll: true });
    return () => {
      dialog.close();
      // WebKit may restore focus while the parent editor is still inert.
      // Wait for React to finish removing the confirmation and its inert state.
      queueMicrotask(() => {
        const open = [...document.querySelectorAll<HTMLDialogElement>('dialog:modal')].filter(
          (d) => d !== dialog,
        );
        const parent = open[open.length - 1];
        if (parent?.contains(document.activeElement)) return;
        if (
          previous instanceof HTMLElement &&
          previous.isConnected &&
          !previous.closest('[inert]') &&
          (!parent || parent.contains(previous))
        )
          previous.focus({ preventScroll: true });
        else
          parent
            ?.querySelector<HTMLElement>(
              'button:not(:disabled), input:not(:disabled), textarea:not(:disabled), select:not(:disabled)',
            )
            ?.focus({ preventScroll: true });
      });
    };
  }, []);
  // Native top-layer dialogs provide focus containment and make every lower
  // dialog inert. A portal keeps positioning independent of scrolling editors.
  return createPortal(
    <ModalDepth.Provider value={depth + 1}>
      <dialog
        ref={ref}
        role={role}
        inert={inert || undefined}
        className={`modal desktop-modal ${className}`}
        id={dialogId}
        aria-labelledby={titleId}
        aria-describedby={description ? descriptionId : undefined}
        onCancel={(e) => {
          e.preventDefault();
          e.stopPropagation();
          close();
        }}
      >
        <DialogHeader className="modal-head">
          <div>
            <h2 id={titleId}>{title}</h2>
            {description && <p id={descriptionId}>{description}</p>}
          </div>
          <IconButton icon="x" label={closeText} onClick={close} />
        </DialogHeader>
        {navigation}
        {children && <DialogBody className="modal-body">{children}</DialogBody>}
        {footer && (
          <DialogFooter className="modal-footer" ref={footerRef}>
            {footer}
          </DialogFooter>
        )}
      </dialog>
    </ModalDepth.Provider>,
    document.body,
  );
}
