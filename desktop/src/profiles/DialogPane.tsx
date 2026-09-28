import { createContext, useContext, type ComponentType } from 'react';
import { createPortal } from 'react-dom';
import type { ModalProps } from '../ui';

export type EmbeddedEditorProps = {
  Frame?: ComponentType<ModalProps>;
  onActivity?(busy: boolean, dirty: boolean): void;
  completed?(): void;
  targetGroup?: string;
  groupChanged?(id: string): void;
};

export const PaneContext = createContext<{ active: boolean; footer: HTMLDivElement | null }>({
  active: true,
  footer: null,
});

// Both editors stay mounted when changing tabs. Only the active editor supplies
// actions to the one native dialog's fixed footer.
export function PaneFrame({ children, footer }: ModalProps) {
  const pane = useContext(PaneContext);
  return (
    <>
      {children}
      {pane.active && pane.footer && createPortal(footer, pane.footer)}
    </>
  );
}
