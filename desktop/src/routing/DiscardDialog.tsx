import { translate, type Language } from '../shared/i18n/index.ts';
import { ConfirmDialog } from '../ui';
import type { DiscardGuard } from './useDiscardGuard';

export default function DiscardDialog({
  guard,
  language,
  confirmId,
}: {
  guard: DiscardGuard;
  language: Language;
  confirmId?: string;
}) {
  if (!guard.asking) return null;
  return (
    <ConfirmDialog
      className="editor-discard"
      title={translate(language, 'routing.discard_changes_21dac79')}
      cancelLabel={translate(language, 'routing.keep_editing_7c292c4')}
      confirmLabel={translate(language, 'routing.discard_6febe61')}
      cancel={guard.keep}
      confirm={guard.close}
      confirmId={confirmId}
    />
  );
}
