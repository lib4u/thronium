import ProfileForm from './ProfileForm';
import { Button } from '../shared/ui/controls';
import { Icon, ConfirmDialog } from '../ui';
import type { useProfileEditor } from './useProfileEditor';
export default function ProfileEditorView({
  controller,
}: {
  controller: ReturnType<typeof useProfileEditor>;
}) {
  const {
    Frame,
    busy,
    close,
    confirmClose,
    confirmKey,
    confirmReload,
    draft,
    error,
    generateKey,
    inUse,
    reload,
    requestClose,
    setConfirmClose,
    setConfirmKey,
    setConfirmReload,
    submit,
    t,
    tr,
  } = controller;
  return (
    <Frame
      title={t(draft?.id ? 'editProfile' : 'newProfile')}
      description={tr('hint')}
      close={requestClose}
      closeLabel={t('close')}
      initialFocus="#profile-name"
      className="editor-modal compact-profile-modal"
      footer={
        <>
          <Button
            className="button secondary"
            type="button"
            onClick={() => void submit(true)}
            disabled={busy || confirmClose}
          >
            {t(busy ? 'checking' : 'check')}
          </Button>
          <span className="filter-spacer" />
          <Button className="text-button" type="button" disabled={busy} onClick={requestClose}>
            {t('cancel')}
          </Button>
          <Button
            className="button primary"
            form="profile-editor"
            type="submit"
            disabled={busy || confirmClose || inUse}
          >
            <Icon name="check" />
            {t('save')}
          </Button>
        </>
      }
    >
      {confirmClose && (
        <ConfirmDialog
          className="editor-discard"
          title={tr('discardTitle')}
          message={tr('discardHint')}
          cancelLabel={tr('keepEditing')}
          confirmLabel={tr('discard')}
          cancel={() => setConfirmClose(false)}
          confirm={close}
        />
      )}
      {confirmReload && (
        <ConfirmDialog
          title={t('profileReloadConfirm')}
          cancelLabel={tr('keepEditing')}
          confirmLabel={t('profileReload')}
          busy={busy}
          error={error}
          cancel={() => setConfirmReload(false)}
          confirm={() => void reload()}
        />
      )}
      {confirmKey && (
        <ConfirmDialog
          title={tr('replaceKey')}
          cancelLabel={t('cancel')}
          confirmLabel={tr('generate')}
          busy={busy}
          error={error}
          cancel={() => setConfirmKey(false)}
          confirm={() => void generateKey()}
        />
      )}
      <ProfileForm controller={controller} />
    </Frame>
  );
}
