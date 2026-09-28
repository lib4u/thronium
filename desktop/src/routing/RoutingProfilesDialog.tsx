import { translate } from '../shared/i18n/index.ts';
import { InlineError, Field, Input, Button } from '../shared/ui/controls';
import { Modal, Icon, ConfirmDialog } from '../ui';
import { newProfile, type Routing } from './model';
import { limits } from '../shared/api/generated/limits.ts';
import type { RoutingPageController } from './useRoutingPage';

/** Routing profiles: rename, clone, delete and create. */
export default function RoutingProfilesDialog({
  controller,
  data,
}: {
  controller: RoutingPageController;
  data: Routing;
}) {
  const {
    language,
    tr,
    busy,
    error,
    setModal,
    nameOf,
    run,
    persist,
    deleting,
    setDeleting,
    profileName,
    setProfileName,
    profileEditing,
    setProfileEditing,
  } = controller;
  return (
    <Modal
      title={tr('profiles')}
      close={() => !busy && setModal(null)}
      closeLabel={tr('close')}
      footer={
        <Button className="button primary" disabled={busy} onClick={() => setModal(null)}>
          {tr('done')}
        </Button>
      }
    >
      {error && (
        <InlineError className="desktop-inline-error" role="alert">
          {error}
        </InlineError>
      )}
      {data.profiles.map((p) => (
        <div className="group-row route-profile-row" key={p.id}>
          <Icon name="route" />
          <strong>{nameOf(p)}</strong>
          <span>{p.rules.length}</span>
          <Button
            className="icon-button"
            data-route-rename={p.id}
            aria-label={tr('edit')}
            disabled={busy}
            onClick={() => {
              setProfileEditing(p.id);
              setProfileName(p.name);
            }}
          >
            <Icon name="edit" />
          </Button>
          <Button
            className="icon-button"
            data-route-clone={p.id}
            aria-label={tr('clone')}
            disabled={busy}
            onClick={() =>
              run(async () => {
                // A copy is the user's own profile: remote updates keep
                // writing only to the imported original.
                const { source: _source, ...own } = p;
                const clone = {
                  ...own,
                  id: crypto.randomUUID(),
                  name: translate(language, 'common.copy_name', { name: p.name }),
                  rules: p.rules.map((r) => ({ ...r, id: crypto.randomUUID() })),
                };
                await persist({ ...data, profiles: [...data.profiles, clone] });
              })
            }
          >
            <Icon name="copy" />
          </Button>
          <Button
            className="icon-button"
            data-route-delete={p.id}
            aria-label={tr('remove')}
            disabled={busy || data.profiles.length === 1}
            onClick={() => setDeleting(p.id)}
          >
            <Icon name="trash" />
          </Button>
        </div>
      ))}
      {deleting && (
        <ConfirmDialog
          title={tr('deleteProfile')}
          message={data.profiles.find((p) => p.id === deleting)?.name}
          cancelLabel={tr('cancel')}
          confirmLabel={tr('remove')}
          busy={busy}
          error={error}
          cancel={() => setDeleting('')}
          confirmId="route-profile-delete-confirm"
          confirm={() =>
            void run(async () => {
              const profiles = data.profiles.filter((p) => p.id !== deleting);
              await persist({
                ...data,
                profiles,
                active: data.active === deleting ? profiles[0].id : data.active,
              });
              setDeleting('');
            })
          }
        />
      )}
      <form
        className="desktop-group-form"
        onSubmit={(e) => {
          e.preventDefault();
          run(async () => {
            const p = newProfile(profileName.trim());
            await persist({
              ...data,
              profiles: profileEditing
                ? data.profiles.map((old) =>
                    old.id === profileEditing ? { ...old, name: profileName.trim() } : old,
                  )
                : [...data.profiles, p],
            });
            setProfileName('');
            setProfileEditing('');
          });
        }}
      >
        <Field className="feature-field" label={tr(profileEditing ? 'name' : 'newProfile')}>
          <Input
            id="route-profile-name"
            className="text-input"
            required
            maxLength={limits.maxNameBytes}
            disabled={busy}
            value={profileName}
            onChange={(e) => setProfileName(e.target.value)}
          />
        </Field>
        <Button className="button primary" id="route-profile-save" disabled={busy}>
          {tr('save')}
        </Button>
      </form>
    </Modal>
  );
}
