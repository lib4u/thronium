import type { Dispatch, SetStateAction } from 'react';
import { command, type Profile } from '../api';
import type { ModalState } from '../AppModel';
import { translate } from '../shared/i18n/index.ts';
export function useLibraryActions({
  perform,
  setModal,
  language,
}: {
  perform(action: () => Promise<unknown>, done?: () => void): Promise<void>;
  setModal: Dispatch<SetStateAction<ModalState>>;
  language: string;
}) {
  async function configure(profile: Profile) {
    await perform(async () => {
      const draft = await command('profile', { id: profile.id });
      setModal({ type: 'configuration', draft });
    });
  }
  async function edit(profile: Profile) {
    await perform(async () => {
      const draft = await command('profile', { id: profile.id });
      setModal({ type: 'editor', draft });
    });
  }
  async function clone(profile: Profile) {
    await perform(
      async () => {
        const draft = await command('profile', { id: profile.id });
        await command('saveProfile', {
          ...draft,
          id: undefined,
          name: translate(language, 'common.copy_name', { name: draft.name }),
        });
      },
      () => setModal(null),
    );
  }
  return { configure, edit, clone };
}
