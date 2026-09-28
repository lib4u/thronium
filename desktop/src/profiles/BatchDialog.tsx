import { InlineError, Field } from '../shared/ui/controls';
import { Button, Select } from '../shared/ui/controls';
import { errorCode } from '../shared/api/errors.ts';
import { useState } from 'react';
import { command, type Snapshot } from '../api';
import { Modal } from '../ui';
import { groupName, personalGroupId } from '../groups/groupModel';
import { label, type Label } from './schema';
import type { Language } from '../shared/i18n/index.ts';

const messageKeys = {
  select: 'profiles.select_multiple_7da743b',
  done: 'profiles.done_239ae08',
  visible: 'profiles.select_visible_a231c7e',
  selected: 'profiles.selected_f19a934',
  move: 'profiles.move_to_group_7a9c9f4',
  remove: 'profiles.delete_selected_4308c2c',
  test: 'profiles.test_selected_de35e04',
  ip: 'profiles.check_ip_selected',
  speed: 'profiles.test_speed_selected',
  cancel: 'profiles.cancel_bf4c449',
  confirmDelete: 'profiles.delete_55f670b',
  confirmMove: 'profiles.move_b380b49',
  deleteHint: 'profiles.the_selected_profiles_will_be_deleted_together_c_88678e2',
  moveHint: 'profiles.names_settings_and_favorites_will_be_preserved_m_42b152e',
  missing: 'profiles.profile_no_longer_exists_13cc43b',
} satisfies Record<string, Label>;
export const batchText = (key: keyof typeof messageKeys, language: Language) =>
  label(messageKeys[key], language);

export default function BatchDialog({
  snapshot,
  ids,
  operation,
  close,
  changed,
  completed,
  translateError,
}: {
  snapshot: Snapshot;
  ids: string[];
  operation: 'move' | 'remove';
  close(): void;
  changed(): Promise<void>;
  completed(groupId?: string): void;
  translateError(e: unknown): string;
}) {
  const t = (key: keyof typeof messageKeys) => batchText(key, snapshot.preferences.language);
  const [target, setTarget] = useState<string>(personalGroupId);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function apply() {
    setBusy(true);
    setError('');
    try {
      await command(operation === 'move' ? 'moveProfiles' : 'deleteProfiles', { ids, groupId: target });
      await changed();
      completed(operation === 'move' ? target : undefined);
      close();
    } catch (e) {
      setError(errorCode(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      className="desktop-batch-modal"
      title={t(operation)}
      description={t(operation === 'move' ? 'moveHint' : 'deleteHint')}
      close={() => {
        if (!busy) close();
      }}
      closeLabel={t('cancel')}
      footer={
        <>
          <Button className="text-button" disabled={busy} onClick={close}>
            {t('cancel')}
          </Button>
          <Button
            className="button primary"
            id="batch-confirm"
            disabled={busy || !ids.length}
            onClick={() => void apply()}
          >
            {t(operation === 'move' ? 'confirmMove' : 'confirmDelete')} · {ids.length}
          </Button>
        </>
      }
    >
      {error && (
        <InlineError className="desktop-inline-error" role="alert">
          {translateError(error)}
        </InlineError>
      )}
      {operation === 'move' && (
        <Field className="feature-field" label={t('move')}>
          <Select
            className="text-input"
            id="batch-group"
            disabled={busy}
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          >
            {snapshot.groups.map((g) => (
              <option key={g.id} value={g.id}>
                {groupName(g, snapshot.preferences.language)}
              </option>
            ))}
          </Select>
        </Field>
      )}
      <p>
        {t('selected')}: {ids.length}
      </p>
      <ul className="batch-profile-list">
        {ids.map((id) => (
          <li key={id}>{snapshot.profiles.find((p) => p.id === id)?.name || t('missing')}</li>
        ))}
      </ul>
    </Modal>
  );
}
