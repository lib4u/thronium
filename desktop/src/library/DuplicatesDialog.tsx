import { useMessageState } from '../shared/i18n/react';
import { InlineError } from '../shared/ui/controls';
import { Button } from '../shared/ui/controls';
import { groupName } from '../groups/groupModel';
import type * as Wire from '../shared/api/generated/commands';
import { useEffect, useRef, useState } from 'react';
import { command, type Snapshot } from '../api';
import { Modal } from '../ui';
import { label, type Label } from '../profiles/schema';
import type { Language } from '../shared/i18n/index.ts';
const messageKeys = {
  title: 'library.remove_duplicates_4b712c5',
  open: 'library.duplicates_1612e73',
  hint: 'library.only_identical_configurations_of_the_same_type_i_3706922',
  checking: 'library.finding_duplicates_6adc9d2',
  reload: 'library.check_again_751ba18',
  cancel: 'library.cancel_bf4c449',
  remove: 'library.delete_copies_9cbe87c',
  empty: 'library.no_duplicates_available_for_removal_in_this_sele_b808cde',
  keep: 'library.keep_3bf6a9a',
  count: 'library.profiles_to_check_118b21d',
  running: 'library.active_connection_0d5c0c8',
  routing: 'library.routing_target_f9ed7a9',
  chain: 'library.chain_pool_member_a8c170c',
  otp: 'library.otp_binding_7f4925e',
  selected: 'library.selected_profile_6dd08e0',
  favorite: 'library.favorite_61eb277',
  first: 'library.first_copy_877e54b',
} satisfies Record<string, Label>;
export const duplicateText = (key: keyof typeof messageKeys, language: Language) =>
  label(messageKeys[key], language);
type Preview = Wire.DuplicatesPreview;
export default function DuplicatesDialog({
  snapshot,
  ids,
  close,
  changed,
  translateError,
}: {
  snapshot: Snapshot;
  ids: string[];
  close(): void;
  changed(): Promise<void>;
  translateError(e: unknown): string;
}) {
  const t = (key: keyof typeof messageKeys) => duplicateText(key, snapshot.preferences.language);
  const groupTitle = (id: string) => {
    const group = snapshot.groups.find((g) => g.id === id);
    return group ? groupName(group, snapshot.preferences.language) : '';
  };
  const [preview, setPreview] = useState<Preview | null>(null);
  const [error, setError] = useMessageState(snapshot.preferences.language, translateError);
  const [reload, setReload] = useState(0);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const token = useRef('');
  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError('');
    setPreview(null);
    void command('previewDuplicates', { ids })
      .then((p) => {
        if (alive) {
          token.current = p.token;
          setPreview(p);
        } else void command('discardDuplicates', { token: p.token }).catch(() => {});
      })
      .catch((e) => {
        if (alive) setError(e);
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
      if (token.current) void command('discardDuplicates', { token: token.current }).catch(() => {});
      token.current = '';
    };
  }, [ids, reload]);
  async function apply() {
    if (!preview) return;
    setBusy(true);
    setError('');
    try {
      await command('removeDuplicates', { token: preview.token });
      token.current = '';
      await changed();
      close();
    } catch (e) {
      setError(e);
      setPreview(null);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      title={t('title')}
      description={t('hint')}
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
            className="button secondary"
            id="duplicates-reload"
            disabled={busy || loading}
            onClick={() => setReload((v) => v + 1)}
          >
            {t('reload')}
          </Button>
          <Button
            className="button primary"
            id="duplicates-confirm"
            disabled={busy || loading || !preview?.count}
            onClick={() => void apply()}
          >
            {t('remove')} · {preview?.count || 0}
          </Button>
        </>
      }
    >
      <p>
        {t('count')}: {ids.length}
      </p>
      {loading && <p role="status">{t('checking')}</p>}
      {error && (
        <InlineError className="desktop-inline-error" role="alert">
          {error}
        </InlineError>
      )}
      {preview && !preview.count && <p id="duplicates-empty">{t('empty')}</p>}
      {preview?.clusters.map((cluster, i) => (
        <section className="duplicate-cluster" key={i} data-duplicate-cluster={i}>
          <h3>{groupTitle(cluster.groupId)}</h3>
          <h4>{t('keep')}</h4>
          <ul>
            {cluster.keep.map((p) => (
              <li key={p.id} data-duplicate-keep={p.id}>
                {p.name}
                {p.reason && <small>{t(p.reason)}</small>}
              </li>
            ))}
          </ul>
          <h4>{t('remove')}</h4>
          <ul>
            {cluster.remove.map((p) => (
              <li key={p.id} data-duplicate-remove={p.id}>
                {p.name}
              </li>
            ))}
          </ul>
        </section>
      ))}
    </Modal>
  );
}
