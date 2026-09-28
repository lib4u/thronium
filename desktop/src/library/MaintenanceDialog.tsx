import { useMessageState } from '../shared/i18n/react';
import { Button, InlineError } from '../shared/ui/controls';
import { useEffect, useRef, useState } from 'react';
import { command, type Snapshot } from '../api';
import { errorCode } from '../shared/api/errors.ts';
import { Modal } from '../ui';
import { label, type Label } from '../profiles/schema';
import { translate, type Language } from '../shared/i18n/index.ts';
import { candidateKind, PREVIEW, profilesById, type MaintenanceKind } from './maintenance';

const messageKeys = {
  unavailable: 'library.maintenance_unavailable',
  invalid: 'library.maintenance_invalid',
  insecure: 'library.maintenance_insecure',
  resolve: 'library.maintenance_resolve',
  resetTraffic: 'library.maintenance_reset_traffic',
  unavailableHint: 'library.maintenance_unavailable_hint',
  invalidHint: 'library.maintenance_invalid_hint',
  insecureHint: 'library.maintenance_insecure_hint',
  resolveHint: 'library.maintenance_resolve_hint',
  checking: 'library.maintenance_checking',
  none: 'library.maintenance_none',
  noNames: 'library.maintenance_no_names',
  remove: 'library.maintenance_remove',
  replace: 'library.maintenance_replace',
  cancel: 'library.cancel_bf4c449',
  count: 'library.profiles_to_check_118b21d',
} satisfies Record<string, Label>;
export const maintenanceText = (key: keyof typeof messageKeys, language: Language) =>
  label(messageKeys[key], language);
export default function MaintenanceDialog({
  snapshot,
  kind,
  ids,
  close,
  changed,
  notify,
  translateError,
}: {
  snapshot: Snapshot;
  kind: MaintenanceKind;
  ids: string[];
  close(): void;
  changed(): Promise<void>;
  notify(text: string): void;
  translateError(e: unknown): string;
}) {
  const language = snapshot.preferences.language;
  const t = (key: keyof typeof messageKeys) => maintenanceText(key, language);
  const [found, setFound] = useState<string[] | null>(null);
  const [progress, setProgress] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useMessageState(language, translateError);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  // The engine decides on stored results and configurations; only invalid
  // servers need the core, which is asked about one server at a time.
  useEffect(() => {
    void (async () => {
      try {
        const selection = candidateKind(kind);
        if (selection) {
          const result = await command('maintenanceCandidates', { kind: selection, ids });
          if (alive.current) setFound(result.ids);
          return;
        }
        const invalid: string[] = [];
        for (const [index, id] of ids.entries()) {
          if (!alive.current) return;
          setProgress(index + 1);
          try {
            const profile = await command('profile', { id });
            await command('checkProfile', {
              id: profile.id,
              name: profile.name,
              groupId: profile.groupId,
              kind: profile.kind,
              config: profile.config,
            });
          } catch (e) {
            if (errorCode(e) === 'profile_not_found') continue;
            invalid.push(id);
          }
        }
        if (alive.current) setFound(invalid);
      } catch (e) {
        if (alive.current) {
          setError(e);
          setFound([]);
        }
      }
    })();
    // The dialog works on the selection it opened with; a later snapshot must
    // not restart the run.
  }, []);
  const listed = profilesById(snapshot.profiles, found ?? []);
  const hint = t(
    kind === 'unavailable'
      ? 'unavailableHint'
      : kind === 'insecure'
        ? 'insecureHint'
        : kind === 'invalid'
          ? 'invalidHint'
          : 'resolveHint',
  );
  async function apply() {
    setBusy(true);
    setError('');
    try {
      if (kind === 'resolve') {
        const result = await command('resolveProfileAddresses', { ids: listed.map((p) => p.id) });
        notify(translate(language, 'library.maintenance_resolve_done', result));
      } else {
        const result = await command('deleteProfiles', { ids: listed.map((p) => p.id) });
        notify(`${t(kind)} · ${result.count}`);
      }
      await changed();
      close();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      title={t(kind)}
      description={hint}
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
            id="maintenance-confirm"
            disabled={busy || found === null || !listed.length}
            onClick={() => void apply()}
          >
            {t(kind === 'resolve' ? 'replace' : 'remove')} · {listed.length}
          </Button>
        </>
      }
    >
      <p>
        {t('count')}: {ids.length}
      </p>
      {found === null && (
        <p role="status" id="maintenance-progress">
          {t('checking')}: {progress} / {ids.length}
        </p>
      )}
      {found !== null && !listed.length && (
        <p id="maintenance-empty">{t(kind === 'resolve' ? 'noNames' : 'none')}</p>
      )}
      {listed.length > 0 && (
        <ul className="maintenance-list" id="maintenance-list">
          {listed.slice(0, PREVIEW).map((p) => (
            <li key={p.id} data-maintenance-profile={p.id}>
              <strong>{p.name}</strong>
              <small>
                {p.protocol} · {p.address}
              </small>
            </li>
          ))}
          {listed.length > PREVIEW && (
            <li>{translate(language, 'library.maintenance_more', { count: listed.length - PREVIEW })}</li>
          )}
        </ul>
      )}
      {error && (
        <InlineError className="desktop-inline-error" role="alert">
          {error}
        </InlineError>
      )}
    </Modal>
  );
}
