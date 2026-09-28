import { InlineError } from '../shared/ui/controls';
import { Button, Checkbox } from '../shared/ui/controls';
import { formatDateTime } from '../shared/i18n/format.ts';
import { translate } from '../shared/i18n/index.ts';
import { errorCode } from '../shared/api/errors.ts';
import type * as Wire from '../shared/api/generated/commands';
import { useEffect, useRef, useState } from 'react';
import { command, type Snapshot } from '../api';
import { Modal } from '../ui';
import { label, type Label } from '../profiles/schema';
import LegacyReview, { type LegacyReviewData } from './LegacyReview';
import { jobActive } from '../groups/jobStatus';
import { active as probeActive } from '../probes/messages';
const messageKeys = {
  title: 'backups.backup_and_restore_312ad57',
  hint: 'backups.a_backup_contains_profiles_groups_subscriptions__d8749cc',
  save: 'backups.save_backup_1a624b8',
  open: 'backups.open_backup_3971625',
  undo: 'backups.previous_library_e64b769',
  saved: 'backups.backup_saved_07c97d4',
  restored: 'backups.library_restored_the_previous_state_is_available_d54a7ef',
  restore: 'backups.restore_library_7515808',
  warning: 'backups.this_replaces_the_current_profiles_subscriptions_a03a850',
  settings: 'backups.settings_118c0c9',
  otp: 'backups.otp_entries_8c46a29',
  autostart: 'backups.autostart_b9c171c',
  deepLinks: 'backups.handle_connection_links_70d3859',
  current: 'backups.current_f2e3580',
  incoming: 'backups.in_backup_7114cee',
  profiles: 'backups.profiles_a0a505c',
  groups: 'backups.groups_6af1c99',
  subscriptions: 'backups.subscriptions_dd3688b',
  routingProfiles: 'backups.routing_profiles_0a26067',
  icons: 'backups.icons_summary',
  date: 'backups.backup_date_0ee1504',
  acknowledge: 'backups.replace_the_current_library_with_this_backup_e48d0e5',
  apply: 'backups.restore_aed6413',
  cancel: 'backups.cancel_bf4c449',
  refresh: 'backups.refresh_review_607dabb',
  connected: 'backups.disconnect_the_vpn_before_restoring_05cd61e',
  background: 'backups.wait_for_background_updates_and_url_tests_to_fin_b7c8402',
  legacySelectedTitle: 'backups.import_selected_sections_from_throne_ecb3687',
  legacySelectedAcknowledge: 'backups.add_the_selected_sections_and_keep_the_current_a_6beff86',
  legacySettingsAcknowledge: 'backups.import_the_selected_sections_and_replace_the_lis_d177adc',
  legacyTitle: 'backups.import_profiles_from_throne_1f2b2c0',
  legacyApply: 'backups.import_55fdc70',
  legacyAfter: 'backups.after_import_b0ed9b1',
  legacyAcknowledge: 'backups.add_profiles_and_groups_using_the_current_client_30ca7d9',
  imported: 'backups.import_complete_the_previous_library_is_availabl_7519b7a',
  unknownDate: 'backups.unknown_b0d1a97',
  legacyConnected: 'backups.disconnect_the_vpn_before_importing_e876caa',
} satisfies Record<string, Label>;
type Preview = Wire.BackupPreview;
export default function BackupPanel({
  snapshot,
  changed,
  translateError,
}: {
  snapshot: Snapshot;
  changed(): Promise<void>;
  translateError(e: unknown): string;
}) {
  const language = snapshot.preferences.language;
  const t = (key: keyof typeof messageKeys) => label(messageKeys[key], language);
  const [canUndo, setCanUndo] = useState(false);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [accepted, setAccepted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState<'saved' | 'restored' | 'imported' | ''>('');
  const token = useRef('');
  const mounted = useRef(true);
  const background =
    snapshot.subscriptionJobs.some((j) => jobActive(j.status)) ||
    snapshot.urlTests?.entries.some((e) => probeActive(e.status));
  useEffect(() => {
    mounted.current = true;
    void command('backupStatus')
      .then((s) => {
        if (mounted.current) setCanUndo(s.canUndo);
      })
      .catch((e) => {
        if (mounted.current) setError(errorCode(e));
      });
    return () => {
      mounted.current = false;
      if (token.current) void command('discardBackupPreview', { token: token.current }).catch(() => {});
    };
  }, []);
  function review(p: Preview) {
    if (!mounted.current) {
      void command('discardBackupPreview', { token: p.token }).catch(() => {});
      return;
    }
    token.current = p.token;
    setPreview(p);
    setAccepted(false);
  }
  function close() {
    if (busy) return;
    if (token.current) void command('discardBackupPreview', { token: token.current }).catch(() => {});
    token.current = '';
    setPreview(null);
    setAccepted(false);
    setError('');
  }
  async function action(name: 'exportBackup' | 'readBackup' | 'previewPreviousBackup') {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const result = await command(name);
      const p = 'preview' in result ? result.preview : 'token' in result ? result : undefined;
      if (!mounted.current) {
        if (p) void command('discardBackupPreview', { token: p.token }).catch(() => {});
        return;
      }
      if (name === 'exportBackup' && 'status' in result && result.status === 'saved') setNotice('saved');
      else if (p) review(p);
    } catch (e) {
      if (mounted.current) setError(errorCode(e));
    } finally {
      if (mounted.current) setBusy(false);
    }
  }
  async function refresh() {
    setBusy(true);
    setError('');
    try {
      review(await command('refreshBackupPreview', { token: token.current }));
    } catch (e) {
      if (mounted.current) setError(errorCode(e));
    } finally {
      if (mounted.current) setBusy(false);
    }
  }
  async function scopes(next: LegacyReviewData['scopes']) {
    setBusy(true);
    setError('');
    try {
      review(await command('legacyBackupScopes', { token: token.current, scopes: next }));
    } catch (e) {
      if (mounted.current) setError(errorCode(e));
    } finally {
      if (mounted.current) setBusy(false);
    }
  }
  async function chooseResource(id: string) {
    setBusy(true);
    setError('');
    setAccepted(false);
    try {
      const result = await command('chooseLegacyResource', { token: token.current, id });
      if (result.preview) review(result.preview);
    } catch (e) {
      if (mounted.current) setError(errorCode(e));
    } finally {
      if (mounted.current) setBusy(false);
    }
  }
  async function restore() {
    setBusy(true);
    setError('');
    try {
      const importing = !!preview?.legacy;
      const status = await command('restoreBackup', { token: token.current });
      token.current = '';
      setPreview(null);
      setCanUndo(status.canUndo);
      setAccepted(false);
      setNotice(importing ? 'imported' : 'restored');
      await changed();
    } catch (e) {
      setError(errorCode(e));
      setAccepted(false);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="feature-panel desktop-section backup-panel">
      <div className="feature-panel-head">
        <h2>{t('title')}</h2>
      </div>
      <p>{t('hint')}</p>
      <div className="backup-actions">
        <Button
          className="button primary"
          id="backup-save"
          disabled={busy}
          onClick={() => void action('exportBackup')}
        >
          {t('save')}
        </Button>
        <Button
          className="button secondary"
          id="backup-open"
          disabled={busy}
          onClick={() => void action('readBackup')}
        >
          {t('open')}
        </Button>
        <Button
          className="text-button"
          id="backup-undo"
          disabled={busy || !canUndo}
          onClick={() => void action('previewPreviousBackup')}
        >
          {t('undo')}
        </Button>
      </div>
      {notice && (
        <p id="backup-notice" role="status">
          {t(notice)}
        </p>
      )}
      {error && !preview && (
        <InlineError className="desktop-inline-error" role="alert">
          {translateError(error)}
        </InlineError>
      )}
      {preview && (
        <Modal
          title={t(
            preview.legacy
              ? preview.legacy.mode === 'add-selected' || !preview.legacy.inventory.parts.profiles
                ? 'legacySelectedTitle'
                : 'legacyTitle'
              : 'restore',
          )}
          description={preview.legacy ? undefined : t('warning')}
          close={close}
          closeLabel={t('cancel')}
          footer={
            <>
              <Button className="text-button" disabled={busy} onClick={close}>
                {t('cancel')}
              </Button>
              <Button
                className="button secondary"
                id="backup-refresh"
                disabled={busy}
                onClick={() => void refresh()}
              >
                {t('refresh')}
              </Button>
              <Button
                className="button primary"
                id="backup-confirm"
                disabled={
                  busy ||
                  !accepted ||
                  !!snapshot.running ||
                  !!background ||
                  preview.legacy?.canApply === false
                }
                onClick={() => void restore()}
              >
                {t(preview.legacy ? 'legacyApply' : 'apply')}
              </Button>
            </>
          }
        >
          {preview.legacy && (
            <LegacyReview
              data={preview.legacy}
              language={language}
              busy={busy}
              changeScopes={(next) => void scopes(next)}
              translateError={translateError}
              chooseResource={(id) => void chooseResource(id)}
            />
          )}
          <p>
            {t('date')}:{' '}
            {preview.legacy
              ? preview.legacy.createdAt || t('unknownDate')
              : formatDateTime(new Date(preview.createdAt * 1000), language)}
          </p>
          <table className="backup-summary">
            <thead>
              <tr>
                <th />
                <th>{t('current')}</th>
                <th>{t(preview.legacy ? 'legacyAfter' : 'incoming')}</th>
              </tr>
            </thead>
            <tbody>
              {(
                [
                  'profiles',
                  'groups',
                  'subscriptions',
                  'routingProfiles',
                  'icons',
                  'otp',
                  'settings',
                  'autostart',
                  'deepLinks',
                ] as const
              ).map((key) => (
                <tr key={key}>
                  <th>{t(key)}</th>
                  <td data-backup-current={key}>
                    {typeof preview.current[key] === 'boolean'
                      ? preview.current[key]
                        ? translate(language, 'backups.enabled_dde9969')
                        : translate(language, 'backups.disabled_202f2f6')
                      : preview.current[key]}
                  </td>
                  <td data-backup-incoming={key}>
                    {typeof preview.incoming[key] === 'boolean'
                      ? preview.incoming[key]
                        ? translate(language, 'backups.enabled_dde9969')
                        : translate(language, 'backups.disabled_202f2f6')
                      : preview.incoming[key]}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {error && (
            <InlineError className="desktop-inline-error" role="alert">
              {translateError(error)}
            </InlineError>
          )}
          {snapshot.running && (
            <p className="field-hint" id="backup-connected">
              {t(preview.legacy ? 'legacyConnected' : 'connected')}
            </p>
          )}
          {background && <p className="field-hint">{t('background')}</p>}
          <label className="import-toggle backup-acknowledge">
            <Checkbox
              type="checkbox"
              id="backup-acknowledge"
              checked={accepted}
              disabled={busy || preview.legacy?.canApply === false}
              onChange={(e) => setAccepted(e.target.checked)}
            />
            {t(
              preview.legacy
                ? Object.values(preview.legacy.scopes.settings || {}).some(Boolean)
                  ? 'legacySettingsAcknowledge'
                  : preview.legacy.mode === 'add-selected'
                    ? 'legacySelectedAcknowledge'
                    : 'legacyAcknowledge'
                : 'acknowledge',
            )}
          </label>
        </Modal>
      )}
    </section>
  );
}
