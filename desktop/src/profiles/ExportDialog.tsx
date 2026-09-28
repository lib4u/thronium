import { useMessageState } from '../shared/i18n/react';
import { InlineError, Field } from '../shared/ui/controls';
import { Button, Select } from '../shared/ui/controls';
import { sourceLanguage, translate, type Language } from '../shared/i18n/index.ts';
import { CodedError, errorCode } from '../shared/api/errors.ts';
import { exportedProfiles, qrPreview } from '../shared/api/transfers';
import { useEffect, useRef, useState } from 'react';
import { command, type Snapshot } from '../api';
import { Modal, Icon } from '../ui';
import { label, type Label } from './schema';
import { shareProfiles, profileBundle, type SharedProfile, type ShareFormat } from './share';
import { createArchive, planArchive, type ArchiveFormat } from './archives';
import './Share.css';

const messageKeys = {
  'wireguard-archive': 'profiles.wireguard_amneziawg_files_zip_f52133b',
  'qr-archive': 'profiles.connection_qr_codes_png_in_zip_d31549c',
  wgArchiveHint: 'profiles.wireguard_archive_hint',
  qrArchiveHint: 'profiles.qr_archive_hint',
  files: 'profiles.file_list_2fd5c8e',
  preparing: 'profiles.preparing_files_f937051',
  stop: 'profiles.stop_preparing_617fb47',
  links: 'profiles.connection_links_uri_77c818e',
  'thronium-link': 'profiles.thronium_link_complete_profiles_b3852cc',
  'throne-link': 'profiles.throne_link_json',
  throneHint: 'profiles.throne_link_hint',
  wireguard: 'profiles.wireguard_amneziawg_conf_8cfd63e',
  linksHint: 'profiles.for_clients_supporting_this_protocol_and_its_uri_a51c84a',
  portableHint: 'profiles.for_thronium_preserves_complete_source_json_dns__76e68ee',
  wgHint: 'profiles.one_wireguard_or_amneziawg_profile_with_every_pe_1cc60ec',
  qr: 'profiles.show_qr_code_3e75788',
  qrHide: 'profiles.hide_qr_code_233c197',
  qrCopy: 'profiles.copy_qr_image_296712f',
  qrSave: 'profiles.save_qr_as_png_ea11c0b',
  qrHint: 'profiles.scan_with_a_compatible_client_the_image_contains_d393c23',

  chainHint: 'profiles.chain_and_pool_members_are_included_automaticall_1676ea5',
  title: 'profiles.export_profiles_f4ca8dd',
  hint: 'profiles.choose_the_format_and_where_to_save_the_selected_81f7f34',
  format: 'profiles.format_e00adff',
  profiles: 'profiles.thronium_profiles_json_a4fa680',
  configurations: 'profiles.core_configurations_json_e576a4b',
  profilesHint: 'profiles.preserves_names_configuration_types_and_all_sett_d8a90c0',
  configurationsHint: 'profiles.original_configurations_without_library_names_or_0e00afa',
  secrets: 'profiles.the_export_includes_passwords_and_private_keys_s_7099ce2',
  copy: 'profiles.copy_e2d2d65',
  file: 'profiles.save_to_file_ed92b09',
  reveal: 'profiles.show_content_3d16d49',
  hide: 'profiles.hide_content_339d260',
  close: 'profiles.close_c9a286c',
  copied: 'profiles.copied_to_clipboard_4cddbf1',
  saved: 'profiles.file_saved_391e905',
  selected: 'profiles.selected_f19a934',
} satisfies Record<string, Label>;
export const exportText = (key: keyof typeof messageKeys, language: Language) =>
  label(messageKeys[key], language);

type Format = 'profiles' | 'configurations' | ShareFormat | ArchiveFormat;
export default function ExportDialog({
  snapshot,
  ids = [],
  drafts,
  language: suppliedLanguage,
  close,
  translateError,
}: {
  snapshot?: Snapshot;
  ids?: string[];
  drafts?: SharedProfile[];
  language?: Language;
  close(): void;
  translateError(e: unknown): string;
}) {
  const language = suppliedLanguage || snapshot?.preferences.language || sourceLanguage;
  const t = (key: keyof typeof messageKeys) => exportText(key, language);
  const selected = drafts || snapshot?.profiles.filter((p) => ids.includes(p.id)) || [];
  const hasChain = selected.some((p) => p.kind === 'chain' || p.kind === 'auto-selector');
  const hasExternal = selected.some((p) => p.kind === 'external-core');
  const archiveUnsupported = selected.some((p) => !['sing-box-outbound', 'xray-outbound'].includes(p.kind));
  const [format, setFormat] = useState<Format>(
    drafts && !hasExternal
      ? drafts.some((p) => p.vpnPolicy != null)
        ? 'thronium-link'
        : 'links'
      : 'profiles',
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useMessageState(language, (value) => explain(value));
  const [status, setStatus] = useState('');
  const [preview, setPreview] = useState<string | null>(null);
  const [qr, setQr] = useState<{ image: string; text: string } | null>(null);
  const qrImage = useRef<HTMLImageElement>(null);
  const archiveTask = useRef<AbortController | null>(null);
  const [archiveProgress, setArchiveProgress] = useState<{ done: number; total: number }>();
  const isArchive = format === 'wireguard-archive' || format === 'qr-archive';
  useEffect(() => () => archiveTask.current?.abort(), []);
  useEffect(() => {
    if (!qr) return;
    const show = () => qrImage.current?.scrollIntoView({ block: 'center' });
    show();
    window.addEventListener('resize', show);
    return () => window.removeEventListener('resize', show);
  }, [qr]);
  const canQr =
    format === 'thronium-link' || (['links', 'throne-link'].includes(format) && selected.length === 1);
  async function content(): Promise<string> {
    const profiles: SharedProfile[] = drafts || (await exportedProfiles(ids));
    if (format === 'profiles') return JSON.stringify(profileBundle(profiles), null, 2);
    if (format === 'configurations' && profiles.some((p) => p.vpnPolicy != null))
      throw Error('vpn_policy_export_requires_bundle');
    if (format === 'configurations')
      return JSON.stringify(
        profiles.length === 1 ? profiles[0].config : profiles.map((p) => p.config),
        null,
        2,
      );
    if (format === 'wireguard-archive' || format === 'qr-archive')
      return planArchive(profiles, format)
        .map((p) => p.name)
        .join('\n');
    return shareProfiles(profiles, format);
  }
  function explain(e: unknown): string {
    const code = errorCode(e);
    if (e instanceof CodedError && code === 'share_fields')
      return translate(language, 'profiles.share_fields_lost', e.params);
    const errors: Record<string, Label> = {
      archive_invalid_selection: 'profiles.archive_selection_invalid',
      archive_invalid_data: 'profiles.could_not_prepare_the_archive_try_again_12f9851',
      archive_too_large: 'profiles.archive_too_large',
      archive_cancelled: 'profiles.archive_preparation_was_cancelled_8522f89',
      vpn_policy_export_requires_bundle: 'profiles.use_a_thronium_link_or_thronium_profiles_json_to_4317a38',
      share_unsupported: 'profiles.use_a_thronium_link_or_json_to_preserve_this_con_5eb8e0e',
      share_single_peer: 'profiles.a_native_link_supports_one_wireguard_peer_use_a__33ae541',
      share_wireguard_only: 'profiles.select_one_wireguard_or_amneziawg_profile_for_co_ec17e79',
      share_invalid_address: 'profiles.check_the_server_address_and_port_aa6280c',
      share_invalid_wireguard: 'profiles.check_the_wireguard_fields_line_breaks_and_comme_853340c',
      qr_export_too_large: 'profiles.this_link_is_too_large_for_one_qr_code_copy_the__294336a',
    };
    return errors[code] ? label(errors[code], language) : translateError(code);
  }
  async function deliver(destination: 'clipboard' | 'file' | 'preview', image = false) {
    if (busy) return;
    setBusy(true);
    setError('');
    setStatus('');
    try {
      if (isArchive) {
        const profiles: SharedProfile[] = drafts || (await exportedProfiles(ids));
        const entries = planArchive(profiles, format);
        if (destination === 'preview') {
          setPreview(entries.map((e) => e.name).join('\n'));
          return;
        }
        if (destination !== 'file') throw Error('invalid_export_destination');
        const task = new AbortController();
        archiveTask.current = task;
        setArchiveProgress({ done: 0, total: entries.length });
        const data = await createArchive(
          entries,
          format,
          qrPreview,
          (done, total) => setArchiveProgress({ done, total }),
          task.signal,
        );
        if (task.signal.aborted) throw Error('archive_cancelled');
        setArchiveProgress(undefined);
        const result = await command('exportArchive', { data, format });
        setStatus(result.status);
      } else if (image) {
        const text = qr?.text || (await content());
        const result = await command('exportQr', {
          text,
          destination,
        });
        if (destination === 'preview' && result.image) setQr({ image: result.image, text });
        else setStatus(result.status || '');
      } else {
        const result =
          !drafts && (format === 'profiles' || format === 'configurations')
            ? await command('exportProfiles', {
                ids,
                format,
                destination,
              })
            : await command('exportSharedText', {
                text: await content(),
                format,
                destination,
              });
        if (destination === 'preview') setPreview(result.text || '');
        else setStatus(result.status || '');
      }
    } catch (e) {
      setError(e);
    } finally {
      archiveTask.current = null;
      setArchiveProgress(undefined);
      setBusy(false);
    }
  }
  const hint =
    format === 'wireguard-archive'
      ? 'wgArchiveHint'
      : format === 'qr-archive'
        ? 'qrArchiveHint'
        : format === 'links'
          ? 'linksHint'
          : format === 'throne-link'
            ? 'throneHint'
            : format === 'thronium-link'
              ? 'portableHint'
              : format === 'wireguard'
                ? 'wgHint'
                : format === 'profiles'
                  ? 'profilesHint'
                  : 'configurationsHint';
  return (
    <Modal
      className="desktop-import-modal"
      title={t('title')}
      description={t('hint')}
      close={() => {
        if (!busy) close();
      }}
      closeLabel={t('close')}
      footer={
        <>
          <Button className="text-button" disabled={busy} onClick={close}>
            {t('close')}
          </Button>
          <Button
            className="button secondary"
            id="export-copy"
            disabled={busy || !selected.length || isArchive}
            onClick={() => void deliver('clipboard')}
          >
            <Icon name="copy" />
            {t('copy')}
          </Button>
          <Button
            className="button primary"
            id="export-save"
            disabled={busy || !selected.length}
            onClick={() => void deliver('file')}
          >
            <Icon name="file" />
            {t('file')}
          </Button>
        </>
      }
    >
      {error && (
        <InlineError className="desktop-inline-error" role="alert">
          {error}
        </InlineError>
      )}
      {(status === 'copied' || status === 'saved') && (
        <p className="import-valid" id="export-status" role="status">
          {t(status)}
        </p>
      )}
      <Field className="feature-field" label={t('format')}>
        <Select
          id="export-format"
          className="text-input"
          value={format}
          disabled={busy}
          onChange={(e) => {
            setFormat(e.target.value as Format);
            setPreview(null);
            setQr(null);
            setStatus('');
            setError('');
          }}
        >
          {(
            [
              'profiles',
              'configurations',
              'links',
              'throne-link',
              'thronium-link',
              'wireguard',
              'wireguard-archive',
              'qr-archive',
            ] as const
          ).map((f) => (
            <option
              key={f}
              value={f}
              disabled={
                (hasExternal && !['profiles', 'configurations'].includes(f)) ||
                (hasChain &&
                  [
                    'configurations',
                    'links',
                    'throne-link',
                    'wireguard',
                    'wireguard-archive',
                    'qr-archive',
                  ].includes(f)) ||
                (archiveUnsupported && ['wireguard-archive', 'qr-archive'].includes(f)) ||
                (f === 'wireguard' && selected.length !== 1)
              }
            >
              {t(f)}
            </option>
          ))}
        </Select>
      </Field>
      {archiveProgress && (
        <p role="status" id="archive-progress">
          {t('preparing')}: {archiveProgress.done} / {archiveProgress.total}{' '}
          <Button
            type="button"
            id="archive-cancel"
            className="text-button"
            onClick={() => archiveTask.current?.abort()}
          >
            {t('stop')}
          </Button>
        </p>
      )}
      {hasChain && <p className="field-hint">{t('chainHint')}</p>}
      <p className="field-hint">{t(hint)}</p>
      <p>
        {t('selected')}: {selected.length}
      </p>
      <ul className="batch-profile-list">
        {selected.map((p, i) => (
          <li key={i}>{p.name}</li>
        ))}
      </ul>
      <p className="field-hint">
        {translate(language, 'profiles.group_dns_and_subscription_routing_are_excluded__5b2ffbf')}
      </p>
      <p className="field-hint">{t('secrets')}</p>
      <div className="share-actions">
        <Button
          className="text-button"
          id="export-reveal"
          disabled={busy}
          onClick={() => (preview === null ? void deliver('preview') : setPreview(null))}
        >
          {t(preview === null ? (isArchive ? 'files' : 'reveal') : 'hide')}
        </Button>
        {canQr && (
          <Button
            className="text-button"
            id="export-qr"
            disabled={busy}
            onClick={() => (qr ? setQr(null) : void deliver('preview', true))}
          >
            {t(qr ? 'qrHide' : 'qr')}
          </Button>
        )}
      </div>
      {qr && (
        <div className="share-qr">
          <img
            ref={qrImage}
            id="export-qr-image"
            src={qr.image}
            onLoad={(e) => e.currentTarget.scrollIntoView({ block: 'center' })}
            alt={translate(language, 'profiles.connection_link_as_qr_code_05fc3f1')}
          />
          <p className="field-hint">{t('qrHint')}</p>
          <div className="share-actions">
            <Button
              className="button secondary"
              id="export-qr-copy"
              disabled={busy}
              onClick={() => void deliver('clipboard', true)}
            >
              {t('qrCopy')}
            </Button>
            <Button
              className="button secondary"
              id="export-qr-save"
              disabled={busy}
              onClick={() => void deliver('file', true)}
            >
              {t('qrSave')}
            </Button>
          </div>
        </div>
      )}
      {preview !== null && (
        <pre className="import-json mono" id="export-content">
          {preview}
        </pre>
      )}
    </Modal>
  );
}
