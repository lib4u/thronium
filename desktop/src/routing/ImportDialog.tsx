import { useMessageState } from '../shared/i18n/react';
import { useRoutingDownload } from './useRoutingDownload';
import { Section, Field } from '../shared/ui/controls';
import { InlineError } from '../shared/ui/controls';
import { Button, Input, Checkbox, Textarea } from '../shared/ui/controls';
import { plural, translate, type Language } from '../shared/i18n/index.ts';
import { useEffect, useRef, useState } from 'react';
import { command } from '../api';
import { Icon, Modal } from '../ui';
import {
  importRoutingProfile,
  isThroneRoute,
  profileCatalogs,
  remoteRouteIndex,
  type ProfileCatalogId,
  type RemoteRoute,
} from './catalog';
import { defaultTarget, newProfile, ruleTarget, targetLabel, type RouteProfile } from './model';
import { limits } from '../shared/api/generated/limits.ts';
import { errorCode } from '../shared/api/errors.ts';

// Profile downloads share the geodata downloader and its codes; here they
// name the routing profile.
const downloadErrors = {
  geodata_download_failed: 'routing.source_download_failed',
  geodata_download_rejected: 'routing.source_download_rejected',
  geodata_timeout: 'routing.source_download_timeout',
} as const;

export default function RoutingImportDialog({
  language,
  close,
  save,
  translateError,
  initialCountry,
  initialText,
}: {
  language: Language;
  close(): void;
  save(profiles: RouteProfile[], activate: boolean): Promise<void>;
  translateError(e: unknown): string;
  initialCountry?: ProfileCatalogId;
  /** A link the system opened: shown for confirmation, never activated by default. */
  initialText?: string;
}) {
  const [url, setUrl] = useState<string>(
    (profileCatalogs.find((c) => c.id === initialCountry) || profileCatalogs[0]).url,
  );
  const [text, setText] = useState('');
  const [links, setLinks] = useState<RemoteRoute[]>([]);
  const [preview, setPreview] = useState<RouteProfile | null>(null);
  const [activate, setActivate] = useState(!initialText);
  const [autoUpdate, setAutoUpdate] = useState(true);
  const [failed, setFailed] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useMessageState(language, (e) => {
    const code = errorCode(e);
    return Object.prototype.hasOwnProperty.call(downloadErrors, code)
      ? translate(language, downloadErrors[code as keyof typeof downloadErrors])
      : translateError(e);
  });
  const [origin, setOrigin] = useState('');
  const [raw, setRaw] = useState(false);
  const file = useRef<HTMLInputElement>(null);
  const request = useRoutingDownload('routing-import');
  function requestClose() {
    if (busy && !request.pending) return;
    request.cancel();
    close();
  }
  async function convert(value: string, source?: string, name?: string): Promise<RouteProfile> {
    const fallback = name || translate(language, 'routing.imported_profile_e4a0575');
    // Throne route formats are converted by the engine, which also updates them later.
    return isThroneRoute(value)
      ? {
          ...(await command('importThroneRoute', { text: value, name: fallback, url: source })),
          id: newProfile(fallback).id,
        }
      : importRoutingProfile(value, fallback, source);
  }
  async function parse(value: string, source?: string, name?: string) {
    const index = remoteRouteIndex(value);
    setText(value);
    setOrigin(source || '');
    setFailed([]);
    if (index) {
      setLinks(index);
      setPreview(null);
    } else {
      setLinks([]);
      setPreview(await convert(value, source, name));
    }
    setRaw(false);
  }
  const received = useRef(false);
  useEffect(() => {
    if (!initialText || received.current) return;
    received.current = true;
    void run(() => parse(initialText));
  }, [initialText]);
  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError('');
    try {
      await action();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  async function fetch(source = url, name?: string) {
    await run(async () => {
      const result = await request.download((requestId) =>
        command('fetchRoutingSource', { requestId, url: source.trim() }),
      );
      if (result) await parse(result.text, source, name);
    });
  }
  async function readFile(f?: File) {
    if (!f) return;
    await run(async () => {
      if (f.size > limits.maxRoutingProfileBytes) throw Error('routing_import_too_large');
      await parse(await f.text(), undefined, f.name.replace(/\.[^.]+$/, ''));
    });
  }
  async function submit() {
    if (!preview) return;
    await run(async () => {
      await save([preview], activate);
      close();
    });
  }
  /**
   * Qt's remote route link adds every listed profile with its update source.
   * Profiles that loaded are saved together; the others stay listed with the
   * reason, so they can be retried or opened one by one.
   */
  async function addAll() {
    await run(async () => {
      const added: RouteProfile[] = [];
      const left: RemoteRoute[] = [];
      let reason: unknown;
      for (const link of links) {
        try {
          const result = await request.download((requestId) =>
            command('fetchRoutingSource', { requestId, url: link.url }),
          );
          // The dialog was closed and the download cancelled.
          if (!result) return;
          const profile = await convert(result.text, link.url, link.name);
          added.push({ ...profile, source: profile.source && { ...profile.source, autoUpdate } });
        } catch (e) {
          left.push(link);
          reason ??= e;
        }
      }
      if (added.length) await save(added, false);
      if (!left.length) {
        close();
        return;
      }
      setLinks(left);
      setFailed(left.map((link) => link.name));
      throw reason;
    });
  }
  return (
    <Modal
      className="route-import-modal"
      title={translate(language, 'routing.load_routing_profile_70e4e5c')}
      description={translate(language, 'routing.adds_a_separate_profile_all_its_rules_categories_74e52ad')}
      close={requestClose}
      footer={
        <>
          <Button className="button secondary" disabled={busy && !request.pending} onClick={requestClose}>
            {translate(language, 'routing.cancel_bf4c449')}
          </Button>
          <Button
            id="route-import-save"
            className="button primary"
            disabled={busy || !preview}
            onClick={() => void submit()}
          >
            {busy
              ? translate(language, 'routing.validating_and_loading_4d25bb4')
              : translate(language, 'routing.add_profile_6b5b31a')}
          </Button>
        </>
      }
    >
      <div className="route-country-grid">
        {profileCatalogs.map((c) => (
          <Button
            className={`button ${url === c.url ? 'primary' : 'secondary'}`}
            disabled={busy}
            key={c.id}
            data-route-country={c.id}
            onClick={() => {
              setUrl(c.url);
              setPreview(null);
              setLinks([]);
              setError('');
            }}
          >
            <Icon name="globe" />
            {translate(language, c.label)}
          </Button>
        ))}
      </div>
      <Field className="feature-field" label={translate(language, 'routing.profile_source_f522fee')}>
        <Input
          id="route-import-url"
          className="text-input"
          spellCheck={false}
          value={url}
          disabled={busy}
          onChange={(e) => {
            setUrl(e.target.value);
            setPreview(null);
            setLinks([]);
          }}
        />
      </Field>
      <div className="geo-toolbar">
        <Button
          id="route-import-load"
          className="button primary"
          disabled={busy || !url.trim()}
          onClick={() => void fetch()}
        >
          <Icon name="download" />
          {translate(language, 'routing.load_c6f1183')}
        </Button>
        <Button
          id="route-import-file"
          className="button secondary"
          disabled={busy}
          onClick={() => file.current?.click()}
        >
          <Icon name="file" />
          {translate(language, 'routing.from_file_a9a95a2')}
        </Button>
        <Button
          id="route-import-paste"
          className="button secondary"
          disabled={busy}
          onClick={() => void run(async () => parse(await command('readClipboard')))}
        >
          <Icon name="clipboard" />
          {translate(language, 'routing.from_clipboard_143cdfa')}
        </Button>
        <Input
          className=""
          ref={file}
          type="file"
          accept=".json,.txt"
          hidden
          onChange={(e) => {
            void readFile(e.target.files?.[0]);
            e.target.value = '';
          }}
        />
      </div>
      <p className="geo-hint">
        {translate(language, 'routing.preset_catalog_throneproj_routeprofiles_on_githu_ad5848b')}
      </p>
      {links.length > 0 && (
        <div className="route-remote-list" aria-busy={busy}>
          {links.map((link) => (
            <Button
              className="route-remote-card"
              disabled={busy}
              key={link.url}
              data-route-remote={link.name}
              onClick={() => void fetch(link.url, link.name)}
            >
              <span>
                <strong>{link.name}</strong>
                <small>{link.url}</small>
              </span>
              <Icon name="chevron-right" />
            </Button>
          ))}
          <div className="route-remote-all">
            <label className="feature-check">
              <Checkbox
                id="route-import-auto-update"
                type="checkbox"
                disabled={busy}
                checked={autoUpdate}
                onChange={(e) => setAutoUpdate(e.target.checked)}
              />
              <span>{translate(language, 'routing.source_auto_update')}</span>
            </label>
            <Button
              id="route-import-add-all"
              className="button primary"
              disabled={busy}
              onClick={() => void addAll()}
            >
              {plural(language, 'routing.remote_routes_add_all', links.length)}
            </Button>
          </div>
          {failed.length > 0 && (
            <p className="geo-hint" id="route-import-failed">
              {translate(language, 'routing.remote_routes_failed', { names: failed.join(', ') })}
            </p>
          )}
        </div>
      )}
      {preview && (
        <section className="route-import-preview">
          <Field className="feature-field" label={translate(language, 'routing.profile_name_8f5e541')}>
            <Input
              id="route-import-name"
              className="text-input"
              maxLength={limits.maxNameBytes}
              disabled={busy}
              value={preview.name}
              onChange={(e) => setPreview({ ...preview, name: e.target.value })}
            />
          </Field>
          {origin && (
            <p className="geo-source-label">
              {translate(language, 'routing.source_64835b1')}: {origin}
            </p>
          )}
          <div className="geo-meta">
            <strong>{plural(language, 'routing.rule_count', preview.rules.length)}</strong>
            <span>
              {plural(
                language,
                'routing.rule_set_count',
                ((preview.route.rule_set as unknown[]) || []).length,
              )}
            </span>
            <span>
              {translate(language, 'routing.other_traffic_7de84c1')}:{' '}
              {targetLabel(String(preview.route.final || defaultTarget), [], language)}
            </span>
          </div>
          <ol className="route-preview-rules">
            {preview.rules.map((r) => (
              <li key={r.id}>
                <strong>{r.name}</strong>
                <span>{targetLabel(ruleTarget(r), [], language)}</span>
                <small>{JSON.stringify(r.config)}</small>
              </li>
            ))}
          </ol>
          <label className="feature-check">
            <Checkbox
              id="route-import-activate"
              type="checkbox"
              disabled={busy}
              checked={activate}
              onChange={(e) => setActivate(e.target.checked)}
            />
            <span>{translate(language, 'routing.select_this_profile_after_adding_0168bf2')}</span>
          </label>
          <p className="geo-hint">
            {translate(language, 'routing.a_running_connection_keeps_its_current_rules_unt_0c0a0d5')}
          </p>
        </section>
      )}
      <Section
        title={<>{translate(language, 'routing.paste_a_link_or_json_b368cc7')}</>}
        open={raw}
        onToggle={(e) => setRaw(e.currentTarget.open)}
        className="route-import-raw"
      >
        <Textarea
          id="route-import-text"
          className="text-input mono"
          aria-label={translate(language, 'routing.profile_contents_be42db3')}
          value={text}
          disabled={busy}
          onChange={(e) => {
            setText(e.target.value);
            setPreview(null);
            setLinks([]);
          }}
        />
        <Button
          id="route-import-preview"
          className="button secondary"
          disabled={busy || !text.trim()}
          onClick={() => void run(() => parse(text))}
        >
          {translate(language, 'routing.preview_767cef3')}
        </Button>
      </Section>
      {error && (
        <InlineError className="desktop-inline-error" role="alert">
          {error}
        </InlineError>
      )}
    </Modal>
  );
}
