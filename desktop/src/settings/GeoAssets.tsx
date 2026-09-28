import { messageRef } from '../shared/i18n/message';
import { useMessageState } from '../shared/i18n/react';
import { FormActions, InlineError } from '../shared/ui/controls';
import { Button } from '../shared/ui/controls';
import { formatBytes } from '../shared/i18n/format.ts';
import { plural, type Language } from '../shared/i18n/index.ts';
import { formatDateTime } from '../shared/i18n/format.ts';
import { translate } from '../shared/i18n/index.ts';
import { errorCode } from '../shared/api/errors.ts';
import type * as Wire from '../shared/api/generated/commands';
import { useEffect, useRef, useState } from 'react';
import { command } from '../api';
type Kind = Wire.GeodataAssetKind;
type Status = Wire.GeodataAssetStatus;
type Props = {
  geoip: string;
  geosite: string;
  language: Language;
  disabled: boolean;
  busyChanged(busy: boolean): void;
  sourcesChanged(): void;
  translateError(e: unknown): string;
};
export default function GeoAssets({
  geoip,
  geosite,
  language,
  disabled,
  busyChanged,
  sourcesChanged,
  translateError,
}: Props) {
  const [statuses, setStatuses] = useState<Partial<Record<Kind, Status>>>({}),
    [errors, setErrors] = useState<Partial<Record<Kind, string>>>({}),
    [notice, setNotice] = useMessageState(language, () => '');
  const [job, setJob] = useState<{ id: string; kind: Kind } | null>(null),
    [cancelling, setCancelling] = useState(false);
  const active = useRef(true),
    pending = useRef<typeof job>(null),
    generation = useRef(0),
    urls = useRef({ geoip, geosite });
  urls.current = { geoip, geosite };
  async function refresh() {
    const epoch = ++generation.current,
      selection = urls.current;
    const results = await Promise.all(
      (['geoip', 'geosite'] as const).map(async (kind) => {
        try {
          return { kind, status: await command('xrayGeodataStatus', { kind, url: selection[kind] }) };
        } catch (error) {
          return { kind, error: translateError(error) };
        }
      }),
    );
    if (!active.current || epoch !== generation.current) return;
    setStatuses(Object.fromEntries(results.filter((r) => r.status).map((r) => [r.kind, r.status])));
    setErrors((old) => ({
      ...old,
      ...Object.fromEntries(results.filter((r) => r.error).map((r) => [r.kind, r.error])),
    }));
  }
  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
      ++generation.current;
      if (pending.current)
        void command('cancelXrayGeodataDownload', { requestId: pending.current.id }).catch(() => {});
      busyChanged(false);
    };
  }, []);
  useEffect(() => {
    ++generation.current;
    setStatuses({});
    setErrors({});
    setNotice('');
    const timer = setTimeout(() => void refresh(), 250);
    return () => clearTimeout(timer);
  }, [geoip, geosite]);
  async function download(kind: Kind) {
    if (pending.current || disabled) return;
    const request = { id: crypto.randomUUID(), kind };
    pending.current = request;
    setJob(request);
    setCancelling(false);
    busyChanged(true);
    setErrors((old) => ({ ...old, [kind]: undefined }));
    setNotice('');
    try {
      await command('downloadXrayGeodata', {
        requestId: request.id,
        selection: { kind, url: urls.current[kind] },
      });
      if (active.current)
        setNotice(messageRef('settings.downloaded_new_connections_will_use_the_updated__8541e0d'));
    } catch (e) {
      if (active.current) {
        const message = errorCode(e);
        if (message === 'geodata_cancelled') setNotice(messageRef('settings.download_cancelled_47fa2a8'));
        else setErrors((old) => ({ ...old, [kind]: translateError(e) }));
      }
    } finally {
      if (active.current) {
        await refresh();
        sourcesChanged();
        setJob(null);
        setCancelling(false);
        busyChanged(false);
      }
      pending.current = null;
    }
  }
  async function cancel() {
    if (!pending.current || cancelling) return;
    setCancelling(true);
    try {
      await command('cancelXrayGeodataDownload', { requestId: pending.current.id });
    } catch (e) {
      if (active.current && pending.current)
        setErrors((old) => ({ ...old, [pending.current!.kind]: translateError(e) }));
    } finally {
      if (active.current) setCancelling(false);
    }
  }
  return (
    <section id="xray-geo-assets" aria-label={translate(language, 'settings.xray_geodata_downloads_1cefffa')}>
      <p className="field-hint">
        {translate(language, 'settings.download_from_the_urls_above_save_settings_separ_32ff481')}
      </p>
      <div className="settings-field-grid">
        {(['geoip', 'geosite'] as const).map((kind) => {
          const status = statuses[kind],
            working = job?.kind === kind;
          return (
            <div key={kind} className="feature-field" data-geo-asset={kind}>
              <strong>{kind === 'geoip' ? 'GeoIP' : 'GeoSite'}</strong>
              <span data-geo-state={kind}>
                {working
                  ? translate(language, 'settings.downloading_cb21a11')
                  : status?.state === 'ready'
                    ? translate(language, 'settings.ready_2193711')
                    : status?.state === 'invalid'
                      ? translate(language, 'settings.invalid_cache_download_again_f51a695')
                      : status?.state === 'missing'
                        ? translate(language, 'settings.not_downloaded_de273cb')
                        : errors[kind]
                          ? translate(language, 'settings.data_unavailable_5b9e4c7')
                          : translate(language, 'settings.checking_local_data_6683652')}
              </span>
              {status?.state === 'ready' && (
                <small className="field-hint">
                  {formatBytes(status.bytes || 0, language)} ·{' '}
                  {plural(language, 'common.category_count', status.categories || 0)}
                  {status.updatedAt
                    ? ' · ' + formatDateTime(new Date(status.updatedAt * 1000), language)
                    : ''}
                </small>
              )}
              <FormActions className="feature-toolbar">
                <Button
                  type="button"
                  className="button secondary"
                  data-geo-download={kind}
                  disabled={disabled || !!job}
                  onClick={() => void download(kind)}
                >
                  {status?.state === 'ready'
                    ? translate(language, 'settings.update_9c5847c')
                    : translate(language, 'settings.download_bef2a0a')}
                </Button>
                {working && (
                  <Button
                    type="button"
                    className="button secondary"
                    data-geo-cancel={kind}
                    disabled={cancelling}
                    onClick={() => void cancel()}
                  >
                    {translate(language, 'settings.cancel_bf4c449')}
                  </Button>
                )}
              </FormActions>
              {errors[kind] && (
                <InlineError className="desktop-inline-error" role="alert">
                  {errors[kind]}
                </InlineError>
              )}
            </div>
          );
        })}
      </div>
      {notice && (
        <p role="status" className="field-hint">
          {notice}
        </p>
      )}
    </section>
  );
}
