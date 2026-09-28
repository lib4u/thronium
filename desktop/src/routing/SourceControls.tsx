import { command } from '../api';
import { label } from '../profiles/schema';
import { Icon } from '../shared/ui/Icon';
import { Button, Switch } from '../shared/ui/controls';
import type { RouteProfile, Routing } from './model';
import { useRoutingDownload } from './useRoutingDownload';
import { messageKeys as legacyMessages } from '../backups/LegacyReviewModel';
import type { Language } from '../shared/i18n/index.ts';

type Source = NonNullable<RouteProfile['source']>;
export default function SourceControls({
  profile,
  language,
  disabled,
  changed,
  refreshed,
  failed,
}: {
  profile: RouteProfile;
  language: Language;
  disabled: boolean;
  changed(source: Source): Promise<void>;
  refreshed(routing: Routing): Promise<void>;
  failed(error: unknown): void;
}) {
  const { download, pending, cancel } = useRoutingDownload(profile.id);
  const source = profile.source;
  if (!source) return null;
  // What the last update left out, with the texts of the import review.
  const notes = (source.updateNotes ?? []).filter((code): code is keyof typeof legacyMessages =>
    Object.prototype.hasOwnProperty.call(legacyMessages, code),
  );
  async function refresh() {
    try {
      const result = await download((requestId) =>
        command('refreshRoutingSource', { id: profile.id, requestId }),
      );
      if (result) await refreshed(result);
    } catch (error) {
      failed(error);
    }
  }
  return (
    <div className="route-source-banner route-source-controls">
      <span className="geo-source-label">{source.url}</span>
      <label className="route-source-auto">
        <Switch
          id="route-source-auto"
          checked={source.autoUpdate === true}
          disabled={disabled || pending}
          onChange={(event) => {
            void changed({ ...source, autoUpdate: event.target.checked }).catch(failed);
          }}
        />
        {label('routing.source_auto_update', language)}
      </label>
      <Button
        className="button"
        id="route-source-refresh"
        disabled={disabled && !pending}
        onClick={() => (pending ? cancel() : void refresh())}
      >
        <Icon name={pending ? 'x' : 'refresh'} />
        {label(pending ? 'routing.source_cancel_update' : 'routing.source_update', language)}
      </Button>
      <small>{label('routing.source_update_hint', language)}</small>
      {notes.length > 0 && (
        <ul className="route-source-notes" id="route-source-notes">
          {notes.map((code) => (
            <li key={code}>{label(legacyMessages[code], language)}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
