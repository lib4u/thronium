import { InlineError, Field } from '../shared/ui/controls';
import { Select, Button } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import { errorCode } from '../shared/api/errors.ts';
import { useEffect, useState } from 'react';
import { command, type Snapshot } from '../api';
import ResourcesPanel from '../routing/ResourcesPanel';
import type { Routing, RouteProfile } from '../routing/model';
import { routingProfileName } from '../routing/model';
export default function RouteSettings({
  snapshot,
  changed,
  translateError,
  requested,
  navigated,
}: {
  requested?: string;
  navigated(): void;
  snapshot: Snapshot;
  changed(): Promise<void>;
  translateError(e: unknown): string;
}) {
  const [data, setData] = useState<Routing>(),
    [id, setId] = useState(''),
    [error, setError] = useState(''),
    [busy, setBusy] = useState(false),
    [drafts, setDrafts] = useState<Record<string, string>>({});
  // Follows saves from the Routing page, the tray and other windows; drafts
  // stay in their own state and the chosen profile stays while it exists.
  useEffect(() => {
    if (busy) return;
    let live = true;
    void command('routing')
      .then((v) => {
        if (!live) return;
        setData(v);
        setId((old) => (v.profiles.some((p) => p.id === old) ? old : v.active));
      })
      .catch((e) => live && setError(errorCode(e)));
    return () => {
      live = false;
    };
  }, [snapshot.routing.revision, busy]);
  const profile = data?.profiles.find((p) => p.id === id);
  async function update(profile: RouteProfile) {
    if (!data) return;
    setBusy(true);
    setError('');
    try {
      await command('checkRouting', profile);
      const saved = await command('saveRouting', {
        ...data,
        profiles: data.profiles.map((p) => (p.id === profile.id ? profile : p)),
      });
      setData(saved);
      await changed();
    } catch (e) {
      setError(errorCode(e));
      throw e;
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <span hidden data-navigation-locked={busy || Object.keys(drafts).length > 0 || undefined} />
      <Field
        className="feature-field settings-scope"
        label={translate(snapshot.preferences.language, 'settings.routing_profile_fa1594a')}
      >
        <Select
          className="text-input"
          id="settings-dns-profile"
          disabled={busy}
          value={id}
          onChange={(e) => setId(e.target.value)}
        >
          {data?.profiles.map((p) => (
            <option key={p.id} value={p.id}>
              {routingProfileName(p, snapshot.preferences.language)}
            </option>
          ))}
        </Select>
        <small>
          {translate(
            snapshot.preferences.language,
            'settings.dns_is_saved_for_the_selected_routing_profile_4d3d6e1',
          )}
        </small>
      </Field>
      {error && (
        <InlineError role="alert" className="desktop-inline-error">
          {translateError(error)}{' '}
          <Button
            className="text-button"
            onClick={() => {
              void command('routing').then(
                (v) => {
                  setData(v);
                  setError('');
                  setDrafts({});
                },
                (e) => setError(errorCode(e)),
              );
            }}
          >
            {translate(snapshot.preferences.language, 'settings.reload_saved_dns_ec76e49')}
          </Button>
        </InlineError>
      )}
      {profile && (
        <ResourcesPanel
          key={profile.id}
          requested={requested}
          navigated={navigated}
          kind="dns"
          profile={profile}
          profiles={snapshot.profiles}
          language={snapshot.preferences.language}
          busy={busy}
          rawDraft={drafts[profile.id]}
          setRawDraft={(v) =>
            setDrafts((old) => {
              const next = { ...old };
              if (v === undefined) delete next[profile.id];
              else next[profile.id] = v;
              return next;
            })
          }
          update={update}
          translateError={translateError}
        />
      )}
    </>
  );
}
