import { useMessageState } from '../shared/i18n/react';
import { InlineError } from '../shared/ui/controls';
import { translate, type Language } from '../shared/i18n/index.ts';
import type * as Wire from '../shared/api/generated/commands';
import { useEffect, useState } from 'react';
import { command } from '../api';
type Location = Wire.StorageLocation;
export default function StorageLocation({
  language,
  sealing,
  translateError,
}: {
  language: Language;
  sealing: Wire.Snapshot['sealing'];
  translateError(e: unknown): string;
}) {
  const [location, setLocation] = useState<Location>(),
    [error, setError] = useMessageState(language, translateError);
  useEffect(() => {
    let active = true;
    void command('storageLocation')
      .then((value) => {
        if (active) setLocation(value);
      })
      .catch((e) => {
        if (active) setError(e);
      });
    return () => {
      active = false;
    };
  }, []);
  return (
    <section className="settings-special" id="storage-location">
      <h2>{translate(language, 'settings.data_storage_c857509')}</h2>
      <p id="storage-mode">
        {location &&
          {
            system: translate(language, 'settings.system_directory_6d95dd1'),
            portable: translate(language, 'settings.portable_next_to_the_application_b742dcc'),
            custom: translate(language, 'settings.selected_directory_f22abcc'),
            error: translate(language, 'settings.directory_unavailable_2ec9889'),
          }[location.mode]}
      </p>
      {location?.directory && (
        <p id="storage-directory" className="storage-directory">
          {location.directory}
        </p>
      )}
      <p className="field-hint">
        {translate(language, 'settings.the_data_directory_is_selected_when_the_applicat_2b1fda4')}
      </p>
      <p id="storage-sealing" data-storage-sealing={sealing}>
        {
          {
            sealed: translate(language, 'settings.library_sealed_by_keyring'),
            unavailable: translate(language, 'settings.library_plain_no_keyring'),
            refused: translate(language, 'settings.library_plain_keyring_refused'),
            portable: translate(language, 'settings.library_plain_portable'),
          }[sealing]
        }
      </p>
      {(error || location?.error) && (
        <InlineError role="alert" className="desktop-inline-error">
          {error || translateError(location?.error)}
        </InlineError>
      )}
    </section>
  );
}
