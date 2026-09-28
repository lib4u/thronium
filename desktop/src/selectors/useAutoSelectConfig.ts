// Controller for the auto-select configurator: edit a local copy of the saved
// health/balancing config and persist it into preferences on save.
import { useRef, useState } from 'react';
import { command } from '../api';
import type { Snapshot } from '../api';
import { errorCode } from '../shared/api/errors.ts';
import { set, type Config } from '../profiles/schema.ts';
import { defaultAutoSelectConfig, editableQuickConfig } from './autoSelectModel.ts';
import { defaults } from '../shared/api/generated/defaults.ts';

export function useAutoSelectConfig(snapshot: Snapshot, close: () => void, refresh: () => Promise<void>) {
  const [previous] = useState(() => structuredClone(snapshot.preferences.autoSelect.config));
  const [previousOptions] = useState(() => ({
    failover: snapshot.preferences.autoSelect.failover,
    sourceGroupId: snapshot.preferences.autoSelect.sourceGroupId,
  }));
  const [config, setConfig] = useState<Config>(() => editableQuickConfig(previous));
  const [failover, setFailover] = useState(previousOptions.failover);
  const [sourceGroupId, setSourceGroupId] = useState(previousOptions.sourceGroupId);
  const saving = useRef(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const change = (path: string, value: unknown) => setConfig((current) => set(current, path, value));
  const reset = () => {
    setConfig(structuredClone(defaultAutoSelectConfig));
    setFailover(defaults.preferences.autoSelect.failover);
    setSourceGroupId(defaults.preferences.autoSelect.sourceGroupId);
  };
  async function save() {
    if (saving.current) return;
    saving.current = true;
    setBusy(true);
    setError('');
    try {
      await command('saveAutoSelectSettings', { previous, previousOptions, config, failover, sourceGroupId });
      // Saved already; the periodic snapshot recovers a failed refresh.
      void refresh().catch(() => {});
      close();
    } catch (e) {
      setError(errorCode(e));
    } finally {
      saving.current = false;
      setBusy(false);
    }
  }
  return { config, change, failover, setFailover, sourceGroupId, setSourceGroupId, reset, save, busy, error };
}
