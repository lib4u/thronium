import { useRef, useState } from 'react';
import { command, type Snapshot } from '../api';
import { errorCode } from '../shared/api/errors.ts';
import { active as probeActive } from '../probes/messages';

type ProbeCommand = 'startPing' | 'startIpTests' | 'startSpeedTests' | 'cancelUrlTests' | 'clearUrlTests';

/** Latency, IP and speed tests started from the server list and menus. */
export function useProbeActions(
  state: Snapshot,
  refresh: () => Promise<void>,
  setError: (code: string) => void,
) {
  const submitting = useRef(false);
  const [probeBusy, setProbeBusy] = useState(false);
  const probing = state.urlTests?.entries.some((e) => probeActive(e.status)) || false;
  return {
    probeBusy,
    probing,
    // A new test cannot start while one is being requested or running, or without the core.
    probesBlocked: probeBusy || probing || !state.coreAvailable,
    async probeAction(name: ProbeCommand, ids?: string[]) {
      if (submitting.current) return;
      submitting.current = true;
      setProbeBusy(true);
      setError('');
      try {
        await command(name, ids ? { ids } : {});
        await refresh();
      } catch (e) {
        setError(errorCode(e));
      } finally {
        submitting.current = false;
        setProbeBusy(false);
      }
    },
  };
}
