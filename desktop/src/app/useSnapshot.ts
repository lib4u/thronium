import { useCallback, useEffect, useRef, useState } from 'react';
import { command, empty, type Snapshot } from '../api';
import { errorCode } from '../shared/api/errors';
/**
 * `onError` receives a polling failure once per failure streak, so it does not
 * replace an action's error every second; `onRecovered` gets that code back
 * when polling works again.
 */
export function useSnapshot(onError: (value: string) => void, onRecovered: (value: string) => void) {
  const error = useRef({ onError, onRecovered });
  error.current = { onError, onRecovered };
  const [state, setState] = useState<Snapshot>(empty);
  const mounted = useRef(true);
  const refreshSequence = useRef(0);
  const refresh = useCallback(async () => {
    const sequence = ++refreshSequence.current;
    try {
      const next = await command('snapshot');
      // A delayed poll must not replace a newer session or close its auth form.
      if (mounted.current && sequence === refreshSequence.current) setState(next);
    } catch (e) {
      if (mounted.current && sequence === refreshSequence.current) throw e;
    }
  }, []);
  useEffect(() => {
    mounted.current = true;
    let disposed = false;
    let timeout: ReturnType<typeof setTimeout>;
    let failing = '';
    const poll = async () => {
      try {
        await refresh();
        if (failing && !disposed) error.current.onRecovered(failing);
        failing = '';
      } catch (e) {
        const code = errorCode(e);
        if (!disposed && code !== failing) error.current.onError(code);
        failing = code;
      }
      if (!disposed) timeout = setTimeout(poll, 1000);
    };
    void poll();
    return () => {
      disposed = true;
      mounted.current = false;
      refreshSequence.current++;
      clearTimeout(timeout);
    };
  }, [refresh]);
  return { state, refresh, mounted };
}
