import { useEffect, useRef, useState } from 'react';
import { errorCode } from '../shared/api/errors.ts';

/** Visible diagnostic logs change independently of the library revision. */
export function useDiagnosticLog<T>(read: () => Promise<T>, erase: () => Promise<unknown>, revision: number) {
  const [data, setData] = useState<T>();
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [confirm, setConfirm] = useState(false);
  const [reload, setReload] = useState(0);
  const sequence = useRef(0);
  const clearing = useRef(false);
  const mounted = useRef(false);
  useEffect(() => {
    mounted.current = true;
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      const current = ++sequence.current;
      try {
        if (!clearing.current) {
          const result = await read();
          if (!disposed && current === sequence.current) {
            setData(result);
            setError('');
          }
        }
      } catch (e) {
        if (!disposed && current === sequence.current) setError(errorCode(e));
      } finally {
        if (!disposed) {
          setLoading(false);
          timer = setTimeout(() => void poll(), 2000);
        }
      }
    }
    void poll();
    return () => {
      disposed = true;
      mounted.current = false;
      sequence.current++;
      clearTimeout(timer);
    };
  }, [read, revision, reload]);
  async function clear() {
    if (clearing.current) return;
    if (!confirm) {
      setConfirm(true);
      return;
    }
    clearing.current = true;
    sequence.current++;
    setBusy(true);
    setError('');
    try {
      await erase();
      if (mounted.current) {
        setConfirm(false);
        setReload((value) => value + 1);
      }
    } catch (e) {
      if (mounted.current) setError(errorCode(e));
    } finally {
      clearing.current = false;
      if (mounted.current) setBusy(false);
    }
  }
  return {
    data,
    loading,
    busy,
    error,
    confirm,
    clear,
    cancelClear: () => setConfirm(false),
    refresh: () => setReload((value) => value + 1),
  };
}
