import { useCallback, useEffect, useRef, useState } from 'react';
import { command } from '../api';

/** The routing editor owns only its independent HTTP task, never a core/RPC call. */
export function useRoutingDownload(context: string) {
  const active = useRef<{ id: string; context: string } | null>(null);
  const mounted = useRef(true);
  const current = useRef(context);
  current.current = context;
  const [pending, setPending] = useState(false);
  const cancel = useCallback(() => {
    const task = active.current;
    active.current = null;
    setPending(false);
    if (task) void command('cancelRoutingDownload', { requestId: task.id }).catch(() => {});
  }, []);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      cancel();
    };
  }, [context, cancel]);
  async function download<T>(action: (requestId: string) => Promise<T>): Promise<T | undefined> {
    if (!mounted.current || current.current !== context || active.current) return undefined;
    const task = { id: crypto.randomUUID(), context };
    active.current = task;
    setPending(true);
    const live = () => mounted.current && active.current === task && current.current === task.context;
    try {
      const result = await action(task.id);
      return live() ? result : undefined;
    } catch (error) {
      if (live()) throw error;
      return undefined;
    } finally {
      if (active.current === task) {
        active.current = null;
        setPending(false);
      }
    }
  }
  return { download, cancel, pending };
}
