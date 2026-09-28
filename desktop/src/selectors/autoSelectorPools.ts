import { useEffect, useState } from 'react';
import { command } from '../api';
import type * as Wire from '../shared/api/generated/commands';

type Read = { pools?: Wire.SelectorPool[]; error?: unknown };
type Listener = (read: Read) => void;

const PERIOD_MS = 1000;
const listeners = new Set<Listener>();
let timer: ReturnType<typeof setTimeout> | undefined;
let inFlight = false;
let again = false;

// One poll serves every view that shows running pools. A poll is scheduled
// after the previous reply, so slow RPC calls never overlap, and a reply goes
// only to views that were watching when it was requested.
async function poll() {
  clearTimeout(timer);
  timer = undefined;
  if (inFlight) {
    again = true;
    return;
  }
  inFlight = true;
  const targets = [...listeners];
  let read: Read;
  try {
    read = { pools: await command('getAutoSelectors') };
  } catch (error) {
    read = { error };
  }
  inFlight = false;
  for (const listener of targets) if (listeners.has(listener)) listener(read);
  if (!listeners.size) return;
  if (again) {
    again = false;
    void poll();
  } else timer = setTimeout(() => void poll(), PERIOD_MS);
}

function watch(listener: Listener): () => void {
  listeners.add(listener);
  void poll();
  return () => {
    listeners.delete(listener);
    if (listeners.size) return;
    clearTimeout(timer);
    timer = undefined;
  };
}

/** Requests the pools now, for example after a pool action. */
export const refreshAutoSelectors = () => {
  if (listeners.size) void poll();
};

/**
 * The running pools while `connection` identifies a running connection. Reads
 * of an earlier connection are dropped; a failed read keeps the last pools.
 */
export function useAutoSelectorPools(connection: string | null) {
  const [read, setRead] = useState<Read & { connection: string }>();
  useEffect(() => {
    if (!connection) return;
    return watch((next) =>
      setRead((old) =>
        next.error !== undefined && old?.connection === connection
          ? { ...old, error: next.error }
          : { connection, ...next },
      ),
    );
  }, [connection]);
  return read?.connection === connection ? read : undefined;
}
