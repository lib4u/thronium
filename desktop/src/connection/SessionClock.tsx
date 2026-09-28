import { useEffect, useState } from 'react';
import { duration } from '../AppModel';

/** The running session time; only this text re-renders every second. */
export function SessionClock({ since }: { since: number | null }) {
  const [, tick] = useState(0);
  useEffect(() => {
    if (!since) return;
    const timer = setInterval(() => tick((n) => n + 1), 1000);
    return () => clearInterval(timer);
  }, [since]);
  return <>{duration(since)}</>;
}
