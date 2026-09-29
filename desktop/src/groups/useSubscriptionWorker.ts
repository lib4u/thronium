import { errorCode } from '../shared/api/errors.ts';
import { useEffect } from 'react';
import { command } from '../api';
import { parseImport, importDrafts, splitConfigRows } from '../profiles/import';

// Only one native lease may run. StrictMode cleanup and webview reload invalidate
// the old owner, so a late response can never apply an abandoned job.
export default function useSubscriptionWorker() {
  useEffect(() => {
    const owner = crypto.randomUUID();
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    async function tick() {
      let job: { id: string; groupId: string } | null = null;
      try {
        job = await command('claimSubscriptionJob', { owner });
        if (!active) {
          void command('releaseSubscriptionWorker', { owner }).catch(() => {});
          return;
        }
        if (job) {
          const key = { id: job.id, owner };
          const response = await command('fetchSubscriptionJob', key);
          if (!active) return;
          // One unreadable row must not discard the rest of the update, as in
          // Throne. What was left out is counted and reported, never dropped.
          const rows = splitConfigRows(parseImport(response.body, job.groupId), job.groupId);
          const usable = rows.filter((r) => r.draft && !r.error);
          if (!usable.length) throw new Error('subscription_invalid_profiles');
          const { checks } = await command('prepareSubscriptionJob', {
            ...key,
            profiles: importDrafts(usable),
            omitted: {
              skipped: rows.length - usable.length,
              warned: usable.filter((r) => r.warnings.length).length,
            },
          });
          // One call checks every changed server: geodata once, then one Core pass.
          if (checks && active) await command('checkSubscriptionJob', key);
          if (active) await command('applySubscriptionJob', key);
        }
      } catch (e) {
        if (job && active)
          await command('failSubscriptionJob', {
            id: job.id,
            owner,
            error: errorCode(e),
          }).catch(() => {});
      } finally {
        if (active) timer = setTimeout(() => void tick(), job ? 50 : 1000);
      }
    }
    timer = setTimeout(() => void tick(), 0);
    return () => {
      active = false;
      clearTimeout(timer);
      void command('releaseSubscriptionWorker', { owner }).catch(() => {});
    };
  }, []);
}
