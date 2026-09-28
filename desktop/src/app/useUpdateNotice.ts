import { useEffect, useRef, type Dispatch, type SetStateAction } from 'react';
import { empty, type Snapshot } from '../api';
import type { ModalState, PageId } from '../AppModel';
import { jobChanged } from '../groups/jobStatus';

/**
 * Opens the subscription updates summary once new updates changed profiles,
 * when notifications are on and the connection page is free of dialogs.
 */
export function useUpdateNotice(
  state: Snapshot,
  page: PageId,
  modal: ModalState,
  setModal: Dispatch<SetStateAction<ModalState>>,
) {
  const completedJobs = useRef<Set<string> | null>(null),
    pending = useRef(false);
  useEffect(() => {
    if (state === empty) return;
    const completed = state.subscriptionJobs.filter((j) => jobChanged(j.status));
    if (completedJobs.current === null) {
      completedJobs.current = new Set(completed.map((j) => j.id));
      return;
    }
    if (
      !state.subscriptionNotifications ||
      modal?.type === 'updates' ||
      document.querySelector('dialog.subscription-updates-modal[open]')
    )
      pending.current = false;
    else if (completed.some((j) => !completedJobs.current!.has(j.id))) pending.current = true;
    completed.forEach((j) => completedJobs.current!.add(j.id));
    if (pending.current && page === 'connection' && !modal && !document.querySelector('dialog[open]')) {
      pending.current = false;
      setModal({ type: 'updates' });
    }
  }, [state.subscriptionJobs, state.subscriptionNotifications, page, modal]);
}
