import { useState } from 'react';

/** Closing an editor with unsaved changes first asks to discard them; nothing closes while saving. */
export function useDiscardGuard({ busy, dirty, close }: { busy: boolean; dirty: boolean; close(): void }) {
  const [asking, setAsking] = useState(false);
  return {
    asking,
    requestClose() {
      if (busy) return;
      if (dirty) setAsking(true);
      else close();
    },
    keep: () => setAsking(false),
    close,
  };
}
export type DiscardGuard = ReturnType<typeof useDiscardGuard>;
