import { useEffect, useRef, useState, type PointerEvent } from 'react';

type Target = { id: string; after: boolean };
type Session = {
  id: string;
  scope: string;
  pointer: number;
  handle: HTMLButtonElement;
  startX: number;
  startY: number;
  x: number;
  y: number;
  dragging: boolean;
};
/**
 * Pointer reordering of rows marked with `data-<rowAttribute>="<id>"` inside
 * `root`. Rows move only within their scope (a profile within its group);
 * dragging auto-scrolls near edges, Escape or losing focus cancels.
 */
export default function useRowDrag<R extends HTMLElement>({
  rows,
  rowAttribute,
  enabled,
  move,
}: {
  /** Row ids with the scope each belongs to, in display order. */
  rows: [id: string, scope: string][];
  rowAttribute: string;
  enabled: boolean;
  move: (id: string, target: string, after: boolean) => void;
}) {
  const root = useRef<R>(null);
  const [source, setSource] = useState<string | null>(null),
    [target, setTarget] = useState<Target | null>(null);
  const scopes = new Map(rows);
  const counts = new Map<string, number>();
  rows.forEach(([, scope]) => counts.set(scope, (counts.get(scope) ?? 0) + 1));
  const latest = useRef({ scopes, counts, enabled, move });
  latest.current = { scopes, counts, enabled, move };
  const session = useRef<Session | null>(null);
  const frame = useRef(0),
    lastFrame = useRef(0),
    ignoreUntil = useRef(0);
  const finish = () => {
    const active = session.current;
    session.current = null;
    if (active?.dragging) ignoreUntil.current = Date.now() + 300;
    if (active?.handle.hasPointerCapture(active.pointer)) active.handle.releasePointerCapture(active.pointer);
    cancelAnimationFrame(frame.current);
    frame.current = 0;
    setSource(null);
    setTarget(null);
  };
  const destination = (x: number, y: number): Target | null => {
    const active = session.current;
    const row = document.elementFromPoint(x, y)?.closest<HTMLElement>(`[data-${rowAttribute}]`);
    const id = row?.getAttribute(`data-${rowAttribute}`);
    if (
      !active ||
      !row ||
      !id ||
      !root.current?.contains(row) ||
      id === active.id ||
      latest.current.scopes.get(id) !== active.scope
    )
      return null;
    const box = row.getBoundingClientRect();
    return { id, after: y > box.top + box.height / 2 };
  };
  const indicate = (next: Target | null) =>
    setTarget((old) => (old?.id === next?.id && old?.after === next?.after ? old : next));
  const tick = (time: number) => {
    const active = session.current;
    if (!active?.dragging) return;
    const elapsed = Math.min(32, time - (lastFrame.current || time));
    lastFrame.current = time;
    const hit = document.elementFromPoint(active.x, active.y);
    const under = hit instanceof HTMLElement ? hit : hit?.parentElement;
    for (
      let node: HTMLElement | null = under && root.current?.contains(under) ? under : root.current;
      node;
      node = node.parentElement
    ) {
      if (node.scrollHeight <= node.clientHeight || !/(auto|scroll)/.test(getComputedStyle(node).overflowY))
        continue;
      const box = node.getBoundingClientRect(),
        top = Math.max(0, box.top),
        bottom = Math.min(innerHeight, box.bottom);
      if (active.x < box.left || active.x > box.right || active.y < top || active.y > bottom) continue;
      const edge = Math.min(44, (bottom - top) / 3);
      if (edge <= 0) continue;
      const velocity =
        active.y < top + edge
          ? -(top + edge - active.y) / edge
          : active.y > bottom - edge
            ? (active.y - bottom + edge) / edge
            : 0;
      const before = node.scrollTop;
      node.scrollTop += velocity * elapsed * 0.65;
      if (before !== node.scrollTop) break;
    }
    indicate(destination(active.x, active.y));
    frame.current = requestAnimationFrame(tick);
  };
  const signature = JSON.stringify(rows);
  useEffect(() => {
    finish();
  }, [enabled, signature]);
  useEffect(() => {
    const cancel = (event: KeyboardEvent) => {
      if (event.key === 'Escape') finish();
    };
    const blur = () => finish();
    document.addEventListener('keydown', cancel);
    window.addEventListener('blur', blur);
    return () => {
      const active = session.current;
      session.current = null;
      if (active?.handle.hasPointerCapture(active.pointer))
        active.handle.releasePointerCapture(active.pointer);
      cancelAnimationFrame(frame.current);
      document.removeEventListener('keydown', cancel);
      window.removeEventListener('blur', blur);
    };
  }, []);
  const canStart = (id: string) =>
    latest.current.enabled && (latest.current.counts.get(latest.current.scopes.get(id) ?? '') ?? 0) > 1;
  return {
    root,
    source,
    target,
    canStart,
    ignoreClick: () => Date.now() < ignoreUntil.current,
    start(event: PointerEvent<HTMLButtonElement>, id: string) {
      if (!canStart(id) || event.button !== 0 || !event.isPrimary || session.current) return;
      event.stopPropagation();
      // Pointer capture keeps ordinary mouse/touch movement inside the WebView;
      // GTK's native HTML drag loop does not reliably deliver position events.
      event.currentTarget.setPointerCapture(event.pointerId);
      session.current = {
        id,
        scope: latest.current.scopes.get(id)!,
        pointer: event.pointerId,
        handle: event.currentTarget,
        startX: event.clientX,
        startY: event.clientY,
        x: event.clientX,
        y: event.clientY,
        dragging: false,
      };
    },
    over(event: PointerEvent<HTMLButtonElement>) {
      const active = session.current;
      if (!active || active.pointer !== event.pointerId) return;
      if (!latest.current.enabled) {
        finish();
        return;
      }
      active.x = event.clientX;
      active.y = event.clientY;
      if (!active.dragging) {
        if (Math.hypot(active.x - active.startX, active.y - active.startY) < 6) return;
        active.dragging = true;
        setSource(active.id);
        setTarget(null);
        lastFrame.current = 0;
        frame.current = requestAnimationFrame(tick);
      }
      event.preventDefault();
      event.stopPropagation();
      indicate(destination(active.x, active.y));
    },
    drop(event: PointerEvent<HTMLButtonElement>) {
      const active = session.current;
      if (!active || active.pointer !== event.pointerId) return;
      const next = active.dragging ? destination(event.clientX, event.clientY) : null;
      const valid = latest.current.enabled && latest.current.scopes.get(active.id) === active.scope;
      if (active.dragging) {
        event.preventDefault();
        event.stopPropagation();
      }
      finish();
      if (valid && next) latest.current.move(active.id, next.id, next.after);
    },
    finish,
  };
}
