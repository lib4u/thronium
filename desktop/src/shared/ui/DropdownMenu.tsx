import type { IconName } from './Icon';
import { Button } from './controls';
import { useLayoutEffect, useRef, useId, type ButtonHTMLAttributes } from 'react';
import { createPortal } from 'react-dom';
import { Icon } from './Icon';
import './DropdownMenu.css';

export type MenuEdge = 'first' | 'last';
export type MenuItem = {
  id: string;
  label: string;
  icon: IconName;
  disabled?: boolean;
  danger?: boolean;
  separator?: boolean;
  groupAction?: string;
  checked?: boolean;
  select(): void;
};
export function menuTriggerProps(
  expanded: boolean,
  open: (anchor: HTMLButtonElement, edge?: MenuEdge) => void,
): ButtonHTMLAttributes<HTMLButtonElement> {
  return {
    'aria-haspopup': 'menu',
    'aria-expanded': expanded,
    onClick: (e) => open(e.currentTarget),
    onKeyDown: (e) => {
      if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
      e.preventDefault();
      open(e.currentTarget, e.key === 'ArrowUp' ? 'last' : 'first');
    },
  };
}

// A non-modal portal escapes the scrolling library without blocking the page.
export default function DropdownMenu({
  anchor,
  label,
  items,
  close,
  edge = 'first',
}: {
  anchor: HTMLButtonElement;
  label: string;
  items: MenuItem[];
  close(): void;
  edge?: MenuEdge;
}) {
  const id = 'action-menu-' + useId();
  const ref = useRef<HTMLDivElement>(null);
  const onClose = useRef(close);
  onClose.current = close;
  const search = useRef({ text: '', time: 0 });
  const dismiss = (restore = true) => {
    if (restore && anchor.isConnected) anchor.focus({ preventScroll: true });
    onClose.current();
  };
  useLayoutEffect(() => {
    const menu = ref.current!;
    const previousControls = anchor.getAttribute('aria-controls');
    anchor.setAttribute('aria-controls', id);
    const place = () => {
      if (!anchor.isConnected || !anchor.getClientRects().length) {
        onClose.current();
        return;
      }
      const a = anchor.getBoundingClientRect();
      const gap = 5;
      const margin = 8;
      if (a.bottom <= 0 || a.top >= innerHeight || a.right <= 0 || a.left >= innerWidth) {
        onClose.current();
        return;
      }
      const below = innerHeight - a.bottom - gap - margin;
      const above = a.top - gap - margin;
      menu.style.maxHeight = `${Math.max(0, innerHeight - margin * 2)}px`;
      const upwards = menu.scrollHeight > below && above > below;
      menu.style.maxHeight = `${Math.max(0, Math.min(innerHeight - margin * 2, upwards ? above : below))}px`;
      const r = menu.getBoundingClientRect();
      menu.style.left = `${Math.max(margin, Math.min(a.right - r.width, innerWidth - r.width - margin))}px`;
      menu.style.top = `${Math.max(margin, upwards ? a.top - gap - r.height : a.bottom + gap)}px`;
      menu.dataset.placement = upwards ? 'top' : 'bottom';
    };
    place();
    const buttons = menu.querySelectorAll<HTMLButtonElement>('button:not(:disabled)');
    (buttons[edge === 'last' ? buttons.length - 1 : 0] || menu).focus({ preventScroll: true });
    const outside = (event: PointerEvent) => {
      if (!menu.contains(event.target as Node) && !anchor.contains(event.target as Node)) dismiss(false);
    };
    const focusOutside = (event: FocusEvent) => {
      if (!menu.contains(event.target as Node) && event.target !== anchor) onClose.current();
    };
    const scroll = (event: Event) => {
      if (!menu.contains(event.target as Node)) dismiss();
    };
    document.addEventListener('pointerdown', outside, true);
    document.addEventListener('focusin', focusOutside);
    document.addEventListener('scroll', scroll, true);
    window.addEventListener('resize', place);
    const observer = new ResizeObserver(place);
    observer.observe(menu);
    observer.observe(anchor);
    return () => {
      if (previousControls) anchor.setAttribute('aria-controls', previousControls);
      else anchor.removeAttribute('aria-controls');
      document.removeEventListener('pointerdown', outside, true);
      document.removeEventListener('focusin', focusOutside);
      document.removeEventListener('scroll', scroll, true);
      window.removeEventListener('resize', place);
      observer.disconnect();
      if (menu.contains(document.activeElement) && anchor.isConnected) anchor.focus({ preventScroll: true });
    };
  }, [anchor, edge]);
  return createPortal(
    <div
      ref={ref}
      id={id}
      data-action-menu
      className="dropdown-menu desktop-actions"
      role="menu"
      tabIndex={-1}
      aria-label={label}
      onKeyDown={(event) => {
        const buttons = [...event.currentTarget.querySelectorAll<HTMLButtonElement>('button:not(:disabled)')];
        const index = buttons.indexOf(document.activeElement as HTMLButtonElement);
        if (event.key === 'Escape') {
          event.preventDefault();
          event.stopPropagation();
          dismiss();
        } else if (event.key === 'Tab') {
          dismiss();
        } else if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
          event.preventDefault();
          event.stopPropagation();
          const next =
            event.key === 'Home'
              ? 0
              : event.key === 'End'
                ? buttons.length - 1
                : (index + (event.key === 'ArrowDown' ? 1 : -1) + buttons.length) % buttons.length;
          buttons[next]?.focus();
        } else if (
          event.key.length === 1 &&
          event.key !== ' ' &&
          !event.ctrlKey &&
          !event.metaKey &&
          !event.altKey
        ) {
          event.stopPropagation();
          const now = Date.now();
          search.current = {
            text:
              (now - search.current.time < 700 ? search.current.text : '') + event.key.toLocaleLowerCase(),
            time: now,
          };
          const ordered = [...buttons.slice(index + 1), ...buttons.slice(0, index + 1)];
          ordered
            .find((b) => b.textContent?.trim().toLocaleLowerCase().startsWith(search.current.text))
            ?.focus();
        }
      }}
    >
      {items.map((item) => (
        <Button
          type="button"
          role={item.checked === undefined ? 'menuitem' : 'menuitemradio'}
          aria-checked={item.checked}
          tabIndex={-1}
          key={item.id}
          id={item.id}
          data-group-action={item.groupAction}
          className={`${item.danger ? 'menu-danger' : ''} ${item.separator ? 'menu-separator' : ''}`}
          disabled={item.disabled}
          onClick={() => {
            dismiss();
            item.select();
          }}
        >
          <Icon name={item.icon} />
          <span className="dropdown-label">{item.label}</span>
          {item.checked && <Icon name="check" />}
        </Button>
      ))}
    </div>,
    document.body,
  );
}
