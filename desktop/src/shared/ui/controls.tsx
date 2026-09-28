import { useId, useState, type ComponentProps, type HTMLAttributes, type ReactNode } from 'react';
import { useTranslation } from '../i18n/react';
import { Icon, type IconName } from './Icon';

const classes = (...values: (string | undefined | false)[]) => values.filter(Boolean).join(' ');
type ButtonProps = ComponentProps<'button'> & {
  variant?: 'primary' | 'secondary' | 'text' | 'danger';
  size?: 'small' | 'normal';
  loading?: boolean;
};
export function Button({ variant, size, loading, disabled, className, ...props }: ButtonProps) {
  return (
    <button
      {...props}
      className={classes(
        className ?? (variant === 'text' ? 'text-button' : 'button'),
        variant && variant !== 'text' && variant,
        size === 'small' && 'control-small',
      )}
      aria-busy={loading || props['aria-busy']}
      disabled={disabled || loading}
    />
  );
}
export function IconButton({
  icon,
  label,
  className,
  ...props
}: Omit<ButtonProps, 'children'> & { icon: IconName; label: string }) {
  return (
    <Button
      type="button"
      {...props}
      title={props.title ?? label}
      aria-label={label}
      className={className ?? 'icon-button'}
    >
      <Icon name={icon} />
    </Button>
  );
}
export function Input({ className = 'text-input', ...props }: ComponentProps<'input'>) {
  return <input {...props} className={className} />;
}
/** A search box with its icon; `children` follow the input (for example a shortcut hint). */
export function SearchField({
  className,
  children,
  ...props
}: Omit<ComponentProps<'input'>, 'type'> & { children?: ReactNode }) {
  return (
    <label className={classes('search-field', className)}>
      <Icon name="search" />
      <input type="search" {...props} />
      {children}
    </label>
  );
}
export function NumberField(props: ComponentProps<'input'>) {
  return <Input type="number" {...props} />;
}
export function Textarea({ className = 'text-input', ...props }: ComponentProps<'textarea'>) {
  return <textarea {...props} className={className} />;
}
export function Select({ className = 'text-input', ...props }: ComponentProps<'select'>) {
  return <select {...props} className={className} />;
}
export function Checkbox(props: ComponentProps<'input'>) {
  return <input type="checkbox" {...props} />;
}
export function Switch(props: ComponentProps<'input'>) {
  return <Checkbox role="switch" {...props} />;
}

type FieldControl = { id: string; 'aria-describedby'?: string; 'aria-invalid'?: true };
/**
 * A labelled form field. Given an `id` or a render function, the caption is a
 * `<label for>` and the control receives its id and ARIA links; otherwise the
 * caption and control share one wrapping `<label>` (optionally `htmlFor` a
 * control placed elsewhere).
 */
export function Field({
  id: explicitId,
  htmlFor,
  label,
  hint,
  error,
  children,
  className = 'feature-field',
}: {
  id?: string;
  htmlFor?: string;
  label: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
  children: ReactNode | ((props: FieldControl) => ReactNode);
  className?: string;
}) {
  const generated = useId();
  if (explicitId === undefined && typeof children !== 'function')
    return (
      <label className={className} htmlFor={htmlFor}>
        <span>{label}</span>
        {children}
        {hint && <small className="field-hint">{hint}</small>}
        {error && <InlineError>{error}</InlineError>}
      </label>
    );
  const id = explicitId ?? `field-${generated}`;
  const props: FieldControl = {
    id,
    'aria-describedby': error ? `${id}-error` : hint ? `${id}-hint` : undefined,
    'aria-invalid': error ? true : undefined,
  };
  return (
    <div className={className}>
      <label htmlFor={id}>{label}</label>
      {typeof children === 'function' ? children(props) : children}
      {hint && (
        <small className="field-hint" id={`${id}-hint`}>
          {hint}
        </small>
      )}
      {error && <InlineError id={`${id}-error`}>{error}</InlineError>}
    </div>
  );
}
/** Shows or hides the credential in the control `controls`. */
function RevealButton({
  controls,
  shown,
  onShownChange,
  disabled,
}: {
  controls: string;
  shown: boolean;
  onShownChange(shown: boolean): void;
  disabled?: boolean;
}) {
  const t = useTranslation();
  return (
    <Button
      type="button"
      className="text-button field-reveal"
      disabled={disabled}
      aria-controls={controls}
      aria-pressed={shown}
      onClick={() => onShownChange(!shown)}
    >
      {t(shown ? 'common.hide_secret' : 'common.show_secret')}
    </Button>
  );
}
type Reveal = { shown?: boolean; onShownChange?(shown: boolean): void };
function useReveal(explicitId: string | undefined, prefix: string, { shown, onShownChange }: Reveal) {
  const generated = useId();
  const [local, setLocal] = useState(false);
  return {
    id: explicitId ?? `${prefix}-${generated}`,
    shown: shown ?? local,
    change(next: boolean) {
      setLocal(next);
      onShownChange?.(next);
    },
  };
}
/** A one-line credential, masked until revealed. */
export function SecretField({
  id,
  shown,
  onShownChange,
  ...props
}: Omit<ComponentProps<'input'>, 'type'> & Reveal) {
  const reveal = useReveal(id, 'secret', { shown, onShownChange });
  return (
    <>
      <Input
        autoComplete="off"
        spellCheck={false}
        {...props}
        id={reveal.id}
        type={reveal.shown ? 'text' : 'password'}
      />
      <RevealButton
        controls={reveal.id}
        shown={reveal.shown}
        onShownChange={reveal.change}
        disabled={props.disabled}
      />
    </>
  );
}
/** A multi-line credential (keys, headers), visually masked until revealed. */
export function SecretText({
  id,
  shown,
  onShownChange,
  className = 'text-input mono field-multiline',
  ...props
}: ComponentProps<'textarea'> & Reveal) {
  const reveal = useReveal(id, 'secret', { shown, onShownChange });
  return (
    <>
      <Textarea
        autoComplete="off"
        spellCheck={false}
        {...props}
        id={reveal.id}
        className={classes(className, !reveal.shown && 'field-secret')}
      />
      <RevealButton
        controls={reveal.id}
        shown={reveal.shown}
        onShownChange={reveal.change}
        disabled={props.disabled}
      />
    </>
  );
}
export function JsonEditor(props: ComponentProps<'textarea'>) {
  return (
    <Textarea
      spellCheck={false}
      autoComplete="off"
      {...props}
      className={props.className ?? 'text-input mono'}
    />
  );
}
export function formatJson(text: string): string {
  return JSON.stringify(JSON.parse(text), null, 2);
}
export function InlineError({ className = 'field-error', ...props }: HTMLAttributes<HTMLParagraphElement>) {
  return <p role="alert" {...props} className={className} />;
}
export function Notice({
  kind = 'info',
  className,
  ...props
}: HTMLAttributes<HTMLParagraphElement> & { kind?: 'info' | 'error' | 'success' }) {
  return (
    <p
      role={kind === 'error' ? 'alert' : kind === 'success' ? 'status' : 'note'}
      {...props}
      className={
        className ??
        (kind === 'error' ? 'field-error' : kind === 'success' ? 'desktop-success' : 'field-hint')
      }
    />
  );
}
export function LoadingState(props: HTMLAttributes<HTMLParagraphElement>) {
  return <p className="field-hint" role="status" aria-busy="true" {...props} />;
}
export function DialogHeader(props: HTMLAttributes<HTMLDivElement>) {
  return <div {...props} className={props.className ?? 'modal-head'} />;
}
export function DialogBody(props: HTMLAttributes<HTMLDivElement>) {
  return <div {...props} className={props.className ?? 'modal-body'} />;
}
export function DialogFooter(props: HTMLAttributes<HTMLDivElement> & { ref?: React.Ref<HTMLDivElement> }) {
  return <div {...props} className={props.className ?? 'modal-footer'} />;
}
export function FormActions(props: HTMLAttributes<HTMLDivElement>) {
  return <div {...props} className={props.className ?? 'feature-toolbar'} />;
}
export function Section({
  title,
  children,
  ...props
}: Omit<ComponentProps<'details'>, 'title'> & { title: ReactNode }) {
  return (
    <details {...props}>
      <summary>{title}</summary>
      {children}
    </details>
  );
}
function Tabs({ onKeyDown, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      role="tablist"
      {...props}
      onKeyDown={(event) => {
        onKeyDown?.(event);
        const keys = ['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'];
        if (event.defaultPrevented || !keys.includes(event.key)) return;
        const tabs = [
          ...event.currentTarget.querySelectorAll<HTMLButtonElement>('[role=tab]:not(:disabled)'),
        ];
        const index = tabs.indexOf(document.activeElement as HTMLButtonElement);
        if (index < 0 || !tabs.length) return;
        event.preventDefault();
        const next =
          tabs[
            event.key === 'Home'
              ? 0
              : event.key === 'End'
                ? tabs.length - 1
                : (index + (['ArrowRight', 'ArrowDown'].includes(event.key) ? 1 : -1) + tabs.length) %
                  tabs.length
          ];
        next.focus();
        next.click();
      }}
    />
  );
}
/** A row of tabs; arrow keys, Home and End move between them. Extra attributes identify each tab. */
export function TabList<T extends string>({
  tabs,
  value,
  onChange,
  disabled,
  className = 'feature-tabs',
  ...props
}: Omit<HTMLAttributes<HTMLDivElement>, 'onChange'> & {
  tabs: readonly { id: T; label: ReactNode; attributes?: Record<string, string> }[];
  value: T;
  onChange(id: T): void;
  disabled?: boolean;
}) {
  return (
    <Tabs className={className} {...props}>
      {tabs.map((tab) => (
        <Button
          key={tab.id}
          type="button"
          role="tab"
          aria-selected={tab.id === value}
          tabIndex={tab.id === value ? 0 : -1}
          className={tab.id === value ? 'active' : ''}
          disabled={disabled}
          onClick={() => onChange(tab.id)}
          {...tab.attributes}
        >
          {tab.label}
        </Button>
      ))}
    </Tabs>
  );
}
