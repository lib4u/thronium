import { useMessageState } from '../shared/i18n/react';
import { ApiError } from '../shared/api/errors';
import { messageRef } from '../shared/i18n/message';
import { errorCode } from '../shared/api/errors.ts';
import { useLayoutEffect, useRef, useState } from 'react';
import { command, type Snapshot, type Draft } from '../api';
import { Modal } from '../ui';
import { label } from './schema';
import { parseImport, importDrafts, subscriptionSource, maxImportBytes, type ImportRow } from './import';
import { readImportFile } from './readImportFile';
import type { EmbeddedEditorProps } from './DialogPane';
import { messageKeys, importWarning, ImportMethod } from './ImportModel';
import type { Language } from '../shared/i18n/index.ts';
import { limits } from '../shared/api/generated/limits.ts';
import { personalGroupId } from '../groups/groupModel';
import { draftAddress } from './draftAddress';
export function useImportController({
  groups,
  initialGroup,
  initialText,
  initialDocuments,
  initialProblems = [],
  language,
  close,
  changed,
  subscribe,
  translateError,
  Frame = Modal,
  onActivity,
  completed = close,
  targetGroup,
  groupChanged,
  method = 'link',
  methodChanged,
  reviewChanged,
}: {
  groups: Snapshot['groups'];
  initialGroup: string;
  initialText?: string;
  initialDocuments?: { filename: string; text: string }[];
  /** Files the system opened that could not be read; replaced by the next choice. */
  initialProblems?: { filename: string; code: string }[];
  language: Language;
  close(): void;
  changed(): Promise<void>;
  subscribe(groupId: string): void;
  method?: ImportMethod;
  methodChanged?(method: ImportMethod): void;
  reviewChanged?(review: boolean): void;
  translateError(e: unknown): string;
} & EmbeddedEditorProps) {
  const tr = (key: keyof typeof messageKeys) => label(messageKeys[key], language);
  const [sources, setSources] = useState<
    Record<ImportMethod, { text: string; filename: string; documents?: { text: string; filename: string }[] }>
  >({
    link: { text: initialText || '', filename: '' },
    file: {
      text: initialDocuments?.map((d) => d.text).join('\n') || '',
      filename: initialDocuments?.map((d) => d.filename).join(', ') || '',
      documents: initialDocuments,
    },
    qr: { text: '', filename: '' },
  });
  const { text, filename, documents } = sources[method];
  const setSource = (text: string, filename = '', documents?: { text: string; filename: string }[]) =>
    setSources((old) => ({ ...old, [method]: { text, filename, documents } }));
  const [name, setName] = useState('');
  const [fileProblems, setFileProblems] = useState(initialProblems);
  const subscriptionSaved = useRef<{ url: string; name: string; id: string; autoUpdate: boolean } | null>(
    null,
  );
  const [subscriptionAutoUpdate, setSubscriptionAutoUpdate] = useState(true);
  const [dragging, setDragging] = useState(false);
  const [localGroup, setLocalGroup] = useState(
    initialGroup === 'all' ? groups[0]?.id || personalGroupId : initialGroup,
  );
  const group = targetGroup ?? localGroup;
  const setGroup = (id: string) => {
    setLocalGroup(id);
    groupChanged?.(id);
  };
  // A review and its error belong to the import method that produced them.
  const [reviewed, setReviewed] = useState<{ method: ImportMethod; rows: ImportRow[] | null }>({
    method,
    rows: null,
  });
  const rows = reviewed.method === method ? reviewed.rows : null;
  const setRows = (next: ImportRow[] | null | ((old: ImportRow[] | null) => ImportRow[] | null)) =>
    setReviewed((old) => ({
      method,
      rows: typeof next === 'function' ? next(old.method === method ? old.rows : null) : next,
    }));
  const [chosen, setChosen] = useState<Set<number>>(new Set());
  const [busy, setBusy] = useState(false);
  const [methodError, setMethodError] = useMessageState(language, (e) =>
    e instanceof ApiError ? translateError(e) : message(errorCode(e)),
  );
  const [errorMethod, setErrorMethod] = useState(method);
  const error = errorMethod === method ? methodError : '';
  const setError = (e: unknown) => {
    setErrorMethod(method);
    setMethodError(e);
  };
  const submitting = useRef(false);
  const [accepted, setAccepted] = useState(false);
  const [shown, setShown] = useState<Set<number>>(new Set());
  const [checks, setChecks] = useState<Record<number, { error?: string; valid?: boolean }>>({});
  const [validating, setValidating] = useState<number | null>(null);
  useLayoutEffect(() => {
    onActivity?.(busy || validating !== null, !!text.trim());
  }, [busy, validating, text, onActivity]);
  const validRows = rows?.filter((r) => r.draft) || [];
  const selected = validRows.filter((r) => chosen.has(r.index));
  const hasWarnings = selected.some((r) => r.warnings.length);
  const errors = rows?.filter((r) => r.error).length || 0;
  function message(code: string) {
    return Object.prototype.hasOwnProperty.call(messageKeys, code)
      ? tr(code as keyof typeof messageKeys)
      : tr('invalid_content');
  }
  const subscription = !documents || documents.length === 1 ? subscriptionSource(text) : null;
  useLayoutEffect(() => {
    reviewChanged?.(rows !== null);
  }, [rows, reviewChanged]);
  function subscriptionTitle() {
    return subscription ? name.trim() || subscription.name || new URL(subscription.url).hostname : '';
  }
  async function addSubscription() {
    if (!subscription || busy || submitting.current) return;
    submitting.current = true;
    setBusy(true);
    setError('');
    try {
      const title = subscriptionTitle();
      if (
        !subscriptionSaved.current ||
        subscriptionSaved.current.url !== subscription.url ||
        subscriptionSaved.current.name !== title ||
        subscriptionSaved.current.autoUpdate !== subscriptionAutoUpdate
      ) {
        // A new group follows the global update schedule; without automatic
        // updates it keeps its own settings with the global user agent, like
        // Qt's skip_auto_update.
        const manual = subscriptionAutoUpdate
          ? {}
          : {
              inheritDefaults: false,
              intervalMinutes: 0,
              userAgent: String(
                (await command('settings')).subscriptions?.user_agent ?? limits.subscriptionUserAgent,
              ),
            };
        const result = await command('saveGroup', {
          name: title,
          subscription: {
            url: subscription.url,
            userAgent: limits.subscriptionUserAgent,
            headers: {},
            viaProxy: false,
            useProviderRouting: true,
            ...manual,
          },
        });
        subscriptionSaved.current = {
          ...result,
          url: subscription.url,
          name: title,
          autoUpdate: subscriptionAutoUpdate,
        };
      }
      await command('startSubscriptionUpdates', { id: subscriptionSaved.current.id });
      await changed();
      subscribe(subscriptionSaved.current.id);
    } catch (e) {
      setError(e);
    } finally {
      submitting.current = false;
      setBusy(false);
    }
  }
  function review() {
    if (subscription?.automatic) {
      void addSubscription();
      return;
    }
    const parsed = documents?.length
      ? documents
          .flatMap((d) => parseImport(d.text, group, d.filename))
          .map((r, i) => ({ ...r, index: i + 1 }))
      : parseImport(text, group, filename);
    if (parsed.length > limits.maxBatchProfiles) {
      setError(messageRef(messageKeys.too_many_profiles));
      return;
    }
    if (name.trim() && parsed.filter((r) => r.draft).length === 1)
      for (const r of parsed) if (r.draft) r.draft.name = name.trim();
    setRows(parsed);
    setChosen(new Set(parsed.filter((r) => r.draft).map((r) => r.index)));
    setAccepted(false);
    setChecks({});
    setShown(new Set());
    setError('');
  }
  async function read(files: FileList | File[] | null) {
    if (!files?.length || busy) return;
    setBusy(true);
    setError('');
    setFileProblems([]);
    try {
      const inputs = [];
      for (const file of Array.from(files)) inputs.push(await readImportFile(file, method === 'qr'));
      const content = inputs.map((input) => input.text).join('\n');
      if (new TextEncoder().encode(content).length > maxImportBytes) throw new Error('import_too_large');
      setSource(
        content,
        Array.from(files)
          .map((f) => f.name)
          .join(', '),
        inputs,
      );
      setRows(null);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  async function paste() {
    setBusy(true);
    setError('');
    try {
      setSource(await command('readClipboard'));
      setRows(null);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  async function scan(source: 'readQrClipboard' | 'scanScreenQr') {
    setBusy(true);
    setError('');
    try {
      const texts = await command(source);
      setSource(texts.join('\n'));
      setRows(null);
    } catch (e) {
      const code = errorCode(e);
      if (code !== 'qr_capture_cancelled') setError(code);
    } finally {
      setBusy(false);
    }
  }
  async function validate(row: ImportRow) {
    if (!row.draft) return;
    setValidating(row.index);
    try {
      if (row.draft.kind === 'chain' || row.draft.kind === 'auto-selector' || row.draft.vlessCore)
        await command('checkImportProfile', {
          profiles: importDrafts(validRows).map((draft) => ({ ...draft, groupId: group })),
          index: validRows.findIndex((r) => r.index === row.index),
        });
      else await command('checkProfile', row.draft);
      setChecks((old) => ({ ...old, [row.index]: { valid: true } }));
    } catch (e) {
      setChecks((old) => ({ ...old, [row.index]: { error: translateError(e) } }));
    } finally {
      setValidating(null);
    }
  }
  async function save() {
    if (submitting.current) return;
    submitting.current = true;
    setBusy(true);
    setError('');
    try {
      await command('importProfiles', {
        profiles: importDrafts(selected).map((draft) => ({ ...draft, groupId: group })),
      });
      await changed();
      completed();
    } catch (e) {
      setError(e);
    } finally {
      submitting.current = false;
      setBusy(false);
    }
  }
  function rename(index: number, name: string) {
    setRows((old) =>
      old!.map((r) => (r.index === index && r.draft ? { ...r, draft: { ...r.draft, name } } : r)),
    );
  }
  function warning(value: string) {
    return importWarning(value, language);
  }
  const address = (d: Draft) => draftAddress(d.config);
  return {
    Frame,
    accepted,
    addSubscription,
    address,
    busy,
    checks,
    chosen,
    close,
    dragging,
    error,
    errors,
    filename,
    fileProblems,
    group,
    groups,
    hasWarnings,
    language,
    message,
    method,
    methodChanged,
    name,
    paste,
    read,
    rename,
    review,
    rows,
    save,
    scan,
    selected,
    setAccepted,
    setChosen,
    setDragging,
    setGroup,
    setName,
    setRows,
    setShown,
    setSource,
    shown,
    subscription,
    subscriptionAutoUpdate,
    setSubscriptionAutoUpdate,
    subscriptionTitle,
    text,
    tr,
    validRows,
    validate,
    validating,
    warning,
  };
}
