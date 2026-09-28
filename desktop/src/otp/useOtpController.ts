import { messageRef } from '../shared/i18n/message';
import { useMessageState } from '../shared/i18n/react';
import { errorCode } from '../shared/api/errors.ts';
import { useEffect, useRef, useState } from 'react';
import { command } from '../api';
import { message } from './messages';
import { stageImportText } from './importText';
import { decodeQrImage } from '../shared/qrImage.ts';
import { Draft, Row, Editor, ExportFormat, Code } from './OtpModel';
import type { Language } from '../shared/i18n/index.ts';
import { limits } from '../shared/api/generated/limits.ts';
export function useOtpController({
  language,
  translateError,
  codesOnly = false,
}: {
  language: Language;
  translateError(e: unknown): string;
  codesOnly?: boolean;
}) {
  const [rows, setRows] = useState<Row[]>([]),
    [query, setQuery] = useState(''),
    [page, setPage] = useState(0);
  const [codes, setCodes] = useState<Record<string, Code>>({}),
    [busy, setBusy] = useState(false),
    [error, setError] = useMessageState(language, errorText),
    [notice, setNotice] = useMessageState(language, errorText);
  const [editor, setEditor] = useState<Editor>(),
    [showSecret, setShowSecret] = useState(false),
    [removing, setRemoving] = useState<Row>();
  const [importing, setImporting] = useState(false),
    [text, setText] = useState('');
  const [exported, setExported] = useState<{
    ids: string[];
    text: string;
    format: ExportFormat;
    image?: string;
  }>();
  const panel = useRef<HTMLElement>(null);
  const dom = (name: string) => (codesOnly ? name.replace('otp-', 'otp-quick-') : name);
  function unobscured() {
    const dialogs = [...document.querySelectorAll('dialog[open]')];
    return !dialogs.length || !!dialogs[dialogs.length - 1].contains(panel.current);
  }
  const mounted = useRef(true),
    lock = useRef(false),
    listRequest = useRef(0);
  const visible = rows.filter((row) =>
    `${row.name} ${row.issuer}`.toLocaleLowerCase(language).includes(query.toLocaleLowerCase(language)),
  );
  // One page asks the backend for all of its codes at once.
  const pageSize = limits.maxOtpCodesPerRequest;
  const pages = Math.max(1, Math.ceil(visible.length / pageSize));
  const shown = visible.slice(
    Math.min(page, pages - 1) * pageSize,
    (Math.min(page, pages - 1) + 1) * pageSize,
  );
  const idsKey = JSON.stringify(shown.map((row) => row.id)),
    paused = !!editor || !!removing || importing || !!exported;
  function errorText(e: unknown) {
    return message(e, language) || translateError(e);
  }
  async function load() {
    const ticket = ++listRequest.current;
    const next = await command('otpList');
    if (mounted.current && ticket === listRequest.current) setRows(next);
  }
  useEffect(() => {
    mounted.current = true;
    void load().catch((e) => {
      if (mounted.current) setError(e);
    });
    return () => {
      mounted.current = false;
      listRequest.current++;
    };
  }, []);
  useEffect(() => {
    let disposed = false,
      pending = false;
    const ids = JSON.parse(idsKey) as string[];
    async function refresh() {
      if (disposed || paused || document.hidden || !unobscured() || pending || !ids.length) return;
      pending = true;
      try {
        const next = await command('otpCodes', { ids });
        if (!disposed && !document.hidden && unobscured())
          setCodes(Object.fromEntries(next.map((code) => [code.id, code])));
      } catch (e) {
        if (!disposed) setError(e);
      } finally {
        pending = false;
      }
    }
    void refresh();
    const timer = window.setInterval(() => void refresh(), 1000);
    const visibility = () => {
      if (document.hidden) setCodes({});
      else void refresh();
    };
    document.addEventListener('visibilitychange', visibility);
    return () => {
      disposed = true;
      clearInterval(timer);
      document.removeEventListener('visibilitychange', visibility);
    };
  }, [idsKey, paused, language]);
  async function run(action: () => Promise<void>) {
    if (lock.current) return;
    lock.current = true;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await action();
    } catch (e) {
      if (mounted.current) setError(e);
    } finally {
      lock.current = false;
      if (mounted.current) setBusy(false);
    }
  }
  async function edit(row: Row) {
    await run(async () => {
      const entry = await command('otpGet', { id: row.id });
      const { id, revision, ...value } = entry;
      if (mounted.current) {
        setShowSecret(false);
        setEditor({ id, revision, value });
      }
    });
  }
  function field<K extends keyof Draft>(key: K, value: Draft[K]) {
    setEditor((old) => (old ? { ...old, value: { ...old.value, [key]: value } } : old));
  }
  async function save() {
    if (!editor) return;
    await run(async () => {
      await command('otpSave', editor);
      await load();
      if (mounted.current) {
        setEditor(undefined);
        setNotice(messageRef('otp.entry_saved_9969a5a'));
      }
    });
  }
  async function copy(row: Row) {
    await run(async () => {
      const next = await command('otpCodes', { ids: [row.id] });
      await command('writeClipboard', { text: next[0].code });
      if (mounted.current) setNotice(messageRef('otp.code_copied_6d0a72e'));
    });
  }
  async function reorder(row: Row, direction: number) {
    await run(async () => {
      const previous = rows.map((r) => r.id),
        ids = [...previous],
        index = ids.indexOf(row.id);
      if (index + direction < 0 || index + direction >= ids.length) return;
      [ids[index], ids[index + direction]] = [ids[index + direction], ids[index]];
      await command('otpReorder', { previous, ids });
      await load();
    });
  }
  async function exportEntries(ids: string[], format: ExportFormat) {
    await run(async () => {
      try {
        const result = await command('otpExport', { ids, format });
        if (mounted.current) setExported({ ids, text: result, format });
      } catch (e) {
        // A label that cannot fit a URI must still have a path to lossless export.
        if (!exported && format === 'uri' && errorCode(e) === 'otp_uri_label_unsupported') {
          const result = await command('otpExport', { ids, format: 'json' });
          if (mounted.current) {
            setExported({ ids, text: result, format: 'json' });
            setError(e);
          }
        } else throw e;
      }
    });
  }
  function receiveImport(value: string) {
    if (mounted.current) setText(stageImportText(text, value));
  }
  async function readFile(file?: File) {
    if (!file) return;
    await run(async () => {
      if (file.type.startsWith('image/')) {
        receiveImport((await decodeQrImage(file)).join('\n'));
      } else {
        if (file.size > limits.maxOtpTextBytes) throw 'otp_text_too_large';
        const value = await file.text();
        receiveImport(value);
      }
    });
  }
  function close() {
    if (busy) return;
    setEditor(undefined);
    setImporting(false);
    setExported(undefined);
    setRemoving(undefined);
    setShowSecret(false);
    setText('');
    setError('');
  }
  return {
    busy,
    close,
    codes,
    codesOnly,
    copy,
    dom,
    edit,
    editor,
    error,
    exportEntries,
    exported,
    field,
    importing,
    language,
    load,
    mounted,
    notice,
    page,
    pages,
    panel,
    paused,
    query,
    readFile,
    receiveImport,
    removing,
    reorder,
    rows,
    run,
    save,
    setEditor,
    setError,
    setExported,
    setImporting,
    setNotice,
    setPage,
    setQuery,
    setRemoving,
    setShowSecret,
    setText,
    showSecret,
    shown,
    text,
    visible,
  };
}
