// Controller for the single diagnostics: one request at a time, cancelled when the view leaves.
import { useEffect, useRef, useState } from 'react';
import { command } from '../api';
import { errorCode } from '../shared/api/errors.ts';
import { message as probeMessage } from '../probes/messages.ts';
import type { Result } from './testActionsModel.ts';
import type { Language } from '../shared/i18n/index.ts';

export type TestName = 'testInternet' | 'testIp' | 'testSpeed';

export function useTestActions(
  selected: string | null | undefined,
  language: Language,
  translateError: (e: unknown) => string,
) {
  const [busy, setBusy] = useState<TestName | ''>('');
  const [error, setError] = useState('');
  const [result, setResult] = useState<Result>();
  const request = useRef<string | null>(null);
  useEffect(() => {
    setBusy('');
    setError('');
    setResult(undefined);
    return () => {
      const id = request.current;
      request.current = null;
      if (id) void command('cancelSettingsTest', { requestId: id }).catch(() => {});
    };
  }, [selected]);
  function explain(e: unknown) {
    const code = errorCode(e);
    return code.startsWith('probe_') ? probeMessage(e, language) : translateError(e);
  }
  async function run(name: TestName) {
    if (request.current || (name !== 'testInternet' && !selected)) return;
    const id = crypto.randomUUID();
    request.current = id;
    setBusy(name);
    setError('');
    setResult(undefined);
    try {
      const data =
        name === 'testInternet'
          ? await command('testInternet', { requestId: id })
          : await command(name, { id: selected!, requestId: id });
      if (request.current === id) setResult(data.result);
    } catch (e) {
      if (request.current === id) setError(explain(e));
    } finally {
      if (request.current === id) {
        request.current = null;
        setBusy('');
      }
    }
  }
  async function cancel() {
    const id = request.current;
    if (id)
      try {
        await command('cancelSettingsTest', { requestId: id });
      } catch (e) {
        if (request.current === id) setError(explain(e));
      }
  }
  return { busy, error, result, run, cancel };
}
