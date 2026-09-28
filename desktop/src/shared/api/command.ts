import { invoke, isTauri } from '@tauri-apps/api/core';
import type { CommandName, Request, Response } from './generated/commands';
import { ApiError, boundaryError } from './errors';
import { isRequest, isResponse } from './validation';

export type CommandArgs<K extends CommandName> =
  Record<string, never> extends Request<K> ? [payload?: Request<K>] : [payload: Request<K>];

export async function command<K extends CommandName>(name: K, ...args: CommandArgs<K>): Promise<Response<K>> {
  if (!isTauri()) throw new ApiError('desktop_required');
  const payload = args[0] ?? {};
  if (!isRequest(name, payload)) throw new ApiError('invalid_command_payload');
  let result: unknown;
  try {
    result = await invoke<unknown>('app_command', { name, payload });
  } catch (error) {
    throw boundaryError(error);
  }
  if (!isResponse(name, result)) throw new ApiError('invalid_command_response');
  return result;
}
