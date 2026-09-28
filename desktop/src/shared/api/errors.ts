import contracts from '../../../contracts/ipc.generated.json' with { type: 'json' };
import type { ErrorCode } from './generated/commands';

const known = new Set<string>(contracts.errorCodes);

export class ApiError extends Error {
  readonly code: ErrorCode;
  readonly field?: string;
  readonly safeParams?: Readonly<{ fields: string }>;

  constructor(code: ErrorCode, field?: string, safeParams?: Readonly<{ fields: string }>) {
    super(code);
    this.name = 'ApiError';
    this.code = code;
    this.field = field;
    this.safeParams = safeParams;
  }
}

export function boundaryError(value: unknown): ApiError {
  if (value instanceof ApiError) return value;
  const record = value && typeof value === 'object' ? (value as Record<string, unknown>) : undefined;
  const candidate = record?.code ?? (typeof value === 'string' ? value.split(':', 1)[0] : undefined);
  const code =
    typeof candidate === 'string' && known.has(candidate) ? (candidate as ErrorCode) : 'operation_failed';
  // Fields originate in the native schema, never in a backend dump or user value.
  const field =
    typeof record?.field === 'string' &&
    /^\$(?:\.[A-Za-z0-9_*]+|\[\d+\])*$/.test(record.field) &&
    record.field.length < 512
      ? record.field
      : undefined;
  const params = record?.safeParams;
  const fields = params && typeof params === 'object' && 'fields' in params ? params.fields : undefined;
  const safeParams =
    code === 'settings_conflict' &&
    typeof fields === 'string' &&
    fields.length < 8192 &&
    /^[a-z0-9_]+(?:,[a-z0-9_]+)*$/.test(fields)
      ? { fields }
      : undefined;
  return new ApiError(code, field, safeParams);
}

/** A local failure: a code plus safe values its message may show (never user secrets). */
export class CodedError extends Error {
  readonly code: string;
  readonly params: Readonly<Record<string, string>>;
  constructor(code: string, params: Readonly<Record<string, string>> = {}) {
    const values = Object.values(params);
    super(values.length ? `${code}:${values.join(', ')}` : code);
    this.name = 'CodedError';
    this.code = code;
    this.params = params;
  }
}
const codeShape = /^[a-z][A-Za-z0-9_]*$/;
/**
 * The code of a failure: a boundary error's code, or a local error whose
 * message is itself a code (`throw Error('routing_import_invalid')`). Any other
 * message, such as a runtime `TypeError`, is `operation_failed`, never text.
 */
export function errorCode(value: unknown): string {
  if (value instanceof ApiError || value instanceof CodedError) return value.code;
  const message = value instanceof Error ? value.message : typeof value === 'string' ? value : undefined;
  if (message === undefined) return boundaryError(value).code;
  return codeShape.test(message) ? message : 'operation_failed';
}
