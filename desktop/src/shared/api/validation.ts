import contracts from '../../../contracts/ipc.generated.json' with { type: 'json' };
import type { CommandName, Request, Response, Models } from './generated/commands';

type Schema =
  | { kind: 'json' | 'null' | 'boolean' | 'number' | 'string' }
  | { kind: 'literal'; value: unknown }
  | { kind: 'ref'; name: string }
  | { kind: 'array'; items: Schema }
  | { kind: 'map'; values: Schema }
  | { kind: 'object'; fields: Record<string, { schema: Schema; optional: boolean }> }
  | { kind: 'union'; members: Schema[] };

// Both this metadata and the static types are emitted by the same Rust registry.
const registry = contracts as unknown as {
  definitions: Record<string, Schema>;
  commands: Record<CommandName, { request: Schema; response: Schema }>;
};

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function matches(schema: Schema, value: unknown, depth = 0): boolean {
  if (depth > 128) return false;
  switch (schema.kind) {
    case 'json':
      return true;
    case 'null':
      return value === null;
    case 'boolean':
      return typeof value === 'boolean';
    case 'number':
      return typeof value === 'number' && Number.isFinite(value);
    case 'string':
      return typeof value === 'string';
    case 'literal':
      return value === schema.value;
    case 'ref': {
      const target = registry.definitions[schema.name];
      return !!target && matches(target, value, depth + 1);
    }
    case 'array':
      return Array.isArray(value) && value.every((entry) => matches(schema.items, entry, depth + 1));
    case 'map':
      return object(value) && Object.values(value).every((entry) => matches(schema.values, entry, depth + 1));
    case 'object':
      return (
        object(value) &&
        Object.entries(schema.fields).every(([name, field]) =>
          value[name] === undefined ? field.optional : matches(field.schema, value[name], depth + 1),
        )
      );
    case 'union':
      return schema.members.some((member) => matches(member, value, depth + 1));
  }
}

export function isRequest<K extends CommandName>(name: K, value: unknown): value is Request<K> {
  return (
    Object.prototype.hasOwnProperty.call(registry.commands, name) &&
    matches(registry.commands[name].request, value)
  );
}

export function isResponse<K extends CommandName>(name: K, value: unknown): value is Response<K> {
  return (
    Object.prototype.hasOwnProperty.call(registry.commands, name) &&
    matches(registry.commands[name].response, value)
  );
}

export function isModel<K extends keyof Models>(name: K, value: unknown): value is Models[K] {
  return (
    Object.prototype.hasOwnProperty.call(registry.definitions, name) &&
    matches(registry.definitions[name], value)
  );
}
