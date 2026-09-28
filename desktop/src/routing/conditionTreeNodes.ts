// Condition trees: node model, limits, reading JSON into nodes and writing nodes back.
import { limits as builderLimits } from '../shared/limits.ts';
import type { Config } from '../profiles/schema';
import { matches } from './model.ts';
import { parseRuleValue } from './ruleInput.ts';
import { headlessFields, parseHeadlessField, headlessValueShape } from './headlessFields.ts';
export type ConditionNode = {
  id: string;
  kind: 'leaf' | 'group' | 'raw' | 'set';
  config: Config;
  children: ConditionNode[];
  fields: string[];
  buffers: Record<string, string>;
  errors: Record<string, boolean>;
  raw?: unknown;
  reason?: string;
};
export type TreeLimits = { maxDepth: number; maxNodes: number };
export type ConditionSchema = 'route' | 'headless';
export type ConditionTree = {
  root: ConditionNode;
  limits: TreeLimits;
  idFactory: () => string;
  schema: ConditionSchema;
  collection: boolean;
};
export type TreeIssue = { id: string; key?: string; code: string };
export type TreeOptions = Partial<TreeLimits> & { idFactory?: () => string; schema?: ConditionSchema };

// Reflected from pinned option.RuleAction variants, minus RawDefaultRule keys:
// engine/tests/fixtures/nested-routing/action_keys.json. network_type belongs
// to the match object first, even for a root action="direct".
export const actionOnlyKeys: readonly string[] = [
  'action',
  'bind_address_no_port',
  'bind_interface',
  'client_subnet',
  'connect_timeout',
  'disable_cache',
  'disable_optimistic_cache',
  'disable_tcp_keep_alive',
  'domain_resolver',
  'domain_strategy',
  'fallback_delay',
  'fallback_network_type',
  'inet4_bind_address',
  'inet6_bind_address',
  'method',
  'netns',
  'network_strategy',
  'no_drop',
  'outbound',
  'override_address',
  'override_destination',
  'override_port',
  'protect_path',
  'reuse_addr',
  'rewrite_ttl',
  'routing_mark',
  'server',
  'sniffer',
  'strategy',
  'tcp_fast_open',
  'tcp_keep_alive',
  'tcp_keep_alive_interval',
  'tcp_multi_path',
  'timeout',
  'tls_fragment',
  'tls_fragment_fallback_delay',
  'tls_record_fragment',
  'tls_spoof',
  'tls_spoof_method',
  'udp_connect',
  'udp_disable_domain_unmapping',
  'udp_fragment',
  'udp_timeout',
];
export const actionKeys = new Set(actionOnlyKeys);
const matchKeys = new Set([
  ...matches.map((f) => f.key),
  'invert',
  'geosite',
  'geoip',
  'source_geoip',
  'rule_set_ipcidr_match_source',
]);
const headlessKeys = new Set([...headlessFields.map((f) => f.key), 'invert']);
export const fieldsFor = (schema: ConditionSchema) => (schema === 'headless' ? headlessFields : matches);
export const keysFor = (schema: ConditionSchema) => (schema === 'headless' ? headlessKeys : matchKeys);
export const parseField = (schema: ConditionSchema, selected: (typeof matches)[number], text: string) =>
  schema === 'headless' ? parseHeadlessField(selected, text) : parseRuleValue(selected, text);
export const object = (value: unknown): value is Config =>
  !!value && typeof value === 'object' && !Array.isArray(value);
export const own = (value: object, key: string) => Object.prototype.hasOwnProperty.call(value, key);
export const fail = (code: string): never => {
  throw Error(code);
};

// JSON input may be deeper than the form limit. Iterative copying preserves
// the complete opaque subtree without JSON.stringify/recursive stack limits.
export function copy<T>(value: T): T {
  if (!value || typeof value !== 'object') return value;
  const result: unknown[] | Config = Array.isArray(value) ? [] : {};
  const seen = new Map<object, unknown>([[value, result]]);
  const pending: [object, unknown[] | Config][] = [[value, result]];
  while (pending.length) {
    const [source, target] = pending.pop()!;
    for (const key of Object.keys(source)) {
      const child = (source as Config)[key];
      let next = child;
      if (child && typeof child === 'object') {
        if (seen.has(child)) next = seen.get(child);
        else {
          next = Array.isArray(child) ? [] : {};
          seen.set(child, next);
          pending.push([child, next as Config]);
        }
      }
      Object.defineProperty(target, key, {
        value: next,
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
  }
  return result as T;
}
export function equal(left: unknown, right: unknown): boolean {
  const pending: [unknown, unknown][] = [[left, right]];
  const seen = new Map<object, Set<object>>();
  while (pending.length) {
    const [a, b] = pending.pop()!;
    if (Object.is(a, b)) continue;
    if (!a || !b || typeof a !== 'object' || typeof b !== 'object' || Array.isArray(a) !== Array.isArray(b))
      return false;
    if (seen.get(a)?.has(b)) continue;
    if (!seen.has(a)) seen.set(a, new Set());
    seen.get(a)!.add(b);
    const keys = Object.keys(a);
    if (keys.length !== Object.keys(b).length) return false;
    for (const key of keys) {
      if (!own(b, key)) return false;
      pending.push([(a as Config)[key], (b as Config)[key]]);
    }
  }
  return true;
}
export function nextId(tree: Pick<ConditionTree, 'idFactory'>, used: Set<string>): string {
  const id = tree.idFactory();
  if (!id || used.has(id)) fail('condition_tree_node');
  used.add(id);
  return id;
}
export function blank(id: string, kind: ConditionNode['kind'], config: Config): ConditionNode {
  return { id, kind, config, children: [], fields: [], buffers: {}, errors: {} };
}
export function createTree(raw: unknown, options: TreeOptions = {}): ConditionTree {
  return create(raw, options, false);
}
/** Editor-only collection container. Wire JSON remains the exact rule array,
 * whose entries are combined with OR. Empty source arrays are preserved, but
 * the pinned core's inline-set constructor rejects them. */
export function createRuleSetTree(raw: unknown, options: TreeOptions = {}): ConditionTree {
  return create(raw, { ...options, schema: 'headless' }, true);
}
function create(raw: unknown, options: TreeOptions, collection: boolean): ConditionTree {
  const schema = options.schema ?? 'route';
  if (schema !== 'route' && schema !== 'headless') fail('condition_tree_unsupported');
  const limits = {
    maxDepth: options.maxDepth ?? builderLimits.maxConditionDepth,
    maxNodes: options.maxNodes ?? builderLimits.maxConditionNodes,
  };
  if (
    !Number.isInteger(limits.maxDepth) ||
    limits.maxDepth < 1 ||
    limits.maxDepth > 64 ||
    !Number.isInteger(limits.maxNodes) ||
    limits.maxNodes < 1 ||
    limits.maxNodes > 4096
  )
    fail('condition_tree_limit');
  const idFactory = options.idFactory ?? (() => crypto.randomUUID());
  const used = new Set<string>();
  const source = copy(raw);
  let count = 0;
  function read(value: unknown, depth: number): ConditionNode {
    const node = blank(nextId({ idFactory }, used), 'raw', object(value) ? { ...value } : {});
    count++;
    const opaque = (reason: string) => {
      node.raw = value;
      node.reason = reason;
      return node;
    };
    if (!object(value)) return opaque('condition_tree_unsupported');
    if ((schema === 'headless' || depth > 1) && Object.keys(value).some((k) => actionKeys.has(k)))
      return opaque('condition_tree_nested_action');
    if (schema === 'headless') {
      const allowed =
        value.type === 'logical'
          ? new Set(['type', 'mode', 'rules', 'invert'])
          : new Set(['type', ...headlessKeys]);
      if (Object.keys(value).some((k) => !allowed.has(k))) return opaque('condition_tree_unsupported');
    }
    if (own(value, 'invert') && typeof value.invert !== 'boolean')
      return opaque('condition_tree_unsupported');
    if (value.type === 'logical') {
      if (Object.keys(value).some((k) => k !== 'invert' && keysFor(schema).has(k)))
        return opaque('condition_tree_unsupported');
      if (!['and', 'or'].includes(String(value.mode)) || !Array.isArray(value.rules))
        return opaque('condition_tree_unsupported');
      if ((depth >= limits.maxDepth && value.rules.length) || count + value.rules.length > limits.maxNodes)
        return opaque('condition_tree_limit');
      node.kind = 'group';
      // If expansion of an earlier sibling exhausts the budget, retain the
      // whole group as one opaque node instead of dropping remaining rules.
      for (const child of value.rules) {
        if (count >= limits.maxNodes) {
          node.kind = 'raw';
          node.children = [];
          return opaque('condition_tree_limit');
        }
        node.children.push(read(child, depth + 1));
      }
    } else {
      if (
        (own(value, 'type') && value.type !== '' && value.type !== 'default') ||
        own(value, 'rules') ||
        own(value, 'mode')
      )
        return opaque('condition_tree_unsupported');
      const present = fieldsFor(schema).filter((f) => own(value, f.key));
      if (
        schema === 'headless' &&
        (!present.length || present.some((f) => !headlessValueShape(f, value[f.key])))
      )
        return opaque('condition_tree_unsupported');
      node.kind = 'leaf';
      node.fields = present.map((f) => f.key);
    }
    return node;
  }
  if (!collection) return { root: read(source, 1), limits, idFactory, schema, collection };
  const root = blank(nextId({ idFactory }, used), 'set', {});
  if (!Array.isArray(source) || source.length > limits.maxNodes) {
    root.kind = 'raw';
    root.raw = source;
    root.reason = Array.isArray(source) ? 'condition_tree_limit' : 'condition_tree_unsupported';
  } else {
    for (const child of source) {
      if (count >= limits.maxNodes) {
        root.kind = 'raw';
        root.raw = source;
        root.reason = 'condition_tree_limit';
        root.children = [];
        break;
      }
      root.children.push(read(child, 1));
    }
  }
  return { root, limits, idFactory, schema, collection };
}
export function serialize(node: ConditionNode): unknown {
  if (node.kind === 'raw') return copy(node.raw);
  if (node.kind === 'set') return node.children.map(serialize);
  const config = copy(node.config);
  if (node.kind === 'group') config.rules = node.children.map(serialize);
  return config;
}
/** Serialization does not discard invalid buffers. Call validateDraft before
 * changing to JSON or saving; invalid edits retain their last parsed value. */
export function serializeTree(tree: ConditionTree): unknown {
  return serialize(tree.root);
}
export function nodes(tree: ConditionTree): ConditionNode[] {
  const result: ConditionNode[] = [],
    pending = [tree.root];
  while (pending.length) {
    const node = pending.pop()!;
    result.push(node);
    pending.push(...node.children);
  }
  return result;
}
export function findNode(tree: ConditionTree, id: string): ConditionNode | undefined {
  return nodes(tree).find((n) => n.id === id);
}
export function requireNode(tree: ConditionTree, id: string): ConditionNode {
  return findNode(tree, id) ?? fail('condition_tree_node');
}
export function replace(
  tree: ConditionTree,
  id: string,
  transform: (node: ConditionNode) => ConditionNode,
): ConditionTree {
  requireNode(tree, id);
  function visit(node: ConditionNode): ConditionNode {
    if (node.id === id) return transform(node);
    const children = node.children.map(visit);
    return children.some((c, i) => c !== node.children[i]) ? { ...node, children } : node;
  }
  return { ...tree, root: visit(tree.root) };
}
export function bounded(tree: ConditionTree): ConditionTree {
  let count = 0;
  const ids = new Set<string>(),
    pending: [ConditionNode, number][] = [[tree.root, tree.collection ? 0 : 1]];
  while (pending.length) {
    const [node, depth] = pending.pop()!;
    if (
      ((node !== tree.root || !tree.collection) && ++count > tree.limits.maxNodes) ||
      depth > tree.limits.maxDepth
    )
      fail('condition_tree_limit');
    if (!node.id || ids.has(node.id)) fail('condition_tree_node');
    ids.add(node.id);
    if (
      node.kind !== 'raw' &&
      (tree.schema === 'headless' || node !== tree.root) &&
      Object.keys(node.config).some((k) => actionKeys.has(k))
    )
      fail('condition_tree_nested_action');
    if (tree.schema === 'headless' && node.kind !== 'raw') {
      const allowed =
        node.kind === 'set'
          ? new Set<string>()
          : node.kind === 'group'
            ? new Set(['type', 'mode', 'rules', 'invert'])
            : new Set(['type', ...headlessKeys]);
      if (Object.keys(node.config).some((k) => !allowed.has(k))) fail('condition_tree_unsupported');
    }
    pending.push(...node.children.map((c) => [c, depth + 1] as [ConditionNode, number]));
  }
  return tree;
}
