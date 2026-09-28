// Editing operations on condition trees; the node model lives in conditionTreeNodes.
import type { Config } from '../profiles/schema';
import { defaultCondition } from './model.ts';
import { formatRuleValue } from './ruleInput.ts';
import { formatHeadlessField } from './headlessFields.ts';
import {
  actionKeys,
  actionOnlyKeys,
  createRuleSetTree,
  createTree,
  serializeTree,
  blank,
  bounded,
  copy,
  equal,
  fail,
  fieldsFor,
  keysFor,
  nextId,
  nodes,
  object,
  own,
  parseField,
  replace,
  requireNode,
  serialize,
  type ConditionNode,
  type ConditionSchema,
  type ConditionTree,
  type TreeIssue,
} from './conditionTreeNodes.ts';
export {
  actionOnlyKeys,
  createRuleSetTree,
  createTree,
  findNode,
  serializeTree,
  type ConditionNode,
  type ConditionSchema,
  type ConditionTree,
  type TreeIssue,
  type TreeLimits,
  type TreeOptions,
} from './conditionTreeNodes.ts';

export function updateNode(
  tree: ConditionTree,
  id: string,
  transform: (node: ConditionNode) => ConditionNode,
): ConditionTree {
  const current = requireNode(tree, id);
  if (current.kind === 'raw' || current.kind === 'set') fail('condition_tree_unsupported');
  const changed = copy(transform(copy(current)));
  if (changed.id !== id || changed.kind !== current.kind || !object(changed.config))
    fail('condition_tree_node');
  if (current.kind === 'group' && !equal(changed.config.rules, current.config.rules))
    fail('condition_tree_unsupported');
  return bounded(replace(tree, id, () => changed));
}
function field(key: string, schema: ConditionSchema = 'route') {
  return fieldsFor(schema).find((f) => f.key === key) ?? fail('condition_tree_field');
}
export function addField(tree: ConditionTree, id: string, key: string): ConditionTree {
  field(key, tree.schema);
  return updateNode(tree, id, (node) => {
    if (node.kind !== 'leaf') fail('condition_tree_field');
    if (node.fields.includes(key)) return node;
    return {
      ...node,
      fields: [...node.fields, key],
      buffers: { ...node.buffers, [key]: '' },
      errors: { ...node.errors, [key]: true },
    };
  });
}
export function editField(tree: ConditionTree, id: string, key: string, text: string): ConditionTree {
  const selected = field(key, tree.schema);
  return updateNode(tree, id, (node) => {
    if (node.kind !== 'leaf' || !node.fields.includes(key)) fail('condition_tree_field');
    node.buffers[key] = text;
    try {
      const parsed = parseField(tree.schema, selected, text);
      if (parsed === undefined) node.errors[key] = true;
      else {
        node.config[key] = parsed;
        node.errors[key] = false;
      }
    } catch {
      node.errors[key] = true;
    }
    return node;
  });
}
export function removeField(tree: ConditionTree, id: string, key: string): ConditionTree {
  field(key, tree.schema);
  return updateNode(tree, id, (node) => {
    if (node.kind !== 'leaf') fail('condition_tree_field');
    delete node.config[key];
    delete node.buffers[key];
    delete node.errors[key];
    node.fields = node.fields.filter((k) => k !== key);
    return node;
  });
}
/** Changes a condition's field in place, so the row keeps its position. */
export function replaceField(tree: ConditionTree, id: string, from: string, to: string): ConditionTree {
  if (from === to) return tree;
  field(to, tree.schema);
  const current = requireNode(tree, id);
  const position = current.kind === 'leaf' ? current.fields.indexOf(from) : -1;
  const next = addField(removeField(tree, id, from), id, to);
  return updateNode(next, id, (node) => {
    if (position < 0) return node;
    const fields = node.fields.filter((k) => k !== to);
    fields.splice(position, 0, to);
    return { ...node, fields };
  });
}
function fresh(
  tree: ConditionTree,
  kind: 'leaf' | 'group',
  used: Set<string>,
  mode: 'and' | 'or' = 'and',
): ConditionNode {
  const node = blank(nextId(tree, used), kind, kind === 'group' ? { type: 'logical', mode, rules: [] } : {});
  if (kind === 'leaf') {
    node.fields = [defaultCondition];
    node.buffers[defaultCondition] = '';
    node.errors[defaultCondition] = true;
  } else node.children = [fresh(tree, 'leaf', used)];
  return node;
}
function append(
  tree: ConditionTree,
  parentId: string,
  kind: 'leaf' | 'group',
  mode: 'and' | 'or',
): ConditionTree {
  if (!['group', 'set'].includes(requireNode(tree, parentId).kind)) fail('condition_tree_parent');
  if (!['and', 'or'].includes(mode)) fail('condition_tree_unsupported');
  const child = fresh(tree, kind, new Set(nodes(tree).map((n) => n.id)), mode);
  return bounded(replace(tree, parentId, (parent) => ({ ...parent, children: [...parent.children, child] })));
}
export const addLeaf = (tree: ConditionTree, parentId: string): ConditionTree =>
  append(tree, parentId, 'leaf', 'and');
export const addGroup = (tree: ConditionTree, parentId: string, mode: 'and' | 'or' = 'and'): ConditionTree =>
  append(tree, parentId, 'group', mode);
function parentOf(tree: ConditionTree, id: string): ConditionNode {
  if (id === tree.root.id) fail('condition_tree_root');
  requireNode(tree, id);
  return nodes(tree).find((n) => n.children.some((c) => c.id === id)) ?? fail('condition_tree_parent');
}
export function removeNode(tree: ConditionTree, id: string): ConditionTree {
  const parent = parentOf(tree, id);
  return replace(tree, parent.id, (node) => ({
    ...node,
    children: node.children.filter((c) => c.id !== id),
  }));
}
export function moveNode(tree: ConditionTree, id: string, offset: -1 | 1): ConditionTree {
  const parent = parentOf(tree, id),
    at = parent.children.findIndex((c) => c.id === id);
  if (offset !== -1 && offset !== 1) fail('condition_tree_node');
  if (at + offset < 0 || at + offset >= parent.children.length) return tree;
  return replace(tree, parent.id, (node) => {
    const children = [...node.children];
    [children[at], children[at + offset]] = [children[at + offset], children[at]];
    return { ...node, children };
  });
}
export function wrapNode(tree: ConditionTree, id: string, mode: 'and' | 'or' = 'and'): ConditionTree {
  const current = requireNode(tree, id),
    root = id === tree.root.id;
  if (current.kind === 'raw' || current.kind === 'set' || !['and', 'or'].includes(mode))
    fail('condition_tree_unsupported');
  const known =
    current.kind === 'group'
      ? new Set(['type', 'mode', 'rules', 'invert'])
      : new Set(['type', ...keysFor(tree.schema)]);
  if (
    Object.keys(current.config).some(
      (k) => !known.has(k) && !(tree.schema === 'route' && root && actionKeys.has(k)),
    )
  )
    fail('condition_tree_unsupported');
  const child = { ...current, config: { ...current.config } },
    actions: Config = {};
  if (root && tree.schema === 'route')
    for (const key of actionOnlyKeys)
      if (own(child.config, key)) {
        actions[key] = child.config[key];
        delete child.config[key];
      }
  const group = blank(nextId(tree, new Set(nodes(tree).map((n) => n.id))), 'group', {
    ...actions,
    type: 'logical',
    mode,
    rules: [],
  });
  group.children = [child];
  return bounded(replace(tree, id, () => group));
}
export function unwrapNode(tree: ConditionTree, id: string): ConditionTree {
  const group = requireNode(tree, id),
    root = id === tree.root.id;
  if (group.kind !== 'group' || group.children.length !== 1 || group.children[0].kind === 'raw')
    fail('condition_tree_unwrap');
  if (
    Object.keys(group.config).some(
      (k) =>
        !['type', 'mode', 'rules', 'invert'].includes(k) &&
        !(tree.schema === 'route' && root && actionKeys.has(k)),
    )
  )
    fail('condition_tree_unwrap');
  const child = { ...group.children[0], config: { ...group.children[0].config } };
  if (
    (own(group.config, 'invert') && typeof group.config.invert !== 'boolean') ||
    (own(child.config, 'invert') && typeof child.config.invert !== 'boolean')
  )
    fail('condition_tree_unwrap');
  if (group.config.invert === true) child.config.invert = child.config.invert !== true;
  if (root && tree.schema === 'route')
    for (const key of actionOnlyKeys) if (own(group.config, key)) child.config[key] = group.config[key];
  return bounded(replace(tree, id, () => child));
}
export function validateDraft(tree: ConditionTree): TreeIssue[] {
  const issues: TreeIssue[] = [];
  for (const node of nodes(tree)) {
    if (node.kind === 'set') {
      if (!node.children.length) issues.push({ id: node.id, code: 'condition_tree_empty_set' });
      continue;
    }
    if (node.kind === 'raw') {
      issues.push({
        id: node.id,
        code: node.reason === 'condition_tree_nested_action' ? node.reason : 'condition_tree_raw',
      });
      continue;
    }
    if (node.kind === 'group') {
      if (!node.children.length) issues.push({ id: node.id, code: 'condition_tree_empty_group' });
      if (
        node.config.type !== 'logical' ||
        !['and', 'or'].includes(String(node.config.mode)) ||
        Object.keys(node.config).some((k) => k !== 'invert' && keysFor(tree.schema).has(k))
      )
        issues.push({ id: node.id, code: 'condition_tree_unsupported' });
    }
    if (
      node.kind === 'leaf' &&
      (tree.schema === 'headless' || node !== tree.root) &&
      !node.fields.length &&
      Object.keys(node.config).every((k) => k === 'type' || k === 'invert')
    )
      issues.push({ id: node.id, code: 'invalid_condition' });
    if (own(node.config, 'invert') && typeof node.config.invert !== 'boolean')
      issues.push({ id: node.id, key: 'invert', code: 'invalid_condition' });
    for (const key of node.fields) {
      let invalid = node.errors[key] === true;
      if (own(node.buffers, key)) {
        try {
          invalid ||= parseField(tree.schema, field(key, tree.schema), node.buffers[key]) === undefined;
        } catch {
          invalid = true;
        }
      } else if (!own(node.config, key)) invalid = true;
      if (invalid) issues.push({ id: node.id, key, code: 'invalid_condition' });
    }
  }
  return issues;
}
export function reconcileRoot(tree: ConditionTree, nextRoot: Config): ConditionTree {
  if (tree.collection) fail('condition_tree_root');
  if (!object(nextRoot)) fail('condition_tree_unsupported');
  const headerSupported =
    tree.schema !== 'headless' ||
    (Object.keys(nextRoot).every((k) => ['type', 'mode', 'rules', 'invert'].includes(k)) &&
      ['and', 'or'].includes(String(nextRoot.mode)) &&
      (!own(nextRoot, 'invert') || typeof nextRoot.invert === 'boolean'));
  if (
    tree.root.kind === 'group' &&
    nextRoot.type === 'logical' &&
    headerSupported &&
    equal(nextRoot.rules, tree.root.children.map(serialize))
  ) {
    return { ...tree, root: { ...tree.root, config: copy(nextRoot) } };
  }
  if (equal(serializeTree(tree), nextRoot)) return tree;
  if (
    nodes(tree).some((n) => Object.values(n.errors).some(Boolean) || n.fields.some((k) => !own(n.config, k)))
  )
    fail('condition_tree_draft_conflict');
  return createTree(nextRoot, { ...tree.limits, idFactory: tree.idFactory, schema: tree.schema });
}

export function reconcileRuleSet(tree: ConditionTree, nextRules: unknown): ConditionTree {
  if (!tree.collection || tree.schema !== 'headless') fail('condition_tree_root');
  if (equal(serializeTree(tree), nextRules)) return tree;
  if (
    nodes(tree).some((n) => Object.values(n.errors).some(Boolean) || n.fields.some((k) => !own(n.config, k)))
  )
    fail('condition_tree_draft_conflict');
  return createRuleSetTree(nextRules, { ...tree.limits, idFactory: tree.idFactory });
}

export function fieldText(node: ConditionNode, key: string, schema: ConditionSchema = 'route'): string {
  return (
    node.buffers[key] ??
    (schema === 'headless'
      ? formatHeadlessField(field(key, schema), node.config[key])
      : formatRuleValue(field(key), node.config[key]))
  );
}
