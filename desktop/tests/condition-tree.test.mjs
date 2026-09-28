import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  actionOnlyKeys,
  createTree,
  serializeTree,
  findNode,
  updateNode,
  addLeaf,
  addGroup,
  addField,
  editField,
  removeField,
  replaceField,
  fieldText,
  removeNode,
  moveNode,
  wrapNode,
  unwrapNode,
  validateDraft,
  reconcileRoot,
} from '../src/routing/conditionTree.ts';

function tree(value, options = {}) {
  let n = 0;
  return createTree(value, { idFactory: () => `node-${++n}`, ...options });
}
const rule = {
  type: 'logical',
  mode: 'and',
  invert: false,
  action: 'route',
  outbound: 'proxy',
  rules: [
    { domain: ['a.test', 'b.test'], port: [80, 443], invert: true },
    { process_name: ['browser'], network: ['tcp'] },
  ],
};
const code = (fn, value) => assert.throws(fn, (e) => e.message === value);

test('action ownership matches reflected pinned core including network_type overlap', () => {
  const oracle = JSON.parse(
    readFileSync(new URL('../engine/tests/fixtures/nested-routing/action_keys.json', import.meta.url)),
  );
  assert.deepEqual(
    [...actionOnlyKeys].sort(),
    oracle.actionKeysUnion.filter((k) => !oracle.match.includes(k)).sort(),
  );
  assert.equal(actionOnlyKeys.length, 43);
  assert(!actionOnlyKeys.includes('network_type'));
  for (const key of actionOnlyKeys) {
    const input = { domain: ['a.test'], action: 'route', [key]: null };
    const original = tree(input),
      wrapped = wrapNode(original, original.root.id);
    assert.equal(serializeTree(wrapped)[key], null, key);
    assert(!Object.hasOwn(serializeTree(wrapped).rules[0], key), key);
    assert.deepEqual(serializeTree(unwrapNode(wrapped, wrapped.root.id)), input, key);
    const invalid = tree({ type: 'logical', mode: 'and', rules: [{ domain: ['a.test'], [key]: null }] });
    assert.equal(invalid.root.children[0].kind, 'raw', key);
    assert.deepEqual(serializeTree(invalid).rules[0], { domain: ['a.test'], [key]: null });
    assert.equal(validateDraft(invalid)[0].code, 'condition_tree_nested_action');
  }
});

test('import/export is exact for nested unknown fields, false/nulls and listable scalars', () => {
  const input = {
    ...rule,
    future_root: { keep: null },
    rules: [
      {
        domain: 'a.test',
        port: 80,
        network_type: ['wifi'],
        future_match: [null, false, { opaque: 'value' }],
      },
      {
        type: 'logical',
        mode: 'or',
        future_group: null,
        rules: [{ ip_is_private: false }, { port_range: ['8000:9000'], invert: true }],
      },
    ],
  };
  const model = tree(input);
  assert.deepEqual(serializeTree(model), input);
  const first = model.root.children[0].id;
  const updated = editField(model, first, 'domain', 'changed.test');
  const output = serializeTree(updated);
  assert.deepEqual(output.rules[0].future_match, input.rules[0].future_match);
  assert.deepEqual(output.future_root, input.future_root);
  assert.deepEqual(output.rules[1], input.rules[1]);
  assert.deepEqual(serializeTree(model), input);
  assert.deepEqual(input.rules[0].domain, 'a.test');
  output.rules[0].future_match[2].opaque = 'mutated export';
  assert.equal(serializeTree(updated).rules[0].future_match[2].opaque, 'value');
});

test('wrap retains flat OR field families as one match and keeps inversion with them', () => {
  const input = {
    type: 'default',
    domain: ['a.test'],
    domain_suffix: ['b.test'],
    ip_cidr: ['192.0.2.0/24'],
    port: [80, 443],
    port_range: ['9000:9010'],
    network_type: ['wifi'],
    invert: true,
    action: 'direct',
    bind_interface: 'lo',
    tcp_keep_alive_interval: '0s',
    domain_resolver: { server: 'dns-direct' },
  };
  const original = tree(input),
    wrapped = wrapNode(original, original.root.id, 'or');
  const output = serializeTree(wrapped);
  assert.equal(output.rules.length, 1);
  assert.equal(wrapped.root.children[0].id, original.root.id);
  assert.equal(output.action, 'direct');
  assert.equal(output.bind_interface, 'lo');
  assert.equal(output.invert, undefined);
  assert.equal(output.rules[0].invert, true);
  assert.deepEqual(output.rules[0].network_type, ['wifi']);
  for (const key of actionOnlyKeys) assert(!Object.hasOwn(output.rules[0], key));
  assert.deepEqual(serializeTree(unwrapNode(wrapped, wrapped.root.id)), input);
  assert.deepEqual(serializeTree(original), input);
});

test('reorder keeps stable node IDs, invalid buffers and sibling values', () => {
  let model = tree(rule),
    id = model.root.children[0].id,
    sibling = model.root.children[1].id;
  model = editField(model, id, 'port', '443,no');
  const before = serializeTree(model);
  const changed = moveNode(model, id, 1);
  assert.equal(changed.root.children[1].id, id);
  assert.equal(changed.root.children[0].id, sibling);
  assert.equal(fieldText(findNode(changed, id), 'port'), '443,no');
  assert.deepEqual(validateDraft(changed), [{ id, key: 'port', code: 'invalid_condition' }]);
  assert.deepEqual(serializeTree(changed).rules, [before.rules[1], before.rules[0]]);
  assert.equal(model.root.children[0].id, id);
  const wrapped = wrapNode(changed, id);
  assert.equal(fieldText(findNode(wrapped, id), 'port'), '443,no');
  assert.deepEqual(validateDraft(wrapped), [{ id, key: 'port', code: 'invalid_condition' }]);
  const restored = unwrapNode(wrapped, wrapped.root.children[1].id);
  assert.equal(findNode(restored, id).errors.port, true);
});

test('field add/edit/remove never discards last valid value or neighboring fields', () => {
  let model = tree(rule),
    id = model.root.children[0].id;
  model = addField(model, id, 'interface_address');
  assert.equal(fieldText(findNode(model, id), 'interface_address'), '');
  assert(validateDraft(model).some((x) => x.key === 'interface_address'));
  model = editField(model, id, 'interface_address', '{"lo":["127.0.0.1/8"]}');
  assert.deepEqual(findNode(model, id).config.interface_address, { lo: ['127.0.0.1/8'] });
  const last = serializeTree(model);
  for (const invalid of ['{', '', '  ']) {
    model = editField(model, id, 'interface_address', invalid);
    assert.deepEqual(serializeTree(model), last);
    assert.equal(fieldText(findNode(model, id), 'interface_address'), invalid);
    assert(validateDraft(model).some((x) => x.key === 'interface_address'));
  }
  model = editField(model, id, 'port', '65536');
  assert.deepEqual(findNode(model, id).config.port, [80, 443]);
  model = removeField(model, id, 'interface_address');
  assert(!Object.hasOwn(findNode(model, id).config, 'interface_address'));
  assert(!Object.hasOwn(findNode(model, id).buffers, 'interface_address'));
  assert.equal(findNode(model, id).errors.port, true);
  assert.deepEqual(findNode(model, id).config.domain, ['a.test', 'b.test']);
  assert.deepEqual(serializeTree(model).rules[1], rule.rules[1]);
  model = removeField(model, id, 'port');
  assert.deepEqual(validateDraft(model), []);
});

test('fresh groups/leaves require completing or removing the new field', () => {
  let model = tree(rule);
  model = addLeaf(model, model.root.id);
  let added = model.root.children.at(-1);
  assert.deepEqual(added.fields, ['domain_suffix']);
  assert.equal(added.errors.domain_suffix, true);
  assert.equal(added.buffers.domain_suffix, '');
  model = editField(model, added.id, 'domain_suffix', 'example.test, other.test');
  assert.deepEqual(findNode(model, added.id).config.domain_suffix, ['example.test', 'other.test']);
  assert.deepEqual(validateDraft(model), []);
  model = addGroup(model, model.root.id, 'or');
  const group = model.root.children.at(-1);
  assert.equal(group.config.mode, 'or');
  assert.equal(group.children.length, 1);
  assert.equal(group.children[0].errors.domain_suffix, true);
  model = removeNode(model, group.children[0].id);
  assert.deepEqual(validateDraft(model), [{ id: group.id, code: 'condition_tree_empty_group' }]);
  model = removeNode(model, group.id);
  assert.deepEqual(validateDraft(model), []);
  code(() => removeNode(model, model.root.id), 'condition_tree_root');
});

test('root action/mode/invert/unknown reconciliation preserves all child drafts', () => {
  let model = tree({ ...rule, future_root: { original: true } }),
    id = model.root.children[0].id;
  model = editField(model, id, 'port', 'bad');
  const incoming = {
    ...serializeTree(model),
    mode: 'or',
    invert: true,
    action: 'reject',
    method: 'drop',
    future_root: { changed: true },
  };
  delete incoming.outbound;
  const next = reconcileRoot(model, incoming);
  assert.equal(next.root.id, model.root.id);
  assert.equal(next.root.children[0].id, id);
  assert.equal(fieldText(findNode(next, id), 'port'), 'bad');
  assert.equal(findNode(next, id).errors.port, true);
  assert.equal(next.root.config.outbound, undefined);
  assert.deepEqual(serializeTree(next), incoming);
  assert.equal(serializeTree(model).action, 'route');
  const changedRules = { ...incoming, rules: [{ domain: ['replacement.test'] }] };
  code(() => reconcileRoot(next, changedRules), 'condition_tree_draft_conflict');
  const valid = editField(next, id, 'port', '80');
  const replaced = reconcileRoot(valid, changedRules);
  assert.deepEqual(serializeTree(replaced), changedRules);
  assert.notEqual(replaced.root.id, next.root.id);
});

test('unknown ownership prevents structural wrap/unwrap atomically, but edit/reorder preserve it', () => {
  const source = { domain: ['a.test'], future_ambiguous: { value: 7 }, action: 'route', outbound: 'proxy' };
  const model = tree(source);
  code(() => wrapNode(model, model.root.id), 'condition_tree_unsupported');
  assert.deepEqual(serializeTree(model), source);
  const group = tree({ type: 'logical', mode: 'and', future_group: null, rules: [{ port: [80] }] });
  code(() => unwrapNode(group, group.root.id), 'condition_tree_unwrap');
  assert.deepEqual(serializeTree(group), {
    type: 'logical',
    mode: 'and',
    future_group: null,
    rules: [{ port: [80] }],
  });
  const changed = updateNode(group, group.root.id, (n) => ({ ...n, config: { ...n.config, mode: 'or' } }));
  assert.equal(serializeTree(changed).future_group, null);
});

test('single-child unwrap composes inversion without changing the predicate truth table', () => {
  const match = (r, p) => {
    let value =
      r.type === 'logical'
        ? r.mode === 'and'
          ? r.rules.every((c) => match(c, p))
          : r.rules.some((c) => match(c, p))
        : r.port.includes(p);
    return r.invert ? !value : value;
  };
  for (const mode of ['and', 'or'])
    for (const outer of [undefined, false, true])
      for (const inner of [undefined, false, true]) {
        const input = {
          type: 'logical',
          mode,
          rules: [{ port: [80], ...(inner === undefined ? {} : { invert: inner }) }],
          action: 'route',
          outbound: 'proxy',
          ...(outer === undefined ? {} : { invert: outer }),
        };
        const model = tree(input),
          result = serializeTree(unwrapNode(model, model.root.id));
        for (const p of [80, 443]) assert.equal(match(input, p), match(result, p));
        assert.equal(result.action, 'route');
        assert.equal(result.outbound, 'proxy');
      }
  const multiple = tree(rule);
  code(() => unwrapNode(multiple, multiple.root.id), 'condition_tree_unwrap');
});

test('malformed/null/nested action branches are opaque and round trip without defaults', () => {
  for (const source of [
    null,
    [],
    7,
    'text',
    { type: null, domain: ['a.test'] },
    { type: 'future', opaque: [1] },
    { type: 'logical', mode: 'xor', rules: [{ port: [80] }] },
    { type: 'logical', mode: 'and', rules: null },
    { type: 'logical', mode: 'and', rules: [null, { action: null, port: [80] }, ['x']] },
    { port: null, invert: null },
    { rules: [] },
  ]) {
    const model = tree(source);
    assert.deepEqual(serializeTree(model), source);
    assert(validateDraft(model).length > 0, JSON.stringify(source));
  }
  const model = tree({ type: 'logical', mode: 'and', rules: [] });
  assert.equal(model.root.kind, 'group');
  assert.equal(validateDraft(model)[0].code, 'condition_tree_empty_group');
});

test('independent real-core rejection fixtures are preserved and flagged by the model', () => {
  const oracle = JSON.parse(
    readFileSync(new URL('../engine/tests/fixtures/nested-routing/matrix.json', import.meta.url)),
  );
  assert.equal(oracle.invalid.length, 13);
  for (const fixture of oracle.invalid) {
    const model = tree(fixture.condition);
    assert.deepEqual(serializeTree(model), fixture.condition, fixture.name);
    assert(validateDraft(model).length > 0, fixture.name);
  }
  let model = tree(rule);
  model = addLeaf(model, model.root.id);
  const id = model.root.children.at(-1).id;
  model = removeField(model, id, 'domain_suffix');
  assert.deepEqual(validateDraft(model), [{ id, code: 'invalid_condition' }]);
});

test('all 32 independently accepted core predicates round trip through singleton wrap and unwrap', () => {
  const oracle = JSON.parse(
    readFileSync(new URL('../engine/tests/fixtures/nested-routing/matrix.json', import.meta.url)),
  );
  assert.equal(oracle.http.length, 32);
  for (const fixture of oracle.http) {
    const source = { ...fixture.condition, action: 'route', outbound: 'proxy' };
    const model = tree(source);
    assert.deepEqual(serializeTree(model), source, fixture.name);
    assert.deepEqual(validateDraft(model), [], fixture.name);
    const grouped = wrapNode(model, model.root.id, 'and');
    assert.equal(grouped.root.children.length, 1, fixture.name);
    assert.deepEqual(serializeTree(grouped).rules[0], fixture.condition, fixture.name);
    assert.deepEqual(serializeTree(unwrapNode(grouped, grouped.root.id)), source, fixture.name);
  }
});

test('constructor limits never truncate imported oversized or very deep JSON', () => {
  const huge = {
    type: 'logical',
    mode: 'or',
    rules: Array.from({ length: 300 }, (_, i) => ({ port: [i + 1] })),
    unknown: 'preserved',
  };
  const model = tree(huge);
  assert.equal(model.root.kind, 'raw');
  assert.equal(model.root.reason, 'condition_tree_limit');
  assert.deepEqual(serializeTree(model), huge);
  let deep = { port: [80], opaque: { last: null } };
  for (let i = 0; i < 12000; i++) deep = { type: 'logical', mode: i % 2 ? 'and' : 'or', rules: [deep] };
  const limited = tree(deep, { maxDepth: 4 });
  let visible = limited.root;
  for (let i = 0; i < 3; i++) visible = visible.children[0];
  assert.equal(visible.kind, 'raw');
  assert.equal(visible.reason, 'condition_tree_limit');
  let result = serializeTree(limited);
  for (let i = 0; i < 12000; i++) {
    assert.equal(result.mode, i % 2 ? 'or' : 'and');
    result = result.rules[0];
  }
  assert.deepEqual(result, { port: [80], opaque: { last: null } });
  const small = tree({ type: 'logical', mode: 'and', rules: [{ port: [80] }] }, { maxDepth: 2, maxNodes: 3 });
  code(() => wrapNode(small, small.root.children[0].id), 'condition_tree_limit');
  code(() => addGroup(small, small.root.id), 'condition_tree_limit');
  assert.deepEqual(serializeTree(small), { type: 'logical', mode: 'and', rules: [{ port: [80] }] });
  const full = addLeaf(small, small.root.id);
  code(() => addLeaf(full, full.root.id), 'condition_tree_limit');
});

test('opaque overflow in a later sibling preserves the entire original group', () => {
  const input = {
    type: 'logical',
    mode: 'and',
    rules: [
      { type: 'logical', mode: 'or', rules: [{ port: [80] }, { port: [443] }] },
      { type: 'logical', mode: 'or', rules: [{ domain: ['a.test'] }, { domain: ['b.test'] }] },
    ],
  };
  assert.deepEqual(serializeTree(tree(input, { maxNodes: 4 })), input);
});

test('updates cannot mutate caller input, inject nested actions or replace node identity', () => {
  const model = tree(rule),
    id = model.root.children[0].id;
  code(
    () =>
      updateNode(model, id, (n) => {
        n.config.domain[0] = 'mutated';
        n.config.action = 'reject';
        return n;
      }),
    'condition_tree_nested_action',
  );
  assert.equal(findNode(model, id).config.domain[0], 'a.test');
  code(() => updateNode(model, id, (n) => ({ ...n, id: 'replacement' })), 'condition_tree_node');
  code(
    () => updateNode(model, model.root.id, (n) => ({ ...n, config: { ...n.config, rules: [] } })),
    'condition_tree_unsupported',
  );
  code(() => addLeaf(model, id), 'condition_tree_parent');
  code(() => editField(model, id, 'outbound', 'direct'), 'condition_tree_field');
  code(() => findNode(model, 'missing') ?? removeNode(model, 'missing'), 'condition_tree_node');
  code(() => createTree(rule, { idFactory: () => 'collision' }), 'condition_tree_node');
});

test('unknown prototype-looking JSON keys remain own data without pollution', () => {
  const source = JSON.parse(
    '{"type":"logical","mode":"and","__proto__":{"polluted":true},"rules":[{"port":[80],"constructor":{"safe":null}}]}',
  );
  const model = tree(source),
    output = serializeTree(model);
  assert.deepEqual(output, source);
  assert.equal({}.polluted, undefined);
  assert(Object.hasOwn(output, '__proto__'));
  const changed = editField(model, model.root.children[0].id, 'port', '443');
  assert.deepEqual(serializeTree(changed).rules[0].constructor, { safe: null });
  assert.equal({}.polluted, undefined);
});

test('changing a condition field keeps the row in its place', () => {
  let model = tree(rule),
    id = model.root.children[0].id;
  assert.deepEqual(findNode(model, id).fields, ['domain', 'port']);
  model = replaceField(model, id, 'domain', 'domain_suffix');
  assert.deepEqual(findNode(model, id).fields, ['domain_suffix', 'port']);
  assert.equal(findNode(model, id).errors.domain_suffix, true);
});
