import test from 'node:test';
import assert from 'node:assert/strict';
import { orderBlocked, orderNeighbor, orderText, orderHint } from '../src/library/profileOrder.ts';

const context = {busy:false,selecting:false,query:'',protocol:'',favorites:false,sort:'original'};
test('manual order permits original view and blocks every row filter including whitespace', () => {
  assert.equal(orderBlocked(context), null);
  assert.equal(orderBlocked({...context,sort:undefined}), null);
  for (const change of [{query:'server'},{query:' '},{protocol:'vless'},{favorites:true}]) {
    assert.equal(orderBlocked({...context,...change}), 'filtered');
  }
});
test('manual order blocks visual sorting, selection and pending operations', () => {
  for (const sort of ['name','latency','address']) assert.equal(orderBlocked({...context,sort}), 'sorted');
  assert.equal(orderBlocked({...context,selecting:true}), 'selection');
  assert.equal(orderBlocked({...context,busy:true}), 'busy');
});
test('keyboard neighbours use only the current group across interleaved library slots', () => {
  const profiles=[{id:'a',groupId:'one'},{id:'x',groupId:'two'},{id:'b',groupId:'one'},{id:'y',groupId:'two'},{id:'c',groupId:'one'}];
  const before=structuredClone(profiles);
  assert.equal(orderNeighbor(profiles,'b',-1),'a');
  assert.equal(orderNeighbor(profiles,'b',1),'c');
  assert.equal(orderNeighbor(profiles,'x',1),'y');
  assert.equal(orderNeighbor(profiles,'a',-1),null);
  assert.equal(orderNeighbor(profiles,'c',1),null);
  assert.equal(orderNeighbor(profiles,'missing',1),null);
  assert.deepEqual(profiles,before);
});
test('boundary commands recompute neighbours after another reorder or removal', () => {
  const profiles=[{id:'c',groupId:'g'},{id:'a',groupId:'g'}];
  assert.equal(orderNeighbor(profiles,'a',-1),'c');
  assert.equal(orderNeighbor(profiles.slice(1),'a',-1),null);
  assert.equal(orderNeighbor(profiles.slice(1),'c',1),null);
});
test('both languages explain restrictions and provider order reset', () => {
  for (const language of ['ru','en']) {
    const warning=orderText('subscription',language);
    assert.ok(warning.length>20);
    for (const block of [null,'busy','selection','filtered','sorted']) {
      assert.ok(orderHint(block,true,language).includes(warning));
      assert.ok(!orderHint(block,false,language).includes(warning));
      assert.ok(orderHint(block,false,language).length>20);
    }
    assert.notEqual(orderText('invalid_profile_order',language),'invalid_profile_order');
  }
});
