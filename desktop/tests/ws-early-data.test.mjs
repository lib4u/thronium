import test from 'node:test';
import assert from 'node:assert/strict';
import { editWsEarlyData as edit, inspectWsEarlyData as inspect, wsEarlyDataText as text } from '../src/profiles/wsEarlyData.ts';

test('the Xray helper represents absence as disabled and preserves untouched paths', () => {
  for (const path of [undefined, '', '/', '/socket?token=abc%2f+xyz#part', '/?ed=0001']) {
    const value=inspect(path);assert.equal(value.issue,null);
    assert.equal(edit(path,String(value.value)),path);
  }
  assert.deepEqual(inspect('/?ed=0'),{value:0,issue:null});
  assert.equal(edit('/?ed=0','0'),'/');
});
test('positive early data requires an explicit path and validates the Qt numeric range', () => {
  for(const value of ['1','8192']) assert.equal(edit('/',value),'/?ed='+value);
  for(const path of [undefined,'','?token=1','#part']) assert.throws(()=>edit(path,'1'),/pathRequired/);
  for(const value of ['-1','8193','1.5','1e2','0x10','NaN','Infinity','9007199254740993']) assert.throws(()=>edit('/',value),/invalidValue/);
  assert.equal(edit('/?ed=1',''),'/');assert.equal(edit('/?ed=1','  '),'/');
});
test('editing only ed preserves unrelated raw query bytes, order and fragment', () => {
  const path='/socket?z=%2f+X&a=1&a=2&ed=1&bare&blank=#frag?ed=77';
  assert.equal(edit(path,'8192'),'/socket?z=%2f+X&a=1&a=2&ed=8192&bare&blank=#frag?ed=77');
  assert.equal(edit(path,'0'),'/socket?z=%2f+X&a=1&a=2&bare&blank=#frag?ed=77');
  assert.equal(edit('/socket?z=%2f+X#part','2'),'/socket?z=%2f+X&ed=2#part');
  assert.equal(edit('/socket?#part','2'),'/socket?ed=2#part');
  assert.equal(edit('/socket?z=1&#part','2'),'/socket?z=1&ed=2#part');
});
test('encoded ed names and digits are recognized without normalizing other tokens', () => {
  const path='/socket?token=%ff&e%64=%31#frag';
  assert.deepEqual(inspect(path),{value:1,issue:null});
  assert.equal(edit(path,'2'),'/socket?token=%ff&ed=2#frag');
  assert.equal(edit(path,'0'),'/socket?token=%ff#frag');
  assert.equal(inspect('/socket?ED=1').value,0);
  assert.equal(edit('/socket?ED=1','2'),'/socket?ED=1&ed=2');
});
test('ambiguous or malformed stored ed is preserved for explicit Path editing', () => {
  for (const path of ['/?ed=1&ed=2','/?ed=1&e%64=2','/?ed','/?ed=','/?ed=-1','/?ed=8193','/?ed=1;token=2','/?token=%xx&ed=1','/%xx?ed=1','/?ed=%','/?ed=+1']) {
    assert.notEqual(inspect(path).issue,null,path);
    assert.throws(()=>edit(path,'0'),undefined,path);
    assert.throws(()=>edit(path,'1'),undefined,path);
  }
  for(const path of [null,42,{},[], '/a\nb']) assert.equal(inspect(path).issue,'invalidPath');
});
test('removing ed retains unrelated empty query segments and fragments', () => {
  assert.equal(edit('/?ed=1&x=2','0'),'/?x=2');
  assert.equal(edit('/?x=2&ed=1','0'),'/?x=2');
  assert.equal(edit('/?ed=1&','0'),'/?');
  assert.equal(edit('/?&ed=1&x=2','0'),'/?&x=2');
  assert.equal(edit('/#?ed=2','0'),'/#?ed=2');
});
test('URI authority and scheme shapes stay in the raw Path field', () => {
  for (const path of [':broken?ed=1','//[broken?ed=1','//host/socket?ed=1','https://host/socket?ed=1','ws:opaque?ed=1']) {
    assert.equal(inspect(path).issue,'invalidPath');
    assert.throws(()=>edit(path,'8192'),/invalidPath/);
  }
  assert.equal(edit('socket?ed=1','2'),'socket?ed=2');
  assert.equal(edit('/socket/a:b?ed=1','2'),'/socket/a:b?ed=2');
});
test('the field has finite localized explanations for every refused edit', () => {
  for(const language of ['ru','en']) for(const key of ['label','hint','invalidPath','ambiguousQuery','invalidValue','pathRequired']) {
    assert.ok(text(key,language).length>15);assert.notEqual(text(key,'ru'),text(key,'en'));
  }
});
