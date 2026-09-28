import { translate } from '../src/shared/i18n/index.ts';
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {headlessFields,dnsQueryTypeNames,parseHeadlessField,formatHeadlessField} from '../src/routing/headlessFields.ts';
import {createTree,createRuleSetTree,serializeTree,reconcileRoot,reconcileRuleSet,findNode,fieldText,addLeaf,addGroup,addField,editField,removeField,removeNode,moveNode,wrapNode,unwrapNode,updateNode,validateDraft,actionOnlyKeys} from '../src/routing/conditionTree.ts';

const reflected=JSON.parse(readFileSync(new URL('../engine/tests/fixtures/inline-ruleset/headless_keys.json',import.meta.url)));
function collection(value,options={}){let id=0;return createRuleSetTree(value,{idFactory:()=>`h-${++id}`,...options});}
const error=(fn,code)=>assert.throws(fn,e=>e.message===code);
const field=key=>headlessFields.find(f=>f.key===key);

test('headless fields are exactly reflected25 includinginvert, independent of route fields',()=>{
  assert.deepEqual([...headlessFields.map(f=>f.key),'invert'].sort(),reflected.defaultHeadless);
  assert.equal(headlessFields.length,24);assert.equal(new Set(headlessFields.map(f=>f.key)).size,24);
  for(const f of headlessFields)assert(['en', 'ru'].every(language => Boolean(translate(language, f.label))));
  for(const key of reflected.routeOnlyNotHeadless)assert(!field(key),key);
  assert(field('query_type'));assert(field('network_type'));
  assert.deepEqual([...dnsQueryTypeNames].sort(),Object.keys(reflected.dnsQueryTypeNames).sort());
  assert.equal(dnsQueryTypeNames.length,88);
});

test('collection root is editor-only OR with no exportedwrapper, including emptyset',()=>{
  const input=[{domain:['a.test']},{type:'logical',mode:'and',invert:false,rules:[{network:'tcp'},{port:[80,443]}]}];
  const model=collection(input);
  assert.equal(model.schema,'headless');assert.equal(model.collection,true);assert.equal(model.root.kind,'set');
  assert.deepEqual(model.root.config,{});assert.deepEqual(serializeTree(model),input);assert.deepEqual(validateDraft(model),[]);
  const empty=collection([]);assert.deepEqual(serializeTree(empty),[]);assert.deepEqual(validateDraft(empty),[{id:empty.root.id,code:'condition_tree_empty_set'}]);
  error(()=>updateNode(model,model.root.id,n=>({...n,config:{mode:'and'}})),'condition_tree_unsupported');
  error(()=>wrapNode(model,model.root.id),'condition_tree_unsupported');
  error(()=>unwrapNode(model,model.root.id),'condition_tree_unwrap');
  error(()=>removeNode(model,model.root.id),'condition_tree_root');
});

test('all reflected forbidden route/action fields preserve raw on everyheadlesslevel',()=>{
  for(const key of new Set([...reflected.routeOnlyNotHeadless,...actionOnlyKeys])){
    const raw={network:'tcp',[key]:null};
    const single=createTree(raw,{schema:'headless'});assert.equal(single.root.kind,'raw',key);assert.deepEqual(serializeTree(single),raw);
    const model=collection([raw,{type:'logical',mode:'and',rules:[raw]}]);
    assert.equal(model.root.children[0].kind,'raw',key);assert.equal(model.root.children[1].children[0].kind,'raw',key);
    assert.deepEqual(serializeTree(model),[raw,{type:'logical',mode:'and',rules:[raw]}],key);
    assert(validateDraft(model).length>0,key);
  }
});

test('unknown properties are opaque instead of being silently treated as headless conditions',()=>{
  for(const input of [[{domain:['a.test'],future:1}],[{type:'logical',mode:'and',future:null,rules:[{network:'tcp'}]}]]){
    const model=collection(input);assert.equal(model.root.children[0].kind,'raw');assert.deepEqual(serializeTree(model),input);
    error(()=>wrapNode(model,model.root.children[0].id),'condition_tree_unsupported');
  }
  const input=[{future:{preserve:[1,null]}},{domain:['a.test']}];let model=collection(input);
  model=moveNode(model,model.root.children[0].id,1);assert.deepEqual(serializeTree(model),[input[1],input[0]]);
  model=editField(model,model.root.children[0].id,'domain','changed.test');
  assert.deepEqual(serializeTree(model)[1],input[0]);assert.deepEqual(input,[{future:{preserve:[1,null]}},{domain:['a.test']}]);
});

test('query_type import keeps scalar/list/named/numeric representations exactly',()=>{
  for(const value of ['A',1,['A',28],0,65535,['None','Reserved',0,65535],['TXT','TXT']]){
    const source=[{query_type:value,network:'tcp'}],model=collection(source);
    assert.equal(model.root.children[0].kind,'leaf');assert.deepEqual(serializeTree(model),source);assert.deepEqual(validateDraft(model),[]);
    assert.equal(formatHeadlessField(field('query_type'),value),Array.isArray(value)?value.join(', '):String(value));
  }
  for(const value of ['a','1','*','NONE',-1,65536,1.5,true,null,[],[null],['AAAA',null]]){
    const source=[{query_type:value,network:'tcp'}],model=collection(source);
    assert.equal(model.root.children[0].kind,'raw',JSON.stringify(value));assert.deepEqual(serializeTree(model),source);
  }
});

test('query_type edits use actual case-sensitive88names and uint16 values',()=>{
  for(const name of dnsQueryTypeNames)assert.deepEqual(parseHeadlessField(field('query_type'),name),[name]);
  assert.deepEqual(parseHeadlessField(field('query_type'),'A, 28\nTXT 65535,0,None,Reserved'),['A',28,'TXT',65535,0,'None','Reserved']);
  for(const value of ['a','*','1.5','-1','65536','9007199254740993','UNKNOWN','NONE','A, bad'])error(()=>parseHeadlessField(field('query_type'),value),'invalid_condition');
  assert.equal(parseHeadlessField(field('query_type'),' \n '),undefined);
  assert.deepEqual(parseHeadlessField(field('port'),'1,65535'),[1,65535]);
  for(const value of ['0','65536','-1','0.5'])error(()=>parseHeadlessField(field('source_port'),value),'invalid_condition');
});

test('complete leaf families/inversion remain one child when wrapping and unwrapping',()=>{
  const input=[{domain:['a.test'],domain_suffix:['b.test'],ip_cidr:['192.0.2.0/24'],port:[80],port_range:['90:100'],query_type:['A',28],invert:true}];
  const model=collection(input),id=model.root.children[0].id,grouped=wrapNode(model,id,'or');
  assert.equal(grouped.root.children[0].children.length,1);assert.equal(grouped.root.children[0].children[0].id,id);
  assert.deepEqual(serializeTree(grouped),[{type:'logical',mode:'or',rules:input}]);
  assert.deepEqual(serializeTree(unwrapNode(grouped,grouped.root.children[0].id)),input);
  for(const key of actionOnlyKeys)assert(!Object.hasOwn(serializeTree(grouped)[0],key));
});

test('collection reorder, wrap and metadata-only reconciliation preserve invalid buffers and IDs',()=>{
  let model=collection([{query_type:['A'],domain:['a.test']},{network:'tcp'}]);const id=model.root.children[0].id;
  model=editField(model,id,'query_type','A, 99999');
  const previous=serializeTree(model);model=moveNode(model,id,1);
  assert.equal(fieldText(findNode(model,id),'query_type','headless'),'A, 99999');
  assert.equal(findNode(model,id).errors.query_type,true);
  const same=reconcileRuleSet(model,structuredClone(serializeTree(model)));assert.equal(same,model);
  const wrapped=wrapNode(model,id);assert.equal(findNode(wrapped,id).errors.query_type,true);
  error(()=>reconcileRuleSet(model,[{network:'udp'}]),'condition_tree_draft_conflict');
  assert.deepEqual(serializeTree(model),[previous[1],previous[0]]);
  const fixed=editField(model,id,'query_type','AAAA');const replaced=reconcileRuleSet(fixed,[{network:'udp'}]);
  assert.deepEqual(serializeTree(replaced),[{network:'udp'}]);assert.notEqual(replaced.root.id,model.root.id);
  error(()=>reconcileRoot(model,{type:'logical',mode:'or',rules:[]}), 'condition_tree_root');
});

test('new set entries/groups remain incomplete until explicitlyfilled or removed',()=>{
  let model=collection([]);model=addLeaf(model,model.root.id);const id=model.root.children[0].id;
  assert.deepEqual(validateDraft(model),[{id,key:'domain_suffix',code:'invalid_condition'}]);
  model=removeField(model,id,'domain_suffix');assert.deepEqual(validateDraft(model),[{id,code:'invalid_condition'}]);
  model=addField(model,id,'query_type');model=editField(model,id,'query_type','A,28');assert.deepEqual(validateDraft(model),[]);
  model=addGroup(model,model.root.id,'or');const group=model.root.children[1];assert.equal(group.kind,'group');assert.equal(group.children.length,1);
  model=removeNode(model,group.children[0].id);assert.deepEqual(validateDraft(model),[{id:group.id,code:'condition_tree_empty_group'}]);
  model=removeNode(model,group.id);model=removeNode(model,id);assert.deepEqual(serializeTree(model),[]);assert.deepEqual(validateDraft(model),[{id:model.root.id,code:'condition_tree_empty_set'}]);
});

test('field edits cannot drop unrelated fields or turn malformedJSON into validdefault',()=>{
  const input=[{domain_regex:['[a-z]{1,3}\\.test$'],wifi_ssid:['Office, West'],network_interface_address:{wifi:['192.0.2.0/24']},network_is_expensive:false}];
  let model=collection(input);const id=model.root.children[0].id;
  model=editField(model,id,'network_interface_address','null');assert(findNode(model,id).errors.network_interface_address);
  assert.deepEqual(serializeTree(model),input);assert.equal(fieldText(findNode(model,id),'network_interface_address','headless'),'null');
  model=editField(model,id,'network_interface_address','{"wifi":["198.51.100.0/24"]}');
  model=removeField(model,id,'network_is_expensive');assert(!Object.hasOwn(serializeTree(model)[0],'network_is_expensive'));
  assert.deepEqual(serializeTree(model)[0].domain_regex,input[0].domain_regex);assert.deepEqual(serializeTree(model)[0].wifi_ssid,input[0].wifi_ssid);
  assert.deepEqual(serializeTree(model)[0].network_interface_address,{wifi:['198.51.100.0/24']});
  error(()=>addField(model,id,'protocol'),'condition_tree_field');
  error(()=>updateNode(model,id,n=>({...n,config:{...n.config,action:'reject'}})),'condition_tree_nested_action');
  error(()=>updateNode(model,id,n=>({...n,config:{...n.config,inbound:'mixed-in'}})),'condition_tree_unsupported');
});

test('malformedcollections and ambiguousempty/nullnodes roundtrip asopaque',()=>{
  for(const source of [null,{},'text',7,[null],[[]],[{}],[{invert:true}],[{type:'logical',mode:'xor',rules:[{network:'tcp'}]}],[{type:'logical',mode:'and',rules:null}],[{type:'logical',mode:'and',network:'tcp',rules:[{network:'tcp'}]}],[{port:null}],[{query_type:[null]}]]){
    const model=collection(source);assert.deepEqual(serializeTree(model),source);assert(validateDraft(model).length>0,JSON.stringify(source));
  }
  const empty=collection([{type:'logical',mode:'and',rules:[]}]);assert.equal(validateDraft(empty)[0].code,'condition_tree_empty_group');
});

test('setcontainerdoesnotconsumeconditionbudgetandimportlimitsnevertruncatesource',()=>{
  let model=collection([],{maxDepth:1,maxNodes:2});model=addLeaf(model,model.root.id);model=addLeaf(model,model.root.id);
  assert.equal(model.root.children.length,2);error(()=>addLeaf(model,model.root.id),'condition_tree_limit');
  error(()=>wrapNode(model,model.root.children[0].id),'condition_tree_limit');
  const source=Array.from({length:129},(_,i)=>({port:[i]}));const over=collection(source);assert.equal(over.root.kind,'raw');assert.deepEqual(serializeTree(over),source);
  const edge=collection(source.slice(0,128));assert.equal(edge.root.kind,'set');assert.equal(edge.root.children.length,128);
  let deep={query_type:['A']};for(let i=0;i<12000;i++)deep={type:'logical',mode:'and',rules:[deep]};
  const saved=serializeTree(collection([deep]));let cursor=saved[0];for(let i=0;i<12000;i++)cursor=cursor.rules[0];assert.deepEqual(cursor,{query_type:['A']});
});

test('single-ruleheadlessAPIhasnoactionexceptionanddefault route remainsindependent',()=>{
  const single=createTree({query_type:'A'},{schema:'headless'});assert.equal(single.root.kind,'leaf');assert.equal(single.collection,false);
  const changed=editField(single,single.root.id,'query_type','AAAA');assert.deepEqual(serializeTree(changed),{query_type:['AAAA']});
  const grouped=wrapNode(single,single.root.id);assert.deepEqual(serializeTree(grouped),{type:'logical',mode:'and',rules:[{query_type:'A'}]});
  const route=createTree({protocol:['http'],action:'route',outbound:'proxy'});assert.equal(route.schema,'route');assert.equal(route.root.kind,'leaf');
  error(()=>addField(route,route.root.id,'query_type'),'condition_tree_field');
  assert.deepEqual(serializeTree(route),{protocol:['http'],action:'route',outbound:'proxy'});
});

test('headless single-rule reconciliation cannot introduce root actions or hide pending text',()=>{
  let model=createTree({type:'logical',mode:'and',rules:[{query_type:'A'}]},{schema:'headless'});
  const source=serializeTree(model), invalid={...source,action:'reject'};
  const opaque=reconcileRoot(model,invalid);assert.equal(opaque.root.kind,'raw');assert.deepEqual(serializeTree(opaque),invalid);
  assert.equal(validateDraft(opaque)[0].code,'condition_tree_nested_action');
  model=editField(model,model.root.children[0].id,'query_type','A,wrong');
  error(()=>reconcileRoot(model,invalid),'condition_tree_draft_conflict');
  const changed=reconcileRoot(model,{...source,mode:'or',invert:true});
  assert.equal(changed.root.children[0].id,model.root.children[0].id);
  assert.equal(fieldText(changed.root.children[0],'query_type','headless'),'A,wrong');
});
