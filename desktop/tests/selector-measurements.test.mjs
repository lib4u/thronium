import test from 'node:test';
import assert from 'node:assert/strict';
import { measureAndRank } from '../src/selectors/measurements.ts';

const profile={name:'Draft',groupId:'personal',kind:'auto-selector',config:{member_source:{group_id:'source'}}};
function fixture(count=3) {
  const ids=Array.from({length:count},(_,i)=>`member-${i}`);
  const state={calls:[],progress:[],current:true,batch:undefined,active:undefined,clock:0};
  const plan={context:'c'.repeat(64),ids,candidateCount:count+2,freshCount:2,url:'https://example.test/health',timeoutMs:100};
  const flow={current:()=>state.current,batch:id=>{state.batch=id},progress:p=>state.progress.push(p),pause:async()=>{state.clock+=120},now:()=>state.clock,
    command:async(name,payload)=>{
      state.calls.push({name,payload});
      if(name==='planSelectorMeasurements')return plan;
      if(name==='startUrlTests') {state.active={id:`batch-${state.calls.length}`,url:plan.url,method:'http',entries:payload.ids.map(profileId=>({profileId,status:'ok'}))};return {id:state.active.id};}
      if(name==='snapshot')return {urlTests:state.active};
      if(name==='cancelUrlTestBatch') {if(state.active?.id===payload.id)state.active.entries.forEach(e=>e.status='cancelled');return true;}
      if(name==='rankMeasuredSelector')return {members:ids,ranked_at:1};
      throw new Error('unexpected '+name);
    }};
  return {state,plan,flow};
}

test('3000 missing candidates are measured in three owned batches and only then reranked',async()=>{
  const {state,flow,plan}=fixture(3000);const result=await measureAndRank(profile,flow);
  assert.deepEqual(result.members,plan.ids);
  const starts=state.calls.filter(c=>c.name==='startUrlTests');assert.deepEqual(starts.map(c=>c.payload.ids.length),[1000,1000,1000]);
  assert.deepEqual(starts.flatMap(c=>c.payload.ids),plan.ids);assert.equal(state.calls.at(-1).name,'rankMeasuredSelector');
  assert.deepEqual(state.progress.at(-1),{total:3000,done:3000,fresh:2,phase:'ranking'});assert.equal(state.batch,undefined);
  assert(!state.calls.some(c=>c.name==='cancelUrlTestBatch'));
});

test('fresh cache performs no HTTP batches and still verifies context before returning ranking',async()=>{
  const {state,flow}=fixture(0);await measureAndRank(profile,flow);
  assert.deepEqual(state.calls.map(c=>c.name),['planSelectorMeasurements','rankMeasuredSelector']);
  assert.equal(state.calls.at(-1).payload.context,'c'.repeat(64));
});

test('cancellation while issuance is delayed cancels the exact returned batch and never ranks',async()=>{
  const {state,flow}=fixture();const original=flow.command;
  flow.command=async(name,payload)=>{const value=await original(name,payload);if(name==='startUrlTests')state.current=false;return value;};
  await assert.rejects(measureAndRank(profile,flow),/selector_measurements_cancelled/);
  assert.equal(state.calls.at(-1).name,'cancelUrlTestBatch');assert.equal(state.calls.at(-1).payload.id,state.active.id);assert.equal(state.batch,undefined);
  assert(!state.calls.some(c=>c.name==='rankMeasuredSelector'));
});

test('a replacement manual batch is not cancelled when the old sweep discovers it',async()=>{
  const {state,flow}=fixture();const original=flow.command;let own;
  flow.command=async(name,payload)=>{
    const value=await original(name,payload);
    if(name==='startUrlTests')own=value.id;
    if(name==='snapshot'){state.active={...state.active,id:'manual-new'};return {urlTests:state.active};}
    return value;
  };
  await assert.rejects(measureAndRank(profile,flow),/selector_measurements_interrupted/);
  assert.equal(state.calls.at(-1).payload.id,own);assert(state.active.entries.every(e=>e.status==='ok'));assert.equal(state.active.id,'manual-new');
});

test('partial HTTP errors can finish, but stale or cancelled entries abort and cancel only own remaining work',async()=>{
  for(const status of ['error','stale','cancelled','unsupported']) {
    const {state,flow}=fixture();const original=flow.command;
    flow.command=async(name,payload)=>{const value=await original(name,payload);if(name==='startUrlTests')state.active.entries[0].status=status;return value;};
    if(status==='error'){await measureAndRank(profile,flow);assert.equal(state.calls.at(-1).name,'rankMeasuredSelector');}
    else {await assert.rejects(measureAndRank(profile,flow),/selector_measurements_interrupted/);assert.equal(state.calls.at(-1).name,'cancelUrlTestBatch');}
  }
});

test('a stalled queue has a finite deadline and a late final ranking cannot apply after cancellation',async()=>{
  const stalled=fixture();const original=stalled.flow.command;
  stalled.flow.command=async(name,payload)=>{const value=await original(name,payload);if(name==='startUrlTests')stalled.state.active.entries.forEach(e=>e.status='testing');return value;};
  stalled.flow.pause=async()=>{stalled.state.clock+=100000};
  await assert.rejects(measureAndRank(profile,stalled.flow),/selector_measurements_timeout/);assert.equal(stalled.state.calls.at(-1).name,'cancelUrlTestBatch');
  const late=fixture(0);const cmd=late.flow.command;late.flow.command=async(name,payload)=>{const result=await cmd(name,payload);if(name==='rankMeasuredSelector')late.state.current=false;return result;};
  await assert.rejects(measureAndRank(profile,late.flow),/selector_measurements_cancelled/);
});

test('a serial queue retains time for Core warm-up, measurement and IPC for every server',async()=>{
  const {state,flow}=fixture(10);const original=flow.command;
  flow.command=async(name,payload)=>{const value=await original(name,payload);if(name==='startUrlTests')state.active.entries.forEach(e=>e.status='testing');return value;};
  flow.pause=async()=>{state.clock+=8100;state.active.entries.find(e=>e.status==='testing').status='ok';};
  await measureAndRank(profile,flow);
  assert.equal(state.clock,81000);assert.equal(state.calls.at(-1).name,'rankMeasuredSelector');
  assert(!state.calls.some(c=>c.name==='cancelUrlTestBatch'));
});
