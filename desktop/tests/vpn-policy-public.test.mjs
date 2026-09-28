import test from 'node:test';
import assert from 'node:assert/strict';
import { parseImport } from '../src/profiles/import.ts';
import * as sharing from '../src/profiles/share.ts';
const { shareProfiles, nativeLink, base64url, profileBundle } = sharing;

const staged = process.env.THRONIUM_POLICY_STAGE !== 'baseline';
const policy = (g,d,b) => ({ onlyAdvertisedRoutes:g, useTunnelDns:d, blockOutsideDns:b });
const profile = (type='openvpn-client') => ({name:'Synthetic VPN policy 🦊',kind:'sing-box-outbound',config:{type,server:'vpn.fixture.invalid',...(type==='openvpn-client'?{server_port:1194}:{}),username:'public-policy-user',password:'public-policy-password'}});
const bundle = (profiles,version=2) => JSON.stringify({format:'thronium-profiles',version,profiles});
const withoutGroup = ({groupId,...draft}) => draft;

test('baseline33 portable full DNS/routes remains exact and policy is absent',()=>{
  const p={name:'Full existing config',kind:'sing-box-config',config:{dns:{servers:[{type:'local',tag:'original-dns'}],rules:[{domain:['dns.fixture.invalid'],server:'original-dns'}],final:'original-dns'},route:{rules:[{domain:['route.fixture.invalid'],action:'route',outbound:'direct'}],final:'direct'},outbounds:[{type:'direct',tag:'direct'}],future:{keep:[false,17]}}};
  const link=shareProfiles([p],'thronium-link');const encoded=link.split('/').at(-1);
  assert.equal(JSON.parse(Buffer.from(encoded,'base64url').toString()).version,1);
  const rows=parseImport(link,'target');assert.equal(rows.length,1);assert.deepEqual(withoutGroup(rows[0].draft),p);assert.deepEqual(rows[0].warnings,[]);
});

test('policy34 all16 combinations survive real bundle and portable link functions',{skip:!staged},()=>{
  for(const protocol of ['openvpn-client','openconnect']) for(const g of [false,true]) for(const d of [false,true]) for(const b of [false,true]){
    const p={...profile(protocol),vpnPolicy:policy(g,d,b)};const before=structuredClone(p);
    for(const input of [bundle([p]),shareProfiles([p],'thronium-link')]){
      const rows=parseImport(input,'target');assert.equal(rows.length,1);assert.ok(rows[0].draft);assert.equal(rows[0].error,undefined);assert.deepEqual(withoutGroup(rows[0].draft),p);assert.deepEqual(rows[0].warnings,[]);
    }
    const link=shareProfiles([p],'thronium-link');assert.equal(JSON.parse(Buffer.from(link.split('/').at(-1),'base64url').toString()).version,2);
    assert.deepEqual(p,before);
  }
});

test('policy34 old headers and raw protocol exports refuse lost metadata',{skip:!staged},()=>{
  const p={...profile(),vpnPolicy:policy(true,true,false)};
  for(const raw of [bundle([p],1),'thronium://profiles/'+base64url(bundle([p],1))]){
    const rows=parseImport(raw,'target');assert.ok(rows.some(r=>r.error));assert.ok(rows.every(r=>!r.draft));assert.ok(!JSON.stringify(rows).includes('public-policy-password'));
  }
  for(const exportFn of [()=>nativeLink(p),()=>shareProfiles([p],'links'),()=>shareProfiles([p],'wireguard')])assert.throws(exportFn,/vpn_policy_export_requires_bundle/);
  const ordinary=profile();assert.equal(JSON.parse(Buffer.from(shareProfiles([ordinary],'thronium-link').split('/').at(-1),'base64url').toString()).version,1);
});

test('policy34 malformed typed metadata is rejected without leaking source bodies',{skip:!staged},()=>{
  for(const vpnPolicy of [{},[],false,{onlyAdvertisedRoutes:true,useTunnelDns:true},{onlyAdvertisedRoutes:'true',useTunnelDns:true,blockOutsideDns:false},{...policy(true,true,false),future:true}]){
    const rows=parseImport(bundle([{...profile(),vpnPolicy}]),'target');assert.ok(rows.some(r=>r.error));assert.ok(rows.every(r=>!r.draft));assert.ok(!JSON.stringify(rows).includes('public-policy-password'));
  }
});

test('policy34 draft null shares as absent while file null is rejected',{skip:!staged},()=>{
  for (const p of [profile(), {...profile(),vpnPolicy:null}]) {
    const output=profileBundle([p]);
    assert.equal(output.version,1);assert.ok(!Object.hasOwn(output.profiles[0],'vpnPolicy'));
    const rows=parseImport(shareProfiles([p],'thronium-link'),'target');
    assert.deepEqual(withoutGroup(rows[0].draft),profile());
  }
  for (const version of [1,2]) {
    const raw=bundle([{...profile(),vpnPolicy:null}],version);
    for(const input of [raw,'thronium://profiles/'+base64url(raw)]) {
      const rows=parseImport(input,'target');assert.ok(rows.every(r=>r.error&&!r.draft));
      assert.ok(!JSON.stringify(rows).includes('public-policy-password'));
    }
  }
});

test('policy34 rejects duplicate metadata but leaves opaque Core JSON parsing unchanged',{skip:!staged},()=>{
  const raw=bundle([{...profile(),vpnPolicy:policy(true,true,false)}]);
  const duplicates=[
    raw.replace('"version":2','"version":1,"version":2'),
    raw.replace('"format":"thronium-profiles"','"format":"other","format":"thronium-profiles"'),
    raw.replace('"profiles":[','"profiles":[],"profiles":['),
    raw.replace('"vpnPolicy":{','"vpnPolicy":null,"vpnPolicy":{'),
    raw.replace('"onlyAdvertisedRoutes":true','"onlyAdvertisedRoutes":false,"onlyAdvertisedRoutes":true'),
    raw.replace('"useTunnelDns":true','"useTunnelDns":false,"useTunnelD\\u006es":true'),
  ];
  for (const text of duplicates) for(const input of [text,'thronium://profiles/'+base64url(text)]) {
    const rows=parseImport(input,'target');assert.ok(rows.every(r=>r.error&&!r.draft));
    assert.ok(!JSON.stringify(rows).includes('public-policy-password'));
  }
  // This is parity with the existing JSON.parse boundary, not a >2^53 precision claim.
  const opaque=raw.replace('"config":{','"config":{"future":{"version":1,"version":2,"vpnPolicy":{"anything":["escaped \\\" } [",9007199254740993]}},');
  const rows=parseImport(opaque,'target');assert.equal(rows[0].error,undefined);
  assert.deepEqual(rows[0].draft.config,JSON.parse(opaque).profiles[0].config);
  assert.deepEqual(rows[0].draft.vpnPolicy,policy(true,true,false));
});

test('policy34 unsuitable profile metadata is explicit in mixed files and fails sharing',{skip:!staged},()=>{
  const valid={...profile(),vpnPolicy:policy(true,true,false)};
  for (const invalid of [
    {...valid,config:{type:'direct'}},
    {...valid,kind:'sing-box-config',config:{endpoints:[profile().config],dns:{servers:[]},route:{rules:[]}}},
    {...valid,kind:'xray-outbound',config:{protocol:'vless',settings:{}}},
    {...valid,kind:'chain',config:{type:'chain',profiles:[]}},
  ]) {
    const rows=parseImport(bundle([valid,invalid]),'target');
    assert.equal(rows.length,2);assert.deepEqual(withoutGroup(rows[0].draft),valid);
    assert.equal(rows[1].error,'vpn_policy_profile_unsupported');assert.equal(rows[1].draft,undefined);
    assert.throws(()=>profileBundle([valid,invalid]),/vpn_policy_profile_unsupported/);
    assert.throws(()=>shareProfiles([valid,invalid],'thronium-link'),/vpn_policy_profile_unsupported/);
  }
});
