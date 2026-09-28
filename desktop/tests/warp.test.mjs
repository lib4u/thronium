import test from 'node:test';
import assert from 'node:assert/strict';
import {settingsValues,profileValues,profileDraft} from '../src/warp/config.ts';
const config={privateKey:'local-private',clientPublicKey:'local-public',peerPublicKey:'remote-public',endpoint:'[2001:db8::1]:2408',host:'2001:db8::1',port:2408,addresses:['172.16.0.2/32','2606:4700::2/128'],reserved:[0,128,255],mtu:1280,persistentKeepalive:10};
test('WARP result maps only its five settings without enabling or applying traffic changes',()=>{
 const values=settingsValues(config);assert.deepEqual(Object.keys(values).sort(),['warp_ep','warp_ifc_addrs','warp_private_key','warp_public_key','warp_reserved']);assert.deepEqual(values.warp_reserved,['0','128','255']);assert.equal(values.warp_public_key,'remote-public');assert.equal(values.warp_ep,'[2001:db8::1]:2408');values.warp_ifc_addrs.push('local-change');assert.equal(config.addresses.length,2);
});
test('WARP fills one WireGuard peer and preserves unrelated profile options',()=>{
 const previous={type:'wireguard',tag:'owned-profile',detour:'upstream',system:false,future:{enabled:true},peers:[{address:'old',pre_shared_key:'old-secret'}]};const after=profileValues(previous,config);
 assert.equal(after.detour,'upstream');assert.deepEqual(after.future,{enabled:true});assert.equal(after.system,false);assert.equal(after.private_key,'local-private');assert.equal(after.mtu,1280);assert.equal(after.peers.length,1);assert.equal(after.peers[0].public_key,'remote-public');assert.equal(after.peers[0].address,'2001:db8::1');assert.equal(after.peers[0].port,2408);assert.equal(after.peers[0].persistent_keepalive_interval,10);assert.ok(!('pre_shared_key' in after.peers[0]));assert.equal(previous.peers[0].pre_shared_key,'old-secret');
});
test('using a WARP draft replaces its fields and keeps unrelated invalid input and protocol variants',()=>{
 const current={text:JSON.stringify({type:'wireguard',listen_port:1234,unknown:{keep:1}}),buffers:{private_key:'old','peers.1.port':'invalid',listen_port:'keep invalid'},invalid:{'peers.1.port':true,listen_port:true},variants:{tls:{raw:'keep'}}};const next=profileDraft(current,config);
 assert.deepEqual(next.buffers,{listen_port:'keep invalid'});assert.deepEqual(next.invalid,{listen_port:true});assert.deepEqual(next.variants,current.variants);assert.deepEqual(JSON.parse(next.text).unknown,{keep:1});assert.equal(current.buffers.private_key,'old');
});
