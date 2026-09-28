import test from 'node:test';
import assert from 'node:assert/strict';
import { fixtures, wgFile, privateKey } from './import-fixtures.mjs';
import { nativeLink, wireguardFile, shareProfiles, base64url } from '../src/profiles/share.ts';
import { parseImport, parseLink } from '../src/profiles/import.ts';

test('TLS switch URI exports preserve false, normalize old imported booleans and refuse lost extensions', () => {
  for (const enabled of [true, false]) for (const legacy of [false, true]) {
    const profile = { name: 'TLS fixture', kind: 'sing-box-outbound', config: {
      type: 'trojan', server: '127.0.0.1', server_port: 443, password: 'fixture',
      tls: { enabled: true, tls_tricks: legacy ? enabled : { mixedcase_sni: enabled }, spoof_enabled: enabled, spoof: 'cover.example', spoof_method: 'wrong-sequence', curve_preferences: ['X25519', 'P256'] },
    }};
    const before = structuredClone(profile);
    const link = nativeLink(profile);
    const restored = parseLink(link, 'target').draft;
    assert.deepEqual(restored.config.tls, { ...profile.config.tls, tls_tricks: { mixedcase_sni: enabled } });
    assert.deepEqual(profile, before);
    const portable = parseImport(shareProfiles([profile], 'thronium-link'), 'target')[0].draft;
    assert.deepEqual(portable.config, profile.config);
    profile.config.tls.tls_tricks = { mixedcase_sni: enabled, future: { keep: [0, false] } };
    assert.throws(() => nativeLink(profile), /share_fields:tls\.tls_tricks\.future/);
    assert.deepEqual(parseImport(shareProfiles([profile], 'thronium-link'), 'target')[0].draft.config, profile.config);
  }
});

test('old empty-SNI core JSON exports as explicit Off without altering the saved sentinel', () => {
  for (const method of [undefined, '', 'wrong-ack']) {
    const profile = { name: 'Old imported Off', kind: 'sing-box-outbound', config: {
      type: 'trojan', server: '127.0.0.1', server_port: 443, password: 'fixture',
      tls: { enabled: true, spoof: '', ...(method === undefined ? {} : { spoof_method: method }) },
    }};
    const original = structuredClone(profile);
    if (method === 'wrong-ack') assert.throws(() => nativeLink(profile), /share_fields:tls\.spoof_method/);
    else {
      const restored = parseLink(nativeLink(profile), 'target').draft;
      assert.deepEqual(restored.config.tls, { ...profile.config.tls, spoof_enabled: false });
    }
    assert.deepEqual(profile, original);
    assert.deepEqual(parseImport(shareProfiles([profile], 'thronium-link'), 'target')[0].draft.config, original.config);
  }
});

test('external launch profiles require JSON even in mixed portable link exports', () => {
  const external = { name: 'External', kind: 'external-core', config: { type: 'extracore', extra_core_conf: 'fixture' } };
  for (const profiles of [[external], [fixtures()[0], external]]) {
    for (const format of ['links', 'thronium-link', 'wireguard']) {
      assert.throws(() => shareProfiles(profiles, format), /^Error: external_export_format$/);
    }
  }
});

for (const f of fixtures()) test('export/reimport ' + f.name, () => {
  const text = f.name.endsWith('multi-peer') ? wireguardFile(f) : nativeLink(f);
  const rows = parseImport(text, 'target');
  assert.equal(rows.length, 1); assert.ok(rows[0].draft); assert.deepEqual(rows[0].warnings, []);
  const expected = structuredClone(f.config); delete expected.tag;
  const actual = rows[0].draft.config; delete actual.tag;
  // A URI can supply protocol defaults absent from a JSON source.
  const subset = (a,b) => { for (const [key,value] of Object.entries(a)) {
    if (value && typeof value === 'object' && !Array.isArray(value)) subset(value,b[key]); else assert.deepEqual(b[key],value,key);
  }};
  subset(expected, actual);
});
test('portable link preserves full DNS/routing, unknown fields, names and core choice', () => {
  const profiles = [{name:'Тест 🦊',kind:'xray-config',config:{dns:{servers:['1.1.1.1']},outbounds:[{protocol:'vless',settings:{}}],routing:{domainStrategy:'IPIfNonMatch',rules:[]},future:{note:'[Interface]'}}}, {...fixtures()[1],vlessCore:'sing-box'}];
  const rows = parseImport(shareProfiles(profiles, 'thronium-link'), 'target');
  assert.deepEqual(rows.map(r=> {const {groupId,...p}=r.draft;return p;}), profiles);
});
test('portable aliases retain chains, pools and pins in mixed URI lists', () => {
  const profiles=[{...fixtures()[1],reference:'p0'}, {name:'Chain',kind:'chain',reference:'p1',config:{type:'chain',hops:['p0']}}, {name:'Pool',kind:'auto-selector',reference:'p2',config:{type:'auto-selector',members:['p1'],pinned_profile:'p1'}}];
  const rows=parseImport(shareProfiles(profiles,'thronium-link')+'\n'+nativeLink(fixtures()[1]),'target');
  assert.deepEqual(rows.map(r=>r.index),[1,2,3,4]);assert.deepEqual(rows.slice(0,3).map(r=>{const {groupId,...p}=r.draft;return p;}),profiles);
});
test('rejects malformed, overlong and recursive portable bundles', () => {
  for(const value of ['thronium://profiles/!!!!','thronium://profiles/'+base64url('{"outbounds":[]}'),shareProfiles([{...fixtures()[1],name:' '}],'thronium-link')])assert.ok(parseImport(value,'target')[0].error);
  assert.throws(()=>shareProfiles(Array(1001).fill(fixtures()[1]),'thronium-link'));
  assert.throws(()=>shareProfiles([{...fixtures()[1],config:{data:'a'.repeat(4*1024*1024)}}],'thronium-link'));
});
test('native export is all or nothing for unsupported or unknown fields', () => {
  const f=fixtures()[1];const bad={...f,config:{...f.config,future:{secret:'must-not-be-in-error'}}};
  assert.throws(()=>shareProfiles([f,bad],'links'),e=>e.message.startsWith('share_fields:')&&!e.message.includes('must-not'));
  assert.throws(()=>nativeLink({name:'full',kind:'xray-config',config:{outbounds:[]}}),/share_unsupported/);
});
test('standard Xray vnext VLESS with TLS insecure flag and complex XHTTP survives', () => {
  const f={name:'Xray',kind:'xray-outbound',config:{protocol:'vless',settings:{vnext:[{address:'example.test',port:443,users:[{id:'bf422fe4-1a5c-4b64-bc33-43c18a1b9dd1',encryption:'none'}]}]},streamSettings:{network:'xhttp',security:'tls',tlsSettings:{allowInsecure:true,serverName:'example.test'},xhttpSettings:{mode:'packet-up',path:'/api',extra:{scMaxConcurrentPosts:1,xPaddingKey:'_dc'}}}}};
  const rows=parseImport(nativeLink(f),'target');assert.equal(rows[0].draft.kind,'xray-outbound');assert.deepEqual(rows[0].draft.config.streamSettings,f.config.streamSettings);
});
test('native links preserve IPv6, Unicode and reserved password characters', () => {
  for(const type of ['socks','http','trojan','shadowsocks']) {
    const config={type,server:'2001:db8::1',server_port:443,password:'p:@/?#%+🦊',...(type==='shadowsocks'?{method:'2022-blake3-aes-128-gcm'}:type==='trojan'?{tls:{enabled:true}}:{username:'имя+user'})};
    const text=nativeLink({name:'Тест 🦊',kind:'sing-box-outbound',config});
    assert.equal(parseLink(text,'target').draft.config.password,config.password);
    assert.equal(parseLink(text,'target').draft.name,'Тест 🦊');
    if(type==='shadowsocks')assert.match(text,/^ss:\/\/2022-blake3-aes-128-gcm:/);
  }
});
test('WG file retains multiple peers and rejects directive injection or reserved bytes', () => {
  const p=parseImport(wgFile,'target')[0].draft;
  assert.deepEqual(parseImport(wireguardFile(p),'target')[0].draft.config,p.config);
  for(const value of [privateKey+'\nPostUp = echo bad',privateKey+'#comment',privateKey+';comment'])assert.throws(()=>wireguardFile({...p,config:{...p.config,private_key:value}}),/share_invalid_wireguard/);
  const reserved=structuredClone(p);reserved.config.peers[0].reserved=[1,2,3];assert.throws(()=>wireguardFile(reserved),/share_fields:peers.reserved/);
});

test('native engine JSON key ordering does not change WG/URI field equality', () => {
  function ordered(v) { return Array.isArray(v) ? v.map(ordered) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k=>[k,ordered(v[k])])) : v; }
  const p=ordered(parseImport(wgFile,'target')[0].draft);
  assert.deepEqual(parseImport(wireguardFile(p),'target')[0].draft.config,p.config);
  const uri=ordered(fixtures().find(f=>f.name==='import-wireguard'));
  assert.deepEqual(parseImport(nativeLink(uri),'target')[0].draft.config,uri.config);
});

test('accepts the legacy-normalized OS-handler alias for full Thronium links', () => {
  const link=shareProfiles([fixtures()[1]],'thronium-link');
  assert.deepEqual(parseImport(link.replace('thronium://','throne://'),'target'),parseImport(link,'target'));
  assert.equal(parseImport(link.replace('thronium://','throne://')+'\n'+nativeLink(fixtures()[1]),'target').length,2);
});

test('ECH query server name uses the sing-box field in both directions, as Qt', () => {
  const link = 'trojan://secret@127.0.0.1:443?security=tls&sni=front.example&ech_enabled=1&ech_server_name=query.example#ECH';
  const draft = parseLink(link, 'target').draft;
  assert.deepEqual(draft.config.tls.ech, { enabled: true, query_server_name: 'query.example' });
  const exported = nativeLink({ name: 'ECH', kind: 'sing-box-outbound', config: draft.config });
  assert.match(exported, /ech_server_name=query\.example/);
  assert.deepEqual(parseLink(exported, 'target').draft.config.tls.ech, draft.config.tls.ech);
});

test('WireGuard .conf export refuses sing-box interface options it cannot carry', () => {
  const base = { type: 'wireguard', private_key: privateKey, address: ['10.10.0.2/32'], peers: [{ address: '192.0.2.1', port: 51820, public_key: privateKey, allowed_ips: ['0.0.0.0/0'] }] };
  assert.match(wireguardFile({ name: 'WG', kind: 'sing-box-outbound', config: { ...base, system: false, workers: 0 } }), /\[Interface\]/);
  for (const [key, value] of [['system', true], ['workers', 4], ['udp_timeout', '5m']])
    assert.throws(() => wireguardFile({ name: 'WG', kind: 'sing-box-outbound', config: { ...base, [key]: value } }), new RegExp('share_fields:' + key));
});
test('every shared URI field survives export and import', async () => {
  const tables = await import('../src/profiles/uriFields.ts');
  const sample = { string: 'fixture-value', boolean: true, number: 7, list: ['one', 'two'] };
  const fill = (table) => {
    const result = {};
    for (const [path, , kind] of table) {
      const parts = path.split('.');
      let node = result;
      for (const part of parts.slice(0, -1)) node = node[part] ??= {};
      node[parts.at(-1)] = sample[kind];
    }
    return result;
  };
  const config = {
    type: 'vless', server: '203.0.113.10', server_port: 443, uuid: '00000000-0000-4000-8000-000000000000',
    tls: { enabled: true, server_name: 'example.test', ...fill(tables.tlsFields), ech: fill(tables.echFields) },
    transport: { type: 'ws', ...fill(tables.transportFields) },
    multiplex: fill(tables.multiplexFields),
    ...fill(tables.dialFields),
  };
  const imported = parseLink(nativeLink({ name: 'Fields', kind: 'sing-box-outbound', config }), 'work').draft.config;
  for (const [section, table, source, target] of [
    ['tls', tables.tlsFields, config.tls, imported.tls],
    ['ech', tables.echFields, config.tls.ech, imported.tls.ech],
    ['transport', tables.transportFields, config.transport, imported.transport],
    ['multiplex', tables.multiplexFields, config.multiplex, imported.multiplex],
    ['dial', tables.dialFields, config, imported],
  ])
    for (const [path] of table) {
      const read = (value) => path.split('.').reduce((node, part) => node?.[part], value);
      assert.deepEqual(read(target), read(source), `${section}.${path}`);
    }
  const quic = { type: 'hysteria2', server: '203.0.113.10', server_port: 443, password: 'fixture', tls: { enabled: true, server_name: 'example.test' }, ...fill(tables.quicFields) };
  const quicImported = parseLink(nativeLink({ name: 'QUIC', kind: 'sing-box-outbound', config: quic }), 'work').draft.config;
  for (const [path] of tables.quicFields) assert.deepEqual(quicImported[path], quic[path], `quic.${path}`);
});

test('a profile no URI can carry is shared as Throne shares it, and back', () => {
  const profile = {
    name: 'Qt shared',
    kind: 'sing-box-outbound',
    config: { type: 'tailscale', auth_key: 'fixture-key', hostname: 'thronium' },
  };
  assert.throws(() => shareProfiles([profile], 'links'));
  const link = shareProfiles([profile], 'throne-link');
  assert.match(link, /^throne:\/\/add\//);
  const restored = parseLink(link, 'personal');
  assert.equal(restored.draft.name, 'Qt shared');
  assert.equal(restored.draft.kind, 'sing-box-outbound');
  assert.deepEqual(restored.draft.config, { ...profile.config, tag: 'Qt shared' });
  const xray = { name: 'Xray shared', kind: 'xray-outbound', config: { protocol: 'vless', settings: { vnext: [{ address: '192.0.2.12', port: 443, users: [{ id: 'bf422fe4-1a5c-4b64-bc33-43c18a1b9dd1', encryption: 'none' }] }] } } };
  assert.equal(parseLink(shareProfiles([xray], 'throne-link'), 'personal').draft.kind, 'xray-outbound');
  assert.throws(() => shareProfiles([{ ...profile, vpnPolicy: { mode: 'default' } }], 'throne-link'));
  assert.throws(() => shareProfiles([{ name: 'Full', kind: 'sing-box-config', config: { outbounds: [] } }], 'throne-link'));
});
