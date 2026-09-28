import test from 'node:test';
import assert from 'node:assert/strict';
import { active, latency, tooltip, message, isProbeError } from '../src/probes/messages.ts';
import { sortProfiles } from '../src/library/sort.ts';
const result = (status) => ({status, method:'auto', effectiveMethod:'http', latencyMs:null, error:null, at:null, firstHop:false, attempts:[{method:'http',status,error:null}]});

test('VPN-only and login-required results are terminal and never display invented latency', () => {
  for (const language of ['ru','en']) for (const status of ['connected-only','auth-required']) {
    const m=result(status);assert.equal(active(status),false);
    assert.doesNotMatch(latency(m,language),/ms|мс|<1|×/);
    assert.ok(latency(m,language).length>0);
    assert.match(tooltip(m,language),/HTTP/);
  }
  assert.equal(latency({...result('ok'),latencyMs:0},'en'),'<1 ms · HTTP(S)');
  assert.equal(latency({...result('ok'),latencyMs:37},'ru'),'37 мс · HTTP(S)');
});
test('VPN results distinguish authentication from missing HTTP and preserve the attempted method', () => {
  assert.match(tooltip(result('connected-only'),'en'),/VPN connected, no HTTP response/);
  assert.match(tooltip(result('auth-required'),'ru'),/Требуется вход в VPN/);
  for (const language of ['ru','en']) {
    const m={...result('auth-required'),error:'probe_vpn_auth_required'};
    assert.equal(tooltip(m,language).includes('TCP'),false);
    assert.match(tooltip(m,language),/HTTP\(S\)/);
    assert.notEqual(message(m.error,language),message('unknown',language));
  }
});
test('untrusted probe error content is replaced by a finite message', () => {
  const secret='private-fixture-password';
  for(const language of ['ru','en']) {
    assert.equal(message(secret,language),message('probe_failed',language));
    assert.equal(tooltip({...result('auth-required'),error:secret},language).includes(secret),false);
  }
});
test('one-time code refusals of disposable tests have finite RU/EN messages', () => {
  for (const code of ['probe_vpn_otp_binding_required','probe_vpn_otp_manual_only','probe_vpn_otp_failed']) for (const language of ['ru','en']) {
    assert.notEqual(message(code,language),message('unknown',language),code);
    assert.ok(message(code,language).length>10,code);
    assert.equal(tooltip({...result('error'),error:code},language).includes(code),false);
  }
});
test('VPN states stay after measured HTTP results for either latency sort direction', () => {
  const profiles=[{id:'auth',measurement:result('auth-required')},{id:'vpn',measurement:result('connected-only')},{id:'slow',measurement:{...result('ok'),latencyMs:42}},{id:'fast',measurement:{...result('ok'),latencyMs:0}}];
  for(const language of ['ru','en']) for(const descending of [false,true]) {
    const actual=sortProfiles(profiles,{language,librarySort:'latency',librarySortDescending:descending}).map(p=>p.id);
    assert.deepEqual(actual,descending?['slow','fast','auth','vpn']:['fast','slow','auth','vpn']);
  }
});

test('VPN eligibility and cleanup codes have finite localized explanations', () => {
  for(const language of ['ru','en']) for(const code of ['probe_vpn_auth_unsupported','probe_vpn_context_unsupported','probe_vpn_connected_only','probe_cleanup_failed']) {
    assert.notEqual(message(code,language),message('probe_failed',language));
    assert.equal(message(code,language).includes(code),false);
  }
});

test('connection and quit guards can reuse finite probe explanations without intercepting unrelated errors', () => {
  for(const code of ['probe_busy','probe_cleanup_failed','probe_vpn_context_unsupported']) {
    assert.equal(isProbeError(code),true);
    for(const language of ['ru','en']) assert.notEqual(message(code,language),code);
  }
  for(const code of ['title','constructor','__proto__','core_missing','probe_unknown_private_value']) assert.equal(isProbeError(code),false);
});
