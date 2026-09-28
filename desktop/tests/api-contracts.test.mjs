import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { isRequest, isResponse, isModel } from '../src/shared/api/validation.ts';
import { ApiError, CodedError, boundaryError, errorCode } from '../src/shared/api/errors.ts';

test('required payload fields and actual response shapes are checked at the boundary', () => {
  assert.equal(isRequest('profile', {}), false);
  assert.equal(isRequest('profile', { id: 42 }), false);
  assert.equal(isRequest('saveProfileConfiguration', { id: 'p', config: {} }), false);
  assert.equal(isRequest('saveProfileConfiguration', { id: 'p', expectedRevision: 'r', config: {} }), true);
  assert.equal(isResponse('profile', { id: 'p' }), false);
  assert.equal(isResponse('generateWgKeys', { privateKey: 'fixture', publicKey: 'fixture' }), true);
  assert.equal(isResponse('generateWgKeys', { privateKey: 'fixture' }), false);
});

test('opaque configuration properties survive validation without being rewritten', () => {
  const draft = { name: 'Fixture', groupId: 'personal', kind: 'sing-box-outbound', config: { type: 'socks', future: { values: [null, true, 'keep'], key: 'synthetic' } } };
  const before = JSON.stringify(draft);
  assert.equal(isModel('ProfileDraft', draft), true);
  assert.equal(JSON.stringify(draft), before);
  assert.equal(isModel('ProfileDraft', { ...draft, config: [] }), false);
  assert.equal(isModel('EditableProfile', draft), false);
  assert.equal(isModel('EditableProfile', { ...draft, id: 'p', expectedRevision: 'r', favorite: false }), true);
});

test('native errors retain known codes and discard credentials and unknown dumps', () => {
  for (const value of ['https://user:synthetic-secret@example.test', { message: 'OTP=synthetic-secret' }, 'core dump synthetic-secret']) {
    const error = boundaryError(value);
    assert.equal(error.code, 'operation_failed');
    assert.equal(JSON.stringify(error).includes('synthetic-secret'), false);
  }
  assert.equal(boundaryError('profile_configuration_changed: synthetic-secret').code, 'profile_configuration_changed');
  for (const code of ['auto_select_no_reachable', 'auto_select_settings_changed', 'invalid_auto_select_settings']) {
    assert.equal(boundaryError({ code }).code, code);
  }
  assert.equal(boundaryError({ code: 'invalid_command_payload', field: '$.id' }).field, '$.id');
  assert.equal(boundaryError({ code: 'invalid_command_payload', field: 'https://synthetic-secret' }).field, undefined);
});

test('every native command in the current dispatcher has a declared wire contract', () => {
  const schema = JSON.parse(readFileSync(new URL('../contracts/ipc.generated.json', import.meta.url)));
  const files = ['lib', 'settings_tests', 'dashboard', 'geodata_assets', 'warp_registration', ...readdirSync(new URL('../src-tauri/src/commands/', import.meta.url)).filter(name => name.endsWith('.rs')).map(name => 'commands/' + name.slice(0, -3))];
  const names = new Set();
  for (const file of files) {
    const source = readFileSync(new URL(`../src-tauri/src/${file}.rs`, import.meta.url), 'utf8');
    for (const match of source.matchAll(/\bname == "(\w+)"/g)) names.add(match[1]);
    for (const match of source.matchAll(/^        ((?:"\w+"\s*\|?\s*)+) =>/gm)) {
      for (const name of match[1].matchAll(/"(\w+)"/g)) names.add(name[1]);
    }
    for (const match of source.matchAll(/matches!\(\s*name.as_str\(\),\s*((?:"\w+"\s*\|?\s*)+)\)/g)) {
      for (const name of match[1].matchAll(/"(\w+)"/g)) names.add(name[1]);
    }
  }
  assert.ok(names.size > 130);
  assert.deepEqual([...names].filter((name) => !schema.commands[name]), []);
});

test('settings conflict fields cross the boundary independently of the error message', () => {
  const error = boundaryError({code:'settings_conflict',safeParams:{fields:'test_concurrent,ping_method'}});
  assert.equal(error.code, 'settings_conflict');
  assert.equal(error.message, 'settings_conflict');
  assert.equal(error.safeParams.fields, 'test_concurrent,ping_method');
  assert.equal(boundaryError({code:'settings_conflict',safeParams:{fields:'https://synthetic-secret'}}).safeParams, undefined);
});

test('creation uses optional identity while export previews have no delivery status', () => {
  assert.equal(isRequest('saveGroup', {name:'Fixture'}), true);
  assert.equal(isRequest('otpSave', {value:{name:'Fixture',issuer:'',type:'totp',algorithm:'SHA1',secret:'JBSWY3DPEHPK3PXP',digits:6,period:30,counter:'0'}}), true);
  assert.equal(isResponse('exportProfiles', {text:'{}'}), true);
  assert.equal(isResponse('exportQr', {image:'synthetic'}), true);
  assert.equal(isResponse('exportProfiles', {}), false);
});

test('connection preferences can update mode and port without replacing TUN settings', () => {
  assert.equal(isRequest('connectionSettings', {mode:'local',port:1080}), true);
  assert.equal(isRequest('connectionSettings', {mode:'local'}), false);
});

test('legacy ping settings may omit the method and keep the native default', () => {
  assert.equal(isRequest('savePingSettings', { url: 'https://example.test', timeoutMs: 2000 }), true);
  assert.equal(isRequest('savePingSettings', { method: 'invalid', url: 'https://example.test', timeoutMs: 2000 }), false);
});

test('minimal subscription requests preserve native defaults without weakening read DTOs', () => {
  assert.equal(isRequest('saveGroup', { name: 'Fixture', subscription: { url: 'https://example.test/sub', nameRules: {} } }), true);
  assert.equal(isModel('SubscriptionSettings', { url: 'https://example.test/sub' }), false);
  assert.equal(isRequest('saveGroup', { name: 'Fixture', subscription: {} }), false);
});

 test('OTP creation preserves native Serde defaults without weakening editor responses', () => {
  assert.equal(isRequest('otpSave', {value: {secret: 'JBSWY3DPEHPK3PXP', type: 'hotp', counter: '9007199254740993'}}), true);
  assert.equal(isRequest('otpSave', {value: {secret: 'JBSWY3DPEHPK3PXP'}}), true);
  assert.equal(isModel('OtpDraft', {secret: 'JBSWY3DPEHPK3PXP'}), false);
  assert.equal(isRequest('otpSave', {value: {name: 'Missing secret'}}), false);
});

test('an error code is a code: runtime messages and text never become one', () => {
  assert.equal(errorCode(new ApiError('routing_changed')), 'routing_changed');
  assert.equal(errorCode(Error('routing_import_invalid')), 'routing_import_invalid');
  assert.equal(errorCode('qr_image_too_large'), 'qr_image_too_large');
  assert.equal(errorCode({ code: 'profile_not_found' }), 'profile_not_found');
  assert.equal(errorCode('invalidResponse'), 'invalidResponse');
  const lost = new CodedError('share_fields', { fields: 'tls.spoof_method' });
  assert.equal(errorCode(lost), 'share_fields');
  assert.equal(lost.message, 'share_fields:tls.spoof_method');
  for (const value of [new TypeError("Cannot read properties of undefined (reading 'x')"), Error(''), 'settings_invalid:$.mtu', 'Some text'])
    assert.equal(errorCode(value), 'operation_failed');
});
