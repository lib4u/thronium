import test from 'node:test';
import assert from 'node:assert/strict';
import { credentialsError, credentialsKey, isCurrentCredentials, validCredentials } from '../src/connection/vpnCredentials.ts';

test('only the same terminal authentication failure can accept new credentials', () => {
  const request = { sessionId: 'session-a', endpointTag: 'proxy' };
  const endpoint = { tag: 'proxy', state: 'error', authFailed: true, challengeId: null };
  const status = { sessionId: 'session-a', endpoints: [endpoint], error: null };
  assert.equal(isCurrentCredentials(status, request), true);
  for (const change of [{ sessionId: 'session-b' }, { endpoints: [] },
    ...[{ state: 'connected' }, { state: 'connecting' }, { authFailed: false }, { tag: 'auxiliary' }, { challengeId: 'live-form' }]
      .map(fields => ({ endpoints: [{ ...endpoint, ...fields }] }))]) {
    assert.equal(isCurrentCredentials({ ...status, ...change }, request), false);
  }
  assert.notEqual(credentialsKey({ sessionId: 'a:b', endpointTag: 'c' }), credentialsKey({ sessionId: 'a', endpointTag: 'b:c' }));
});

test('credentials use byte limits without changing password whitespace', () => {
  assert.equal(validCredentials('', ''), false);
  assert.equal(validCredentials('user', ''), true);
  assert.equal(validCredentials('', ' '), true);
  assert.equal(validCredentials('я'.repeat(2048), ''), true);
  assert.equal(validCredentials('я'.repeat(2049), ''), false);
  assert.equal(validCredentials('', '🔐'.repeat(1024)), true);
  assert.equal(validCredentials('', '🔐'.repeat(1025)), false);
  for (const field of ['a\0b', 'prefix-{otp}-suffix']) {
    assert.equal(validCredentials(field, 'password'), false);
    assert.equal(validCredentials('username', field), false);
  }
});

test('credential errors never reflect private transport or entered text', () => {
  const privateText = 'password=private-value https://private.test/token';
  for (const language of ['en', 'ru']) {
    assert.equal(credentialsError(privateText, language).includes(privateText), false);
    assert.equal(credentialsError(new Error(privateText), language).includes('private'), false);
    assert.notEqual(credentialsError('vpn_credentials_check_failed', language), credentialsError('connection_restored', language));
    for (const key of ['__proto__', 'constructor', 'toString']) assert.equal(credentialsError(key, language), credentialsError(privateText, language));
  }
});
