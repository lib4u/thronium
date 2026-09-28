import test from 'node:test';
import assert from 'node:assert/strict';
import { answerRequest, canAnswer, challengeExpired, challengeKey, initialAnswers, isCurrentChallenge } from '../src/connection/vpnAuth.ts';
import { vpnError } from '../src/connection/vpnMessages.ts';
import { vpnOtpError } from '../src/connection/vpnOtpMessages.ts';

const request = { sessionId: 'session-a', endpointTag: 'vpn', challengeId: '9007199254740993' };
const challenge = { ...request, kind: 'credentials', username: 'alice', message: '', banner: '', error: '', echo: false, deadline: 0, fields: [] };

test('authentication identity includes session, endpoint and lossless challenge ID', () => {
  const status = { sessionId: request.sessionId, endpoints: [{ tag: 'vpn', challengeId: request.challengeId }] };
  assert.equal(isCurrentChallenge(status, request), true);
  for (const field of ['sessionId', 'endpointTag', 'challengeId']) assert.equal(isCurrentChallenge(status, { ...request, [field]: 'different' }), false);
  assert.notEqual(challengeKey(request), challengeKey({ ...request, challengeId: '9007199254740992' }));
  assert.notEqual(challengeKey({ sessionId: 'a/b', endpointTag: 'c', challengeId: 'd' }), challengeKey({ sessionId: 'a', endpointTag: 'b/c', challengeId: 'd' }));
  assert.equal(isCurrentChallenge({ sessionId: null, endpoints: [] }, request), false);
});

test('credentials include an answer with an empty prompt; secret and message send only their own fields', () => {
  const answers = { ...initialAnswers(challenge), password: 'private-password', secret: '123456', fields: { stale: 'old-response' } };
  assert.deepEqual(answerRequest(challenge, answers), { ...request, username: 'alice', password: 'private-password', secret: '123456', formValues: {} });
  assert.deepEqual(answerRequest({ ...challenge, kind: 'secret' }, answers), { ...request, username: '', password: '', secret: '123456', formValues: {} });
  assert.deepEqual(answerRequest({ ...challenge, kind: 'message' }, answers), { ...request, username: '', password: '', secret: '', formValues: {} });
  assert.deepEqual(initialAnswers(challenge), { username: 'alice', password: '', secret: '', fields: {} });
  assert.equal(challengeExpired({ ...challenge, deadline: 100 }, 99999), false);
  assert.equal(challengeExpired({ ...challenge, deadline: 100 }, 100000), true);
  assert.equal(challengeExpired(challenge, 100000), false);
  assert.throws(() => answerRequest({ ...challenge, deadline: 100 }, answers, 100000), /vpn_auth_expired/);
});

test('server forms use exact submission keys and option values, preserving private defaults only in answers', () => {
  const fields = [
    { submissionKey: 'realm', name: 'realm', label: 'Realm', kind: 'select', value: 'value-a', options: [{ value: 'value-a', label: 'Visible label' }, { value: 'value-b', label: 'Visible label' }] },
    { submissionKey: 'pass', name: 'pass', label: 'Password', kind: 'password', value: 'private-default', options: [] },
    { submissionKey: '__proto__', name: 'custom', label: '<img src=x onerror=alert(1)>', kind: 'text', value: 'exact-value', options: [] },
  ];
  const form = { ...challenge, kind: 'form', fields };
  const before = structuredClone(form); const answers = initialAnswers(form);
  assert.equal(canAnswer(form), true);
  assert.equal(answers.fields.pass, 'private-default');
  const response = answerRequest(form, { ...answers, fields: { ...answers.fields, stale: 'do-not-submit', realm: 'value-b' } });
  assert.deepEqual(Object.keys(response.formValues), ['realm', 'pass', '__proto__']);
  assert.equal(response.formValues.realm, 'value-b');
  assert.equal(response.formValues.__proto__, 'exact-value');
  assert.equal(Object.getPrototypeOf(response.formValues), Object.prototype);
  assert.deepEqual(form, before);
  assert.throws(() => answerRequest(form, { ...answers, fields: { ...answers.fields, realm: 'Visible label' } }), /vpn_auth_invalid_response/);
});

test('unsupported forms cannot be partially submitted or silently lose fields', () => {
  const field = { submissionKey: 'field', name: '', label: '', kind: 'text', value: '', options: [] };
  for (const fields of [[], [field, field], [{ ...field, submissionKey: '' }], [{ ...field, kind: 'hidden' }], [{ ...field, kind: 'select' }], [{ ...field, kind: 'select', options: [{ value: 'same', label: 'one' }, { value: 'same', label: 'two' }] }], Array.from({ length: 129 }, (_, i) => ({ ...field, submissionKey: String(i) }))]) {
    const form = { ...challenge, kind: 'form', fields };
    assert.equal(canAnswer(form), false);
    assert.throws(() => answerRequest(form, initialAnswers(form)), /vpn_auth_unsupported/);
  }
  assert.equal(canAnswer({ ...challenge, kind: 'form', fields: Array.from({ length: 128 }, (_, i) => ({ ...field, submissionKey: String(i) })) }), true);
  for (const kind of ['browser', 'open-url', 'new-server-method']) {
    const form = { ...challenge, kind };
    assert.equal(canAnswer(form), false);
    assert.throws(() => answerRequest(form, initialAnswers(form)), /vpn_auth_unsupported/);
  }
});

test('authentication UI errors never echo arbitrary transport or server strings', () => {
  for (const language of ['ru', 'en']) {
    assert.ok(vpnError('vpn_auth_stale', language));
    for (const value of ['private-password', 'https://server/?token=private', '<script>private</script>']) {
      assert.ok(!vpnError(value, language).includes(value));
      assert.ok(!vpnOtpError(value, language).includes(value));
    }
  }
});
