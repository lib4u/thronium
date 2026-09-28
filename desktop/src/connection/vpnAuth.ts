import type { Profile, VpnChallenge, VpnChallengeRequest, VpnChallengeResponse, VpnStatus } from '../api';

export function vpnEndpointLabel(tag: string, profile?: Profile) {
  return tag === 'proxy' && profile?.kind === 'sing-box-outbound' ? profile.name : tag;
}

export function challengeKey(request: VpnChallengeRequest) {
  return JSON.stringify([request.sessionId, request.endpointTag, request.challengeId]);
}
export function isCurrentChallenge(status: VpnStatus, request: VpnChallengeRequest) {
  return (
    status.sessionId === request.sessionId &&
    status.endpoints.some((e) => e.tag === request.endpointTag && e.challengeId === request.challengeId)
  );
}
export function challengeExpired(challenge: VpnChallenge, now = Date.now()) {
  return challenge.deadline > 0 && challenge.deadline <= Math.floor(now / 1000);
}
export function canAnswer(challenge: VpnChallenge) {
  if (['credentials', 'secret', 'message'].includes(challenge.kind)) return true;
  if (challenge.kind !== 'form' || !challenge.fields.length || challenge.fields.length > 128) return false;
  const keys = new Set<string>();
  return challenge.fields.every((field) => {
    if (
      !field.submissionKey ||
      keys.has(field.submissionKey) ||
      !['text', 'password', 'select'].includes(field.kind)
    )
      return false;
    keys.add(field.submissionKey);
    if (field.kind !== 'select') return true;
    return (
      field.options.length > 0 && new Set(field.options.map((o) => o.value)).size === field.options.length
    );
  });
}
export type Answers = { username: string; password: string; secret: string; fields: Record<string, string> };
export function initialAnswers(challenge: VpnChallenge): Answers {
  return {
    username: challenge.username,
    password: '',
    secret: '',
    fields: Object.fromEntries(challenge.fields.map((field) => [field.submissionKey, field.value])),
  };
}
export function answerRequest(
  challenge: VpnChallenge,
  answers: Answers,
  now = Date.now(),
): VpnChallengeResponse {
  if (challengeExpired(challenge, now)) throw new Error('vpn_auth_expired');
  if (!canAnswer(challenge)) throw new Error('vpn_auth_unsupported');
  const result: VpnChallengeResponse = {
    sessionId: challenge.sessionId,
    endpointTag: challenge.endpointTag,
    challengeId: challenge.challengeId,
    username: '',
    password: '',
    secret: '',
    formValues: {},
  };
  if (challenge.kind === 'credentials') {
    result.username = answers.username;
    result.password = answers.password;
    result.secret = answers.secret;
  } else if (challenge.kind === 'secret') result.secret = answers.secret;
  else if (challenge.kind === 'form') {
    const values: [string, string][] = [];
    for (const field of challenge.fields) {
      const value = answers.fields[field.submissionKey] ?? '';
      if (field.kind === 'select' && !field.options.some((option) => option.value === value))
        throw new Error('vpn_auth_invalid_response');
      values.push([field.submissionKey, value]);
    }
    result.formValues = Object.fromEntries(values);
  }
  return result;
}
