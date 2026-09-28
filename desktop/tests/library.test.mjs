import test from 'node:test';
import assert from 'node:assert/strict';
import { sortMembers, hasProblem, memberNote } from '../src/selectors/memberRows.ts';
import { candidateKind, profilesById } from '../src/library/maintenance.ts';
import { sortProfiles } from '../src/library/sort.ts';
const preferences = { language: 'en', librarySort: 'name', librarySortDescending: false };
test('library sorting is numeric, stable and leaves original storage order unchanged', () => {
  const profiles = ['Server 10', 'Server 2', 'server 2', 'Server 1'].map((name, i) => ({ id: String(i), name }));
  assert.deepEqual(sortProfiles(profiles, preferences).map(p => p.id), ['3', '1', '2', '0']);
  assert.deepEqual(sortProfiles(profiles, { ...preferences, librarySortDescending: true }).map(p => p.id), ['0', '1', '2', '3']);
  assert.deepEqual(profiles.map(p => p.id), ['0', '1', '2', '3']);
  assert.deepEqual(sortProfiles(profiles, { ...preferences, librarySort: 'original', librarySortDescending: true }), profiles);
});
test('latency sorting always places failed or missing measurements last without inventing values', () => {
  const profiles = [null, { status: 'ok', latencyMs: 50 }, { status: 'error', latencyMs: 1 }, { status: 'ok', latencyMs: 0 }, { status: 'ok', latencyMs: 50 }].map((measurement, i) => ({ id: i, measurement }));
  assert.deepEqual(sortProfiles(profiles, { ...preferences, librarySort: 'latency' }).map(p => p.id), [3, 1, 4, 0, 2]);
  assert.deepEqual(sortProfiles(profiles, { ...preferences, librarySort: 'latency', librarySortDescending: true }).map(p => p.id), [1, 4, 3, 0, 2]);
});
test('address and protocol ordering use profile metadata for both supported locales', () => {
  const profiles = [{ id: 'a', name: 'Москва', address: 'host10', protocol: 'vless' }, { id: 'b', name: 'Астана', address: 'host2', protocol: 'socks' }];
  for (const language of ['en', 'ru']) for (const librarySort of ['address', 'protocol', 'name']) {
    assert.deepEqual(sortProfiles(profiles, { ...preferences, language, librarySort }).map(p => p.id), ['b', 'a']);
  }
});
test('security ordering follows the engine class, then the label, and leaves unclassified rows last', () => {
  const profiles = [
    { id: 'chain', security: '' },
    { id: 'reality', securityLevel: 3, security: 'Reality' },
    { id: 'raw', securityLevel: 1, security: 'ws' },
    { id: 'tls', securityLevel: 3, security: 'TLS · ws' },
    { id: 'weak', securityLevel: 2, security: 'TLS' },
    { id: 'unknown', securityLevel: 0, security: 'quic' },
  ];
  assert.deepEqual(sortProfiles(profiles, { ...preferences, librarySort: 'security' }).map(p => p.id), ['unknown', 'raw', 'weak', 'reality', 'tls', 'chain']);
  assert.deepEqual(sortProfiles(profiles, { ...preferences, librarySort: 'security', librarySortDescending: true }).map(p => p.id), ['tls', 'reality', 'weak', 'raw', 'unknown', 'chain']);
});
test('traffic ordering uses the window total and keeps rows without history last', () => {
  const profiles = [
    { id: 'none' },
    { id: 'big', traffic: { upload: 10, download: 1000 } },
    { id: 'small', traffic: { upload: 5, download: 5 } },
    { id: 'zero', traffic: { upload: 0, download: 0 } },
  ];
  assert.deepEqual(sortProfiles(profiles, { ...preferences, librarySort: 'traffic' }).map(p => p.id), ['zero', 'small', 'big', 'none']);
  assert.deepEqual(sortProfiles(profiles, { ...preferences, librarySort: 'traffic', librarySortDescending: true }).map(p => p.id), ['big', 'small', 'zero', 'none']);
});

test('maintenance asks the engine for every list except the invalid one', () => {
  const profiles = ['a', 'b'].map((id) => ({ id, name: id.toUpperCase() }));
  assert.equal(candidateKind('unavailable'), 'unavailable');
  assert.equal(candidateKind('insecure'), 'insecure');
  assert.equal(candidateKind('resolve'), 'named');
  assert.equal(candidateKind('invalid'), undefined);
  assert.deepEqual(
    profilesById(profiles, ['b', 'missing', 'a']).map((p) => p.name),
    ['B', 'A'],
  );
});

test('pool members sort and filter as the Qt statistics dialog does', () => {
  const member = (name, extra) => ({
    tag: 't-' + name, profileId: name, name, rank: 1, state: 'ok', selected: false, selectedUdp: false,
    qualified: false, active: false, averageMs: 0, deviationMs: 0, minMs: 0, maxMs: 0, samples: 0,
    failures: 0, probes: 0, dialTotal: 0, dialFailures: 0, lastOkMs: 0, lastProbeMs: 0,
    cooldownUntilMs: 0, lastError: '', ...extra,
  });
  const fast = member('fast', { rank: 2, averageMs: 40, samples: 10, lastOkMs: 500 });
  const slow = member('slow', { rank: 1, averageMs: 300, samples: 10, failures: 5, lastOkMs: 900, dialTotal: 4, dialFailures: 1 });
  const untested = member('untested', { rank: 3, state: 'untested' });
  const dead = member('dead', { rank: 4, state: 'dead', lastError: 'probe_timeout' });
  const members = [untested, slow, fast, dead];
  const names = (sort, descending = false) => sortMembers(members, sort, descending).map((m) => m.name);
  assert.deepEqual(names('rank'), ['slow', 'fast', 'untested', 'dead']);
  assert.deepEqual(names('latency'), ['fast', 'slow', 'untested', 'dead']);
  assert.deepEqual(names('latency', true), ['slow', 'fast', 'untested', 'dead']);
  // Ascending starts at the worst ratio; the header opens this column descending.
  assert.deepEqual(names('checks'), ['slow', 'fast', 'untested', 'dead']);
  assert.deepEqual(names('checks', true), ['fast', 'slow', 'untested', 'dead']);
  assert.deepEqual(names('lastOk', true), ['slow', 'fast', 'untested', 'dead']);
  assert.deepEqual(names('state'), ['slow', 'fast', 'untested', 'dead']);
  assert.deepEqual(members.filter(hasProblem).map((m) => m.name), ['dead']);
  const pool = { pinned: '', members };
  assert.equal(memberNote(dead, pool, 1000).key, 'probe_timeout');
  assert.deepEqual(memberNote(slow, pool, 1000), { key: 'noteFailures', params: { failures: 5, samples: 10 } });
  assert.equal(memberNote(untested, pool, 1000).key, 'noteQueued');
  assert.equal(memberNote(fast, { ...pool, pinned: fast.tag }, 1000).key, 'notePinnedUnusable');
  const cooling = member('cool', { state: 'cooldown', cooldownUntilMs: 9000 });
  assert.deepEqual(memberNote(cooling, pool, 5000), { key: 'noteCooldownIn', params: { seconds: 4 } });
});
