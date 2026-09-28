import test from 'node:test';
import assert from 'node:assert/strict';
import { autoSelectStatus, quickSelectPool } from '../src/selectors/autoSelectStatus.ts';
import { configSections, editableQuickConfig } from '../src/selectors/autoSelectModel.ts';

test('quick status resolves TCP and UDP separately against current library metadata', () => {
  const pool = { selected: 'tcp', selectedUdp: 'udp', balance: true, needsReconnect: true,
    members: [{ tag: 'tcp', profileId: 'a' }, { tag: 'udp', profileId: 'b' }] };
  const profiles = [{ id: 'a', name: 'New TCP name' }, { id: 'b', name: 'UDP host' }];
  const status = autoSelectStatus(pool, profiles);
  assert.equal(status.tcp.name, 'New TCP name');
  assert.equal(status.udp.name, 'UDP host');
  assert.equal(status.balance, true);
  assert.equal(status.needsReconnect, true);
  assert.equal(autoSelectStatus(pool, [profiles[1]]).tcp, undefined);
});

test('explicit Core tags take precedence over transitional selected flags', () => {
  const profiles = [{ id: 'a' }, { id: 'b' }];
  const pool = { selected: 'new', selectedUdp: '', members: [
    { tag: 'old', profileId: 'a', selected: true, selectedUdp: true },
    { tag: 'new', profileId: 'b', selected: false },
  ] };
  const status = autoSelectStatus(pool, profiles);
  assert.equal(status.tcp.id, 'b');
  assert.equal(status.udp.id, 'a');
});

test('the quick configurator retains reuse and displays the effective legacy zero defaults', () => {
  const original = { tolerance: 0, dial_retries: 0 };
  const config = editableQuickConfig(original);
  assert.equal(config.reuse_ttl, '30m');
  assert.equal(config.tolerance, 100);
  assert.equal(config.dial_retries, 2);
  assert.deepEqual(original, { tolerance: 0, dial_retries: 0 });
  const fields = configSections(config).flatMap(s => s.fields);
  assert(!fields.some(f => f.path === 'reuse_ttl'));
  assert.equal(fields.find(f => f.path === 'dial_retries').min, 1);
});


test('quick status finds the virtual profile after WARP renames the Core pool', () => {
  const auxiliary = { tag: 'proxy', profileId: 'manual', members: [] };
  const quick = { tag: 'settings-warp-base', profileId: 'auto-select', selected: 'server',
    members: [{ tag: 'server', profileId: 'a' }] };
  assert.equal(quickSelectPool([auxiliary, quick]), quick);
  assert.equal(autoSelectStatus(quickSelectPool([quick]), [{ id: 'a', name: 'Main VPN' }]).tcp.name, 'Main VPN');
  assert.equal(quickSelectPool([auxiliary]), undefined);
});
