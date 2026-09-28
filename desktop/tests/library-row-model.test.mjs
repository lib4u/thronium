import test from 'node:test';
import assert from 'node:assert/strict';
import {
  displayedData,
  rowSubtitle,
  rowStats,
  securityWarning,
  trafficText,
} from '../src/library/rowData.ts';
import catalog from '../contracts/settings.catalog.json' with { type: 'json' };

const profile = {
  id: 'p',
  name: 'Row',
  address: 'host.example',
  port: 8443,
  protocol: 'trojan',
  security: 'TLS · ws',
  securityLevel: 2,
};
const measurement = (kind, extra) => ({
  kind,
  method: 'http',
  effectiveMethod: 'http',
  attempts: [],
  firstHop: false,
  profileId: 'p',
  name: 'Row',
  status: 'ok',
  latencyMs: null,
  error: null,
  at: 1700000000,
  ip: null,
  countryCode: null,
  download: null,
  upload: null,
  ...extra,
});

test('displayed data defaults come from the settings catalog and snapshot values override them', () => {
  const defaults = displayedData(undefined);
  for (const id of Object.keys(defaults))
    assert.equal(defaults[id], catalog.find((f) => f.id === id).default, id);
  assert.equal(defaults.list_show_address, true);
  assert.equal(defaults.list_show_port, false);
  assert.equal(displayedData({ list_show_port: true, list_show_address: 'yes' }).list_show_port, true);
  assert.equal(displayedData({ list_show_port: true, list_show_address: 'yes' }).list_show_address, true);
});
test('subtitle shows only the chosen data and the port only next to the address', () => {
  const view = displayedData(undefined);
  assert.equal(rowSubtitle(profile, view, 'en'), 'host.example · trojan');
  assert.equal(
    rowSubtitle(profile, { ...view, list_show_port: true, show_config_security: true }, 'en'),
    'host.example:8443 · trojan · TLS · ws',
  );
  assert.equal(
    rowSubtitle(profile, { ...view, list_show_address: false, list_show_port: true }, 'en'),
    'trojan',
  );
  assert.equal(
    rowSubtitle({ ...profile, port: undefined }, { ...view, list_show_port: true }, 'en'),
    'host.example · trojan',
  );
  assert.equal(
    rowSubtitle(
      { ...profile, security: '' },
      { ...view, list_show_address: false, list_show_protocol: false, show_config_security: true },
      'en',
    ),
    '',
  );
  assert.equal(
    rowSubtitle({ ...profile, protocol: 'external-core' }, { ...view, list_show_address: false }, 'ru'),
    'Внешнее ядро',
  );
  assert.equal(
    rowSubtitle({ ...profile, protocol: 'custom' }, { ...view, list_show_address: false }, 'en'),
    'Custom',
  );
});
test('the security warning appears only for weak or raw rows while the security datum is on', () => {
  const view = displayedData({ show_config_security: true });
  assert.equal(securityWarning(profile, view), true);
  assert.equal(securityWarning({ ...profile, securityLevel: 1 }, view), true);
  assert.equal(securityWarning({ ...profile, securityLevel: 3 }, view), false);
  assert.equal(securityWarning({ ...profile, securityLevel: 0 }, view), false);
  assert.equal(securityWarning({ ...profile, securityLevel: undefined }, view), false);
  assert.equal(securityWarning(profile, { ...view, show_config_security: false }), false);
});
test('stats line stays empty until measured and formats country, speed and traffic per language', () => {
  const view = displayedData({ list_show_ip: true, list_show_speed: true, list_show_traffic: true });
  assert.deepEqual(rowStats(profile, view, 'en'), { text: '', title: '' });
  const ip = measurement('ip', { ip: '203.0.113.9', countryCode: 'JP' });
  assert.equal(rowStats({ ...profile, ipMeasurement: ip }, view, 'en').text, 'Japan · 203.0.113.9');
  assert.equal(rowStats({ ...profile, ipMeasurement: ip }, view, 'ru').text, 'Япония · 203.0.113.9');
  assert.equal(rowStats({ ...profile, ipMeasurement: ip }, { ...view, list_show_ip: false }, 'en').text, '');
  const speed = measurement('speed', { download: '12.0 MiB/s', upload: '3.0 MiB/s' });
  assert.equal(
    rowStats({ ...profile, speedMeasurement: speed }, view, 'en').text,
    '↓ 12.0 MiB/s · ↑ 3.0 MiB/s',
  );
  const failed = measurement('ip', { status: 'error', error: 'probe_timeout' });
  assert.equal(rowStats({ ...profile, ipMeasurement: failed }, view, 'en').text, '×');
  assert.match(rowStats({ ...profile, ipMeasurement: failed }, view, 'en').title, /timeout/i);
  const traffic = { upload: 2048, download: 3 * 1048576 };
  const both = rowStats({ ...profile, ipMeasurement: ip, traffic }, view, 'en');
  assert.equal(both.text, 'Japan · 203.0.113.9 · 2.0 KiB↑ 3.0 MiB↓');
  assert.match(both.title, /Uploaded: 2.0 KiB · Downloaded: 3.0 MiB/);
  assert.match(
    rowStats({ ...profile, traffic }, view, 'ru').title,
    /Отправлено: 2,0 КиБ · Получено: 3,0 МиБ/,
  );
  assert.equal(trafficText({ upload: 0, download: 0 }, 'en'), '');
  assert.equal(trafficText(undefined, 'en'), '');
});
