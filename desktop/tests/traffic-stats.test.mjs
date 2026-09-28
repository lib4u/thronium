import test from 'node:test';
import assert from 'node:assert/strict';
import {
  applicationLabel,
  bars,
  periodKeys,
  periods,
  profileLabel,
} from '../src/traffic/statsModel.ts';

const point = (bucket, upload, download) => ({ bucket, upload, download });

test('the chart scales every bucket against the busiest one and labels one in eight', () => {
  const series = Array.from({ length: 24 }, (_, i) => point(i * 3600, i, i * 3));
  const columns = bars(series, 3600, 'en');
  assert.equal(columns.length, 24);
  // The last bucket is the tallest, so its two shares add up to the full height.
  const last = columns[23];
  assert.equal(Math.round((last.uploadShare + last.downloadShare) * 1000) / 1000, 1);
  assert.equal(columns[0].uploadShare, 0);
  assert.equal(columns[12].downloadShare, (12 * 3) / (23 + 23 * 3));
  // A stride of three labels the first of every three columns.
  assert.deepEqual(
    columns.filter((c) => c.labelled).map((c) => c.bucket),
    [0, 3, 6, 9, 12, 15, 18, 21].map((i) => i * 3600),
  );
  assert.ok(columns.every((c) => c.label.length > 0));
});

test('an empty period still draws its buckets without dividing by zero', () => {
  const columns = bars([point(0, 0, 0), point(3600, 0, 0)], 3600, 'en');
  assert.deepEqual(
    columns.map((c) => [c.uploadShare, c.downloadShare]),
    [
      [0, 0],
      [0, 0],
    ],
  );
});

test('daily and hourly buckets are labelled as their own kind of moment', () => {
  const day = bars([point(1700000000, 1, 1)], 86400, 'en')[0].label;
  const hour = bars([point(1700000000, 1, 1)], 3600, 'en')[0].label;
  assert.notEqual(day, hour);
  assert.match(hour, /\d/);
});

test('rows that are not a server of the library say what they are', () => {
  const t = (key) => key;
  assert.equal(profileLabel({ other: true, direct: false, name: '' }, t), 'common.trafficOther');
  assert.equal(profileLabel({ other: false, direct: true, name: '' }, t), 'common.trafficDirect');
  assert.equal(
    profileLabel({ other: false, direct: false, name: '' }, t),
    'common.trafficRemovedProfile',
  );
  assert.equal(profileLabel({ other: false, direct: false, name: 'Kept' }, t), 'Kept');
  assert.equal(applicationLabel({ other: true, process: '' }, t), 'common.trafficOther');
  assert.equal(
    applicationLabel({ other: false, process: '' }, t),
    'common.trafficUnknownApplication',
  );
  assert.equal(applicationLabel({ other: false, process: 'curl' }, t), 'curl');
});

test('the selector offers exactly the periods the engine accepts', () => {
  assert.deepEqual([...periods], [1, 7, 30, 90]);
  assert.deepEqual(
    periods.map((days) => periodKeys[days]),
    [
      'common.trafficPeriodDay',
      'common.trafficPeriodWeek',
      'common.trafficPeriodMonth',
      'common.trafficPeriodQuarter',
    ],
  );
});
