import test from 'node:test';
import assert from 'node:assert/strict';
import { changeText, poolText, switchColumns } from '../src/diagnostics/switchHistoryModel.ts';

const base = { id: 1, at: 1789376433, poolId: 'p1', poolName: 'Automatic pool' };

test('a switch row shows the move; the first selection has no origin', () => {
  assert.equal(
    changeText({ ...base, fromName: 'First member', toName: 'Second member' }, 'en'),
    'First member → Second member',
  );
  assert.equal(
    changeText({ ...base, fromName: '', toName: 'First member' }, 'en'),
    'First selection: First member',
  );
  assert.equal(
    changeText({ ...base, fromName: '', toName: 'First member' }, 'ru'),
    'Первый выбор: First member',
  );
  assert.equal(switchColumns.length, 3);
  assert.equal(poolText(base, 'ru'), 'Automatic pool');
  assert.equal(poolText({ ...base, poolId: 'auto-select', poolName: 'auto-select' }, 'ru'), 'Автовыбор');
});
