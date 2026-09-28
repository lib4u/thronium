import type * as Wire from '../shared/api/generated/commands';
import { AUTO_SELECT_ID } from './autoSelectModel.ts';

export type AutoSelectStatus = {
  tcp?: Wire.ProfileSummary;
  udp?: Wire.ProfileSummary;
  balance: boolean;
  needsReconnect: boolean;
};

export function autoSelectStatus(pool: Wire.SelectorPool, profiles: Wire.ProfileSummary[]): AutoSelectStatus {
  const find = (udp: boolean) => {
    const tag = udp ? pool.selectedUdp : pool.selected;
    const member = pool.members.find((m) => (tag ? m.tag === tag : udp ? m.selectedUdp : m.selected));
    return profiles.find((p) => p.id === member?.profileId);
  };
  return { tcp: find(false), udp: find(true), balance: pool.balance, needsReconnect: !!pool.needsReconnect };
}

/** Core may wrap a pool with WARP and rename its runtime tag. */
export function quickSelectPool(pools: Wire.SelectorPool[]) {
  return pools.find((pool) => pool.profileId === AUTO_SELECT_ID);
}
