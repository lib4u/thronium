import { translate } from '../shared/i18n/index.ts';
import type { Preferences, Profile } from '../api';
type Language = Preferences['language'];

export type OrderBlock = 'busy' | 'selection' | 'filtered' | 'sorted';
export function orderBlocked(context: {
  busy: boolean;
  selecting: boolean;
  query: string;
  protocol: string;
  favorites: boolean;
  sort?: string;
}): OrderBlock | null {
  if (context.busy) return 'busy';
  if (context.selecting) return 'selection';
  // The actual search includes whitespace, so a whitespace-only query is still a filter.
  if (context.query !== '' || context.protocol !== '' || context.favorites) return 'filtered';
  if (context.sort && context.sort !== 'original') return 'sorted';
  return null;
}
export function orderNeighbor(
  profiles: Pick<Profile, 'id' | 'groupId'>[],
  id: string,
  offset: -1 | 1,
): string | null {
  const current = profiles.find((p) => p.id === id);
  if (!current) return null;
  const members = profiles.filter((p) => p.groupId === current.groupId);
  return members[members.findIndex((p) => p.id === id) + offset]?.id ?? null;
}
const labels = {
  up: 'library.move_up_9f8d9bd',
  down: 'library.move_down_2f3f31e',
  drag: 'library.change_order_e9c6c63',
  help: 'library.drag_the_handle_or_press_alt_click_the_handle_to_4939f3c',
  subscription: 'library.updating_the_subscription_restores_the_provider__a3e4780',
  busy: 'library.wait_for_the_current_operation_to_finish_9cc7c20',
  selection: 'library.finish_selecting_multiple_servers_to_change_thei_928ec4c',
  filtered: 'library.clear_the_search_and_filters_to_change_the_order_dbd7fd5',
  sorted: 'library.choose_library_order_sorting_to_change_the_order_4c8d735',
  invalid_profile_order: 'library.servers_can_only_be_reordered_within_the_same_gr_0b76c7f',
} as const;
export function orderText(key: keyof typeof labels, language: Language): string {
  return translate(language, labels[key]);
}
export function orderHint(block: OrderBlock | null, subscribed: boolean, language: Language): string {
  return [orderText(block ?? 'help', language), subscribed ? orderText('subscription', language) : '']
    .filter(Boolean)
    .join(' ');
}
