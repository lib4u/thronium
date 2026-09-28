import { translate, type Language } from '../shared/i18n/index.ts';
import { defaults } from '../shared/api/generated/defaults.ts';
import type { Group } from '../api';

/** The built-in group every library has; it cannot be renamed or deleted. */
export const personalGroupId = defaults.personalGroup;
export const isPersonalGroup = (id: string | null | undefined) => id === personalGroupId;
/** The name shown for a group: the translated built-in name, else the subscription title or the saved name. */
export const groupName = (g: Pick<Group, 'id' | 'name' | 'displayName'>, language: Language) =>
  isPersonalGroup(g.id) ? translate(language, 'subscriptions.personal_09c5ff5') : g.displayName || g.name;
/** The profiles a group holds, in library order. */
export const profilesOf = <P extends { groupId: string }>(profiles: readonly P[], groupId: string): P[] =>
  profiles.filter((p) => p.groupId === groupId);
