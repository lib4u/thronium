import type { Profile } from '../api';

/** The maintenance actions Qt offers for the servers a group shows. */
export type MaintenanceKind = 'unavailable' | 'insecure' | 'invalid' | 'resolve';
/** How many names a confirmation lists, as Qt's `removeListPreviewLimit`. */
export const PREVIEW = 20;
/** What the engine calls the servers of this action, when it decides them. */
export const candidateKind = (kind: MaintenanceKind) =>
  kind === 'resolve' ? 'named' : kind === 'invalid' ? undefined : (kind as 'unavailable' | 'insecure');
export const profilesById = (profiles: Profile[], ids: string[]): Profile[] =>
  ids.map((id) => profiles.find((p) => p.id === id)).filter((p): p is Profile => !!p);
