import { type Profile, type Draft, type VpnChallengeRequest } from './api';
import { type Key } from './i18n';
import { type CredentialRequest } from './connection/vpnCredentials';
import { type MenuEdge } from './DropdownMenu';
import type { MessageKey } from './shared/i18n/index.ts';
import type { IconName } from './shared/ui/Icon';
export const duration = (since: number | null) => {
  const seconds = since ? Math.max(0, Math.floor(Date.now() / 1000) - since) : 0;
  return [Math.floor(seconds / 3600), Math.floor(seconds / 60) % 60, seconds % 60]
    .map((n) => String(n).padStart(2, '0'))
    .join(':');
};

export type ModalState =
  | { type: 'vpn-credentials'; request: CredentialRequest }
  | { type: 'vpn-otp'; profile: Profile }
  | { type: 'vpn-auth'; request: VpnChallengeRequest }
  | { type: 'otp-quick' }
  | { type: 'diagnostics'; profileId: string }
  | { type: 'configuration'; draft: import('./shared/api/generated/commands').EditableProfile }
  | {
      type: 'add';
      initialGroup?: string;
      initialText?: string;
      /** Files the system opened with the application, and those it could not read. */
      initialDocuments?: { filename: string; text: string }[];
      initialProblems?: { filename: string; code: string }[];
    }
  | { type: 'editor'; draft?: Draft; initialGroup?: string }
  | { type: 'delete'; profile: Profile }
  | { type: 'updates' }
  | { type: 'groups'; initialGroupId?: string; initialAction?: 'edit' | 'delete' }
  | { type: 'subscription'; groupId: string; autoLoad?: boolean }
  | { type: 'export' | 'duplicates'; ids: string[] }
  | { type: 'maintenance'; kind: import('./library/maintenance').MaintenanceKind; ids: string[] }
  | { type: 'batch'; ids: string[]; operation: 'move' | 'remove' }
  | { type: 'auto-select-config' }
  | null;

export type MenuState = {
  type: 'profile' | 'group';
  id: string;
  anchor: HTMLButtonElement;
  edge?: MenuEdge;
} | null;

export type Translate = (key: Key) => string;
/** Workspace pages in navigation order, with the label and icon of their tab. */
export const pages = [
  { id: 'connection', label: 'common.connection', icon: 'power' },
  { id: 'routing', label: 'common.routing', icon: 'route' },
  { id: 'activity', label: 'common.activity', icon: 'activity' },
  { id: 'tools', label: 'common.tools', icon: 'grid' },
  { id: 'settings', label: 'common.settings', icon: 'settings' },
] as const satisfies readonly { id: string; label: MessageKey; icon: IconName }[];
export type PageId = (typeof pages)[number]['id'];

/** Browser storage key of the library group shown last on this device. */
export const GROUP_STORAGE_KEY = 'thronium-library-group';
export function rememberedGroup() {
  try {
    return localStorage.getItem(GROUP_STORAGE_KEY) || 'all';
  } catch {
    return 'all';
  }
}
