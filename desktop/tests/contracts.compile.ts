import { command } from '../src/shared/api/command';
import type { EditableProfile } from '../src/shared/api/generated/commands';

// Compile-only witnesses: the function is never invoked by the application or tests.
export function contractTypes() {
  const profile: Promise<EditableProfile> = command('profile', { id: 'profile' });
  void profile;
  void command('snapshot');
  void command('saveProfileConfiguration', { id: 'profile', expectedRevision: 'revision', config: {} });
  // @ts-expect-error Command names come from the Rust registry.
  void command('snapshott');
  // @ts-expect-error A profile lookup requires its payload.
  void command('profile');
  // @ts-expect-error The ID must be a string.
  void command('profile', { id: 42 });
  // @ts-expect-error Configuration editing requires an expected revision.
  void command('saveProfileConfiguration', { id: 'profile', config: {} });
  // @ts-expect-error Callers cannot choose a fictitious response type.
  void command<{ arbitrary: boolean }>('snapshot');
}

import type { IconName } from '../src/shared/ui/icons';
const validIcon: IconName = 'server';
void validIcon;
// @ts-expect-error unknown icon names must be resolved explicitly at a data boundary
const invalidIcon: IconName = 'missing-icon';
void invalidIcon;
