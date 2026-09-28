import { command } from './command';
import { ApiError } from './errors';
import { isModel } from './validation';
import type { ProfileExport } from './generated/commands';

export async function exportedProfiles(ids: string[]): Promise<ProfileExport[]> {
  const response = await command('exportProfiles', { ids, format: 'profiles', destination: 'preview' });
  if (typeof response.text !== 'string') throw new ApiError('invalid_command_response');
  let value: unknown;
  try {
    value = JSON.parse(response.text);
  } catch {
    throw new ApiError('invalid_command_response');
  }
  if (!value || typeof value !== 'object' || !('profiles' in value) || !Array.isArray(value.profiles)) {
    throw new ApiError('invalid_command_response');
  }
  return value.profiles.map((profile: unknown) => {
    if (!isModel('ProfileExport', profile)) throw new ApiError('invalid_command_response');
    return profile;
  });
}

export async function qrPreview(text: string): Promise<string> {
  const response = await command('exportQr', { text, destination: 'preview' });
  if (typeof response.image !== 'string') throw new ApiError('invalid_command_response');
  return response.image;
}
