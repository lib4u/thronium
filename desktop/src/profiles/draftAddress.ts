type Config = Record<string, unknown>;
const object = (value: unknown): Config | undefined =>
  value && typeof value === 'object' && !Array.isArray(value) ? (value as Config) : undefined;
const single = (value: unknown): Config | undefined =>
  Array.isArray(value) && value.length === 1 ? object(value[0]) : undefined;

/**
 * The server host shown for a draft that is not saved yet. Saved profiles get
 * it from the engine (`profile_descriptor::endpoint`); this follows the same
 * order: the outbound's own server, else the single entry of a server list.
 */
export function draftAddress(config: Config): string {
  if (typeof config.server === 'string') return config.server;
  const settings = object(config.settings);
  if (typeof settings?.address === 'string') return settings.address;
  for (const list of [settings?.vnext, settings?.servers, config.peers, settings?.peers]) {
    const entry = single(list);
    if (typeof entry?.address === 'string') return entry.address;
    if (typeof entry?.endpoint === 'string') {
      const colon = entry.endpoint.lastIndexOf(':');
      return colon < 0 ? '' : entry.endpoint.slice(0, colon).replace(/^\[|\]$/g, '');
    }
  }
  return '';
}
