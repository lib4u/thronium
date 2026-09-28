import type { Preferences, Profile } from '../api';

// Successful latency; failed or missing measurements have no value.
const latency = (p: Profile) =>
  p.measurement?.status === 'ok' &&
  p.measurement.latencyMs !== null &&
  p.measurement.latencyMs !== undefined &&
  p.measurement.latencyMs >= 0
    ? p.measurement.latencyMs
    : null;
// Chains, selectors and rows without the security datum have no class.
const security = (p: Profile) => (typeof p.securityLevel === 'number' ? p.securityLevel : null);
// Window total; rows without the datum (or without history) have no value.
const traffic = (p: Profile) => (p.traffic ? p.traffic.upload + p.traffic.download : null);

export function sortProfiles(profiles: Profile[], preferences: Preferences): Profile[] {
  const { librarySort: key, librarySortDescending: descending, language } = preferences;
  if (!key || key === 'original') return [...profiles];
  const compare = new Intl.Collator(language, { numeric: true, sensitivity: 'base' }).compare;
  const numeric =
    key === 'latency' ? latency : key === 'security' ? security : key === 'traffic' ? traffic : null;
  const text = key === 'name' || key === 'address' || key === 'protocol' ? key : null;
  return profiles
    .map((profile, index) => ({ profile, index }))
    .sort((a, b) => {
      let order: number;
      if (numeric) {
        const left = numeric(a.profile),
          right = numeric(b.profile);
        // Missing and failed values stay last in either direction.
        if (left === null || right === null)
          return left === right ? a.index - b.index : left === null ? 1 : -1;
        order =
          left - right ||
          (key === 'security' ? compare(a.profile.security || '', b.profile.security || '') : 0);
      } else order = text ? compare(a.profile[text], b.profile[text]) : 0;
      return order ? order * (descending ? -1 : 1) : a.index - b.index;
    })
    .map((p) => p.profile);
}
