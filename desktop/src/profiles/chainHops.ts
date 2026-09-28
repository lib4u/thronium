// Profile kinds a chain or a group proxy can use as a hop. The backend stays
// authoritative; this only keeps unusable profiles out of the pickers.
const hopKinds: readonly string[] = ['chain', 'sing-box-outbound', 'xray-outbound', 'xray-config'];
// A complete Xray configuration runs as its own instance that the app dials
// directly, so it can only be the first (device-side) hop.
const firstHopOnly = 'xray-config';

export const hopCandidates = <P extends { kind: string }>(profiles: readonly P[], first: boolean): P[] =>
  profiles.filter((p) => hopKinds.includes(p.kind) && (first || p.kind !== firstHopOnly));
