import type * as Wire from './shared/api/generated/commands';
export { command } from './shared/api/command';
import { defaults } from './shared/api/generated/defaults.ts';

export type Kind = Wire.ProfileKind;
export type PingMethod = Wire.PingMethod;
export type ProbeStatus = Wire.ProbeStatus;
export type Measurement = Wire.Measurement;
export type ProbeBatch = Wire.ProbeBatch;
export type Profile = Wire.ProfileSummary;
export type VpnPolicy = Wire.VpnPolicy;
export type Draft = Wire.ProfileDraft;
export type SubscriptionUsage = Wire.SubscriptionUsage;
export type SubscriptionNameRules = Wire.SubscriptionNameRules;
export type SubscriptionSettings = Wire.SubscriptionSettings;
export type ProviderRouting = Wire.ProviderRouting;
export type UpdateCounts = Wire.UpdateCounts;
export type UpdateStatus = Wire.UpdateStatus;
export type LastUpdate = Wire.LastUpdate;
export type SubscriptionJob = Wire.SubscriptionJob;
export type GroupChain = Wire.GroupChain;
export type Group = Wire.GroupSummary;
export type PingSettings = Wire.PingSettings;
export type TunSettings = Wire.TunSettings;
export type VlessCore = Wire.VlessCore;
export type Preferences = Wire.Preferences;
export type Connection = Wire.Connection;
export type RoutingStatus = Wire.RoutingStatus;
export type VpnChallengeRequest = Wire.VpnChallengeRequest;
export type VpnOtpStatus = Wire.VpnOtpStatus;
export type VpnEndpoint = Wire.VpnEndpoint;
export type VpnStatus = Wire.VpnStatus;
export type VpnChallengeField = Wire.VpnChallengeField;
export type VpnChallenge = Wire.VpnChallenge;
export type VpnChallengeResponse = Wire.Request<'submitVpnChallenge'>;
export type Snapshot = Wire.Snapshot;

export const empty: Snapshot = {
  // Nothing is known about this desktop's key store until the engine answers.
  sealing: 'unavailable',
  tunSupported: false,
  autoSelectAvailable: false,
  autoSelectMemberCount: 0,
  systemProxy: { available: false, active: false, error: null },
  urlTests: null,
  subscriptionJobs: [],
  routing: {
    ...defaults.routing,
    revision: 0,
    pending: false,
    profileOwned: false,
    providerOwned: false,
    providerGroup: null,
  },
  profiles: [],
  groups: structuredClone(defaults.groups) as unknown as Wire.Snapshot['groups'],
  preferences: structuredClone(defaults.preferences) as unknown as Wire.Preferences,
  selected: null,
  running: null,
  coreAvailable: false,
  phase: 'disconnected',
  since: null,
  error: null,
  vpn: { sessionId: null, endpoints: [], error: null },
  trafficAvailable: false,
  trafficUp: 0,
  trafficDown: 0,
  localProxy: null,
  connections: [],
};
