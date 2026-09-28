import { limits as engineLimits } from './api/generated/limits.ts';

/**
 * Every limit a catalog message may name as a placeholder: the limits
 * generated from the engine plus the few the window applies on its own.
 */
export const limits = {
  ...engineLimits,
  /** Profiles in one WireGuard or QR archive. */
  maxArchiveProfiles: 100,
  /** Nesting levels and nodes the visual rule builder edits; larger rules stay in JSON. */
  maxConditionDepth: 8,
  maxConditionNodes: 128,
  /** Entries of each type shown in a category preview. */
  maxPreviewEntries: 200,
  /** Largest `ed` value Xray accepts in a WebSocket or HTTPUpgrade path. */
  maxXrayEarlyData: 8192,
} as const;
