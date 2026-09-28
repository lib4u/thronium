import type * as Wire from '../shared/api/generated/commands';
import { defaults } from '../shared/api/generated/defaults.ts';
export type Draft = Wire.OtpDraft;

export type Row = Wire.OtpRow;

export type Editor = Wire.OtpEditRequest;

export type ExportFormat = Wire.OtpExportFormat;

export type Code = Wire.OtpCode;

export const empty = (): Draft => structuredClone(defaults.otp);
