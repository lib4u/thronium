import { translate, type MessageKey } from '../shared/i18n/index.ts';
import type * as Wire from '../shared/api/generated/commands';
import type { Kind } from '../api';

// Types, field builders and the values shared by several protocol forms.
// JSON paths are the wire configuration's keys, not the Qt form's widget IDs.
export type Config = Wire.Configuration;
export type Label = MessageKey;
export type FieldKind =
  | 'text'
  | 'secret'
  | 'number'
  | 'range'
  | 'string-range'
  | 'mark'
  | 'bool'
  | 'list'
  | 'numbers'
  | 'json'
  | 'select';
export type Field = {
  path: string;
  label: Label;
  kind: FieldKind;
  options?: (string | number)[];
  min?: number;
  max?: number;
  wide?: boolean;
  hint?: Label;
  unsetLabel?: Label;
};
export type Section = { id: string; label: Label; fields: Field[] };
export type Definition = {
  id: string;
  label: Label;
  kind: Kind;
  seed: Config;
  main: Field[];
  tls?: boolean;
  transport?: boolean;
  mux?: boolean;
  quic?: boolean;
};
export const label = (value: Label, language: string) => translate(language, value);
export const f = (
  path: string,
  message: Label,
  kind: FieldKind = 'text',
  options?: (string | number)[],
): Field => ({
  path,
  label: message,
  kind,
  options,
});
export const n = (path: string, message: Label, min = 0, max = Number.MAX_SAFE_INTEGER): Field => ({
  ...f(path, message, 'number'),
  min,
  max,
});
export const b = (path: string, message: Label) => f(path, message, 'bool');
export const list = (path: string, message: Label) => f(path, message, 'list');
export const json = (path: string, message: Label) => ({ ...f(path, message, 'json'), wide: true });
export const secret = (path: string, message: Label) => f(path, message, 'secret');
export const select = (path: string, message: Label, options: (string | number)[]) =>
  f(path, message, 'select', options);
export const address = f('server', 'profiles.server_address_57ff2f5');
export const port = n('server_port', 'profiles.port_651531e', 1, 65535);
export const credentials = [
  f('username', 'profiles.username_b80b698'),
  secret('password', 'profiles.password_8714570'),
];
export const password = credentials[1];
export const uuid = secret('uuid', 'profiles.uuid_624b8e1');
export const packetEncoding = select('packet_encoding', 'profiles.packet_encoding_9154155', [
  '',
  'packetaddr',
  'xudp',
]);
export const serverPorts = list('server_ports', 'profiles.port_ranges_e04156b');
export const bandwidth = [
  n('up_mbps', 'profiles.upload_mbps_26e51ac'),
  n('down_mbps', 'profiles.download_mbps_0ffab78'),
];
export const uot = b('udp_over_tcp.enabled', 'profiles.udp_over_tcp_9a8176a');
export const congestion = select('congestion_control', 'profiles.congestion_control_10767ce', [
  'cubic',
  'new_reno',
  'bbr',
]);
