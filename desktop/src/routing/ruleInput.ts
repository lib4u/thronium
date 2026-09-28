import { parseValue, formatValue, type MatchField } from './model.ts';

// Commas are separators only for fields whose values cannot contain them.
// Expressions, process paths, SSIDs and opaque tags retain newline-separated input.
export const commaValues = (field: MatchField) =>
  field.kind === 'numbers' ||
  [
    'domain',
    'domain_suffix',
    'ip_cidr',
    'source_ip_cidr',
    'port_range',
    'source_port_range',
    'network',
    'protocol',
    'source_mac_address',
    'wifi_bssid',
    'sniffer',
  ].includes(field.key);
export const parseRuleValue = (field: MatchField, value: string) =>
  parseValue(field, commaValues(field) ? value.replace(/,/g, '\n') : value);
export const formatRuleValue = (field: MatchField, value: unknown) =>
  Array.isArray(value) && commaValues(field) ? value.join(', ') : formatValue(field, value);
export const primaryActionKeys = new Set([
  'override_address',
  'override_port',
  'network_strategy',
  'tls_spoof',
  'tls_spoof_method',
]);
/** Address strategies of sing-box DNS rules, servers and resolvers. */
export const dnsStrategies = ['prefer_ipv4', 'prefer_ipv6', 'ipv4_only', 'ipv6_only'];
export const optionValues: Record<string, string[]> = {
  method: ['default', 'drop', 'reply'],
  network_strategy: ['default', 'fallback', 'hybrid'],
  strategy: dnsStrategies,
  tls_spoof_method: ['wrong-sequence', 'wrong-checksum', 'wrong-ack', 'wrong-md5', 'wrong-timestamp'],
};
