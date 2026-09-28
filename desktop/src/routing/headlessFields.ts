import type { Label } from '../profiles/schema.ts';
import { portKeys, validPort, type MatchField } from './model.ts';
import { formatRuleValue, parseRuleValue } from './ruleInput.ts';

// Explicit option.DefaultHeadlessRule fields from the pinned Go reflection.
// This is not the route-field list with actions removed: e.g. query_type is
// headless-only, while protocol, ip_version and rule_set are not headless.
const field = (key: string, message: Label, kind: MatchField['kind'] = 'list'): MatchField => ({
  key,
  label: message,
  kind,
});
export const headlessFields: MatchField[] = [
  field('query_type', 'routing.dns_query_types_a_aaaa_or_0_65535_abd698a'),
  field('network', 'routing.network_tcp_udp_icmp_69a8909'),
  field('domain', 'routing.domain_381e975'),
  field('domain_suffix', 'routing.domain_suffix_c8634ef'),
  field('domain_keyword', 'routing.domain_keyword_b0ecba3'),
  field('domain_regex', 'routing.domain_expression_bab7097'),
  field('source_ip_cidr', 'routing.source_ip_cidr_3d32b18'),
  field('ip_cidr', 'routing.destination_ip_cidr_f03f18c'),
  field('source_port', 'routing.source_port_474ca84', 'numbers'),
  field('source_port_range', 'routing.source_port_range_cd681bf'),
  field('port', 'routing.destination_port_a66ec87', 'numbers'),
  field('port_range', 'routing.destination_port_range_dab0144'),
  field('process_name', 'routing.process_name_87ce9cf'),
  field('process_path', 'routing.process_path_eb8aa32'),
  field('process_path_regex', 'routing.process_path_expression_34a9dd2'),
  field('package_name', 'routing.package_name_100b1bf'),
  field('package_name_regex', 'routing.package_name_expression_201e220'),
  field('network_type', 'routing.interface_type_00ef6c1'),
  field('network_is_expensive', 'routing.metered_network_0d7a114', 'bool'),
  field('network_is_constrained', 'routing.constrained_network_d92baae', 'bool'),
  field('wifi_ssid', 'routing.wi_fi_ssid_3cf354f'),
  field('wifi_bssid', 'routing.wi_fi_bssid_ef0bdec'),
  field('network_interface_address', 'routing.network_interface_addresses_7125ad6', 'json'),
  field('default_interface_address', 'routing.default_interface_address_111609a'),
];
// Exact names from miekg/dns.StringToType, including case-sensitive None and
// Reserved. Numeric input is explicitly encoded as a JSON number, not a name.
export const dnsQueryTypeNames: readonly string[] = [
  'A',
  'AAAA',
  'AFSDB',
  'AMTRELAY',
  'ANY',
  'APL',
  'ATMA',
  'AVC',
  'AXFR',
  'CAA',
  'CDNSKEY',
  'CDS',
  'CERT',
  'CNAME',
  'CSYNC',
  'DHCID',
  'DLV',
  'DNAME',
  'DNSKEY',
  'DS',
  'EID',
  'EUI48',
  'EUI64',
  'GID',
  'GPOS',
  'HINFO',
  'HIP',
  'HTTPS',
  'IPSECKEY',
  'ISDN',
  'IXFR',
  'KEY',
  'KX',
  'L32',
  'L64',
  'LOC',
  'LP',
  'MAILA',
  'MAILB',
  'MB',
  'MD',
  'MF',
  'MG',
  'MINFO',
  'MR',
  'MX',
  'NAPTR',
  'NID',
  'NIMLOC',
  'NINFO',
  'NS',
  'NSAP-PTR',
  'NSEC',
  'NSEC3',
  'NSEC3PARAM',
  'NULL',
  'NXNAME',
  'NXT',
  'None',
  'OPENPGPKEY',
  'OPT',
  'PTR',
  'PX',
  'RESINFO',
  'RKEY',
  'RP',
  'RRSIG',
  'RT',
  'Reserved',
  'SIG',
  'SMIMEA',
  'SOA',
  'SPF',
  'SRV',
  'SSHFP',
  'SVCB',
  'TA',
  'TALINK',
  'TKEY',
  'TLSA',
  'TSIG',
  'TXT',
  'UID',
  'UINFO',
  'UNSPEC',
  'URI',
  'X25',
  'ZONEMD',
];
const queryNames = new Set(dnsQueryTypeNames);
const uint16 = (value: unknown): value is number =>
  typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 65535;
export function parseHeadlessField(field: MatchField, text: string): unknown {
  if (field.key === 'query_type' || field.key === 'port' || field.key === 'source_port') {
    if (!text.trim()) return undefined;
    return text
      .trim()
      .split(/[\s,]+/)
      .map((value) => {
        if (/^\d+$/.test(value)) {
          const number = Number(value);
          if (field.key === 'query_type' ? uint16(number) : validPort(number)) return number;
        }
        if (field.key === 'query_type' && queryNames.has(value)) return value;
        throw Error('invalid_condition');
      });
  }
  const parsed = parseRuleValue(field, text);
  if (parsed !== undefined && !headlessValueShape(field, parsed)) throw Error('invalid_condition');
  return parsed;
}
export function formatHeadlessField(field: MatchField, value: unknown): string {
  if (field.key === 'query_type')
    return Array.isArray(value) ? value.join(', ') : value === undefined ? '' : String(value);
  return formatRuleValue(field, value);
}
/** Shape check only. IPs, regex, range grammar and interface names still go
 * through the real core; imported null/malformed values stay opaque JSON. */
export function headlessValueShape(field: MatchField, value: unknown): boolean {
  const values = Array.isArray(value) ? value : [value];
  if (field.key === 'query_type')
    return (
      values.length > 0 && values.every((v) => uint16(v) || (typeof v === 'string' && queryNames.has(v)))
    );
  if (field.kind === 'numbers')
    return values.length > 0 && values.every(portKeys.includes(field.key) ? validPort : uint16);
  if (field.kind === 'bool') return typeof value === 'boolean';
  if (field.kind === 'json') return !!value && typeof value === 'object' && !Array.isArray(value);
  return values.length > 0 && values.every((v) => typeof v === 'string');
}
