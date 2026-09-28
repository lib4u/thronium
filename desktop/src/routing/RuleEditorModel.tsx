import { Select } from '../shared/ui/controls';
import { type Profile } from '../api';
import { type Label } from '../profiles/schema';
import { builtInTargets, outboundProfiles } from './model';
export const messageKeys = {
  categories: 'routing.geo_categories_2a9b058',
  loadProfile: 'routing.load_profile_b19cb5b',
  exportProfile: 'routing.export_profile_78950a4',
  source: 'routing.source_64835b1',
  title: 'routing.routing_3247b97',
  hint: 'routing.choose_a_route_for_your_applications_and_destina_e25bcf9',
  add: 'routing.add_rule_84852c7',
  profiles: 'routing.profiles_a0a505c',
  profile: 'routing.routing_profile_fa1594a',
  default: 'routing.default_4d4d367',
  rules: 'routing.rules_29241d7',
  simple: 'routing.address_lists_32241bd',
  sets: 'routing.rule_sets_28d0c07',
  dns: 'routing.dns_212189c',
  raw: 'routing.json_96a5a28',
  rulesMode: 'routing.by_rules_4359aee',
  allMode: 'routing.all_traffic_1d690b2',
  directMode: 'routing.direct_cc7ab89',
  rulesHint: 'routing.routes_for_your_apps_and_destinations_7e2338a',
  allHint: 'routing.connections_use_the_selected_server_1829e9a',
  directHint: 'routing.connections_use_your_network_directly_0ff054f',
  proxy: 'routing.selected_server_1797ac9',
  warp: 'routing.through_warp',
  'warp-bypass': 'routing.vpn_without_warp',
  warpHint: 'routing.warp_target_hint',
  direct: 'routing.direct_cc7ab89',
  block: 'routing.block_59fb954',
  final: 'routing.all_other_traffic_ce8f36e',
  priority: 'routing.priority_rule_02d0076',
  action: 'routing.action_6b117e2',
  enabled: 'routing.enabled_dde9969',
  order: 'routing.rules_are_evaluated_from_top_to_bottom_6bc4afc',
  search: 'routing.find_a_rule_6c6f8d3',
  none: 'routing.no_matching_rules_a5ce659',
  empty: 'routing.add_an_app_domain_or_ip_rule_687aa7b',
  target: 'routing.destination_7de9527',
  saved: 'routing.saved_c2b7708',
  saving: 'routing.validating_and_saving_3a65dc1',
  next: 'routing.changes_apply_to_the_next_connection_296d832',
  pending: 'routing.routing_changes_are_saved_reconnect_to_apply_the_8c8900c',
  apply: 'routing.apply_and_reconnect_b346b2a',
  inactive: 'routing.these_rules_apply_in_by_rules_mode_e34acb4',
  own: 'routing.the_selected_full_json_configuration_defines_its_365cce9',
  legacyPolicy: 'routing.imported_from_throne_this_preset_keeps_its_saved_18c1992',
  provider: 'routing.subscription_dns_and_routing_apply_by_default_yo_297a86f',
  up: 'routing.move_up_441b312',
  down: 'routing.move_down_d672813',
  remove: 'routing.delete_55f670b',
  clone: 'routing.duplicate_586c15a',
  edit: 'routing.edit_0fd5c3c',
  cancel: 'routing.cancel_bf4c449',
  close: 'routing.close_c9a286c',
  save: 'routing.save_9cd85bd',
  done: 'routing.done_239ae08',
  newProfile: 'routing.new_routing_profile_5c1f463',
  name: 'routing.name_5163a2e',
  deleteProfile: 'routing.delete_this_routing_profile_be58ae0',
  deleteRule: 'routing.delete_this_rule_a2dd5a1',
  newRule: 'routing.new_rule_83c8739',
  editRule: 'routing.edit_rule_ea3572d',
  conditions: 'routing.conditions_16b104c',
  addCondition: 'routing.add_condition_889cb05',
  field: 'routing.condition_type_dbb9cfc',
  value: 'routing.value_a08fa53',
  invert: 'routing.invert_the_match_f63d003',
  ruleHint: 'routing.rules_are_evaluated_from_top_to_bottom_address_c_afdc1aa',
  groupConditions: 'routing.group_conditions_f73dd9d',
  groupUnsupported: 'routing.use_json_to_group_this_rule_without_losing_its_a_afc0b98',
  ruleName: 'routing.rule_name_d84c2fa',
  nameExample: 'routing.for_example_browser_through_vpn_4f6cf76',
  trafficAction: 'routing.what_to_do_with_traffic_5a9e0d2',
  ruleOutbound: 'routing.outbound_route_c31a350',
  saveRule: 'routing.save_rule_d0c4027',
  builder: 'routing.builder_8004ebd',
  commaHint: 'routing.comma_separated_values_b9e824d',
  lineHint: 'routing.one_value_per_line_5405bd3',
  moreOptions: 'routing.more_options_38af03c',
  conditionHint: 'routing.one_value_per_line_nested_groups_combine_conditi_f8374f4',
  any: 'routing.without_conditions_this_rule_matches_all_connect_6c3c8c3',
  logical: 'routing.nested_condition_groups_477ab49',
  advanced: 'routing.action_options_ac5eb26',
  inherited: 'routing.default_4d4d367',
  yes: 'routing.yes_0a80c56',
  no: 'routing.no_3f7ce4a',
  badValue: 'routing.check_this_value_046ee79',
  badName: 'routing.enter_a_name_8bfad9a',
  simpleHint: 'routing.one_selector_per_line_domain_suffix_regex_keywor_5975387',
  simpleSave: 'routing.save_list_269d32f',
  simpleOnly: 'routing.replaces_this_list_and_preserves_other_rules_08a73de',
  rawHint: 'routing.route_json_including_disabled_rules_names_and_sw_771307c',
  setsHint: 'routing.local_remote_and_inline_sing_box_rule_sets_rules_6ca04e4',
  dnsHint: 'routing.dns_servers_rules_and_cache_settings_for_this_ro_14dd667',
  check: 'routing.validate_e2a8979',
  checked: 'routing.the_core_accepted_this_configuration_dde5666',
  unsaved: 'routing.unsaved_changes_f73b98c',
  local: 'routing.local_network_bb3a46a',
  localHint: 'routing.add_a_rule_for_private_destination_addresses_cf568c8',
  systemRoute: 'routing.system_route_a6dcab9',
  bypassHint: 'routing.bypass_requires_linux_tun_with_auto_redirect_des_5969639',
} satisfies Record<string, Label>;

export type W = keyof typeof messageKeys;

export type Tr = (key: W) => string;

export function Targets({
  value,
  profiles,
  tr,
  changed,
  block = false,
  system = false,
  disabled = false,
}: {
  value: string;
  profiles: Profile[];
  tr: Tr;
  changed(value: string): void;
  block?: boolean;
  system?: boolean;
  disabled?: boolean;
}) {
  const options = [
    ...(system ? [{ id: '', name: tr('systemRoute') }] : []),
    ...builtInTargets
      .filter((target) => block || target !== 'block')
      .map((target) => ({ id: target, name: tr(target) })),
    ...outboundProfiles(profiles).map((p) => ({ id: 'profile:' + p.id, name: p.name })),
  ];
  return (
    <Select
      className="text-input route-target"
      aria-label={tr('target')}
      value={value}
      disabled={disabled}
      onChange={(e) => changed(e.target.value)}
    >
      {!options.some((o) => o.id === value) && <option value={value}>{value}</option>}
      {options.map((o) => (
        <option key={o.id} value={o.id}>
          {o.name}
        </option>
      ))}
    </Select>
  );
}
