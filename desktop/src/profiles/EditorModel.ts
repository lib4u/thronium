import { type Config, type Label } from './schema';
export const messageKeys = {
  hint: 'profiles.protocol_and_connection_parameters_88fe0f5',
  json: 'profiles.json_96a5a28',
  fields: 'profiles.fields_24fe8af',
  unknown: 'profiles.additional_parameters_are_preserved_in_json_3e687fb',
  inherited: 'profiles.default_4d4d367',
  enabled: 'profiles.enabled_dde9969',
  disabled: 'profiles.disabled_202f2f6',
  listHint: 'profiles.one_value_per_line_c31f619',
  rangeHint: 'profiles.a_number_or_a_range_30_or_22_30_bece49a',
  markHint: 'profiles.decimal_or_hexadecimal_255_or_0xff_7a54858',
  fieldError: 'profiles.check_this_value_046ee79',
  invalidFields: 'profiles.correct_the_highlighted_fields_before_saving_b00d119',
  customFragmentReset: 'profiles.remove_custom_settings_327f68b',
  customFragmentResetHint: 'profiles.removes_the_entire_custom_configuration_includin_71ef1a1',
  customFragmentTfo: 'profiles.disable_tcp_fast_open_in_advanced_or_turn_custom_2690ed5',
  addPeer: 'profiles.add_peer_b9fbcac',
  peer: 'profiles.peer_6d6066a',
  noPeers: 'profiles.add_a_peer_to_connect_to_a_wireguard_server_c7f57b6',
  generate: 'profiles.generate_key_pair_169122a',
  replaceKey: 'profiles.replace_the_private_key_8e9a904',
  publicKey: 'profiles.your_public_key_cd9a29f',
  generated: 'profiles.keep_the_public_key_for_configuring_the_server_b99f3c2',
  rawHint: 'profiles.this_is_the_configuration_passed_to_the_core_it__4cc0afb',
  externalRawHint: 'profiles.launch_parameters_extra_core_conf_contains_the_o_3d71cde',
  externalChecked: 'profiles.launch_parameters_and_executable_checked_socks5__7d8c2e2',
  formatJson: 'profiles.format_json_5c8ab69',
  discardTitle: 'profiles.discard_unsaved_changes_2326ec7',
  discardHint: 'profiles.changes_in_this_editor_will_be_lost_704fc47',
  keepEditing: 'profiles.keep_editing_7c292c4',
  discard: 'profiles.discard_6febe61',
  optional: 'profiles.optional_99d8384',
  rawOnly: 'profiles.this_configuration_can_be_edited_in_the_json_tab_1292178',
} satisfies Record<string, Label>;

export type Variant = { config: Config; buffers: Record<string, string>; invalid: Record<string, boolean> };

export type Working = {
  text: string;
  buffers: Record<string, string>;
  invalid: Record<string, boolean>;
  variants: Record<string, Variant>;
};

export const working = (config: Config): Working => ({
  text: JSON.stringify(config, null, 2),
  buffers: {},
  invalid: {},
  variants: {},
});

export { secretPath } from '../shared/secretFields.ts';
