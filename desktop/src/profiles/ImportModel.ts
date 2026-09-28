import { label, type Label } from './schema.ts';
import type { Language } from '../shared/i18n/index.ts';
export const importWords = {
  qr_not_found: 'profiles.no_qr_code_found_choose_a_clearer_image_112ae0b',
  qr_image_invalid: 'profiles.could_not_read_this_image_0887f3e',
  qr_image_too_large: 'profiles.qr_image_limits',
  qr_clipboard_empty: 'profiles.copy_an_image_containing_a_qr_code_first_fc2e6ac',
  qr_capture_failed: 'profiles.could_not_capture_the_screen_you_can_choose_a_sa_4a1dd7e',
  qr_capture_cancelled: 'profiles.screen_capture_cancelled_be83dd5',
  invalid_yaml: 'profiles.invalid_clash_yaml_configuration_c2c6220',
  invalid_vpn_file: 'profiles.invalid_vpn_client_configuration_3bdd599',
  unsupported_vpn_file: 'profiles.this_vpn_configuration_uses_an_unsupported_mode_042d2ce',
  unhandledFile: 'profiles.parameters_not_applied_e096cd9',
  unhandledRelativeFile: 'profiles.relative_file_path_check_where_the_f5a83da',
  unhandledExternalFile: 'profiles.credentials_are_in_a_separate_file_b5b28f1',

  vpn_policy_invalid: 'profiles.invalid_vpn_routing_and_dns_policy_c4c6fc7',
  vpn_policy_profile_unsupported: 'profiles.this_protocol_does_not_support_the_vpn_routing_a_3bd31c0',
  clipboard: 'profiles.paste_from_clipboard_20a4bd9',
  invalid_profile_bundle: 'profiles.invalid_thronium_profile_collection_5df6c82',
  unsupported_bundle_version: 'profiles.this_export_requires_a_newer_thronium_version_034b096',
  title: 'profiles.import_connections_2fd23f0',
  hint: 'profiles.paste_a_subscription_url_connection_links_json_o_9619fcf',
  addSubscription: 'profiles.add_subscription_89729e4',
  subscriptionHint: 'profiles.this_url_will_open_subscription_settings_and_imp_0206e59',
  subscription_link: 'profiles.this_is_a_subscription_url_paste_it_separately_t_d18f4a2',
  source: 'profiles.links_or_configuration_6b957dc',
  file: 'profiles.choose_file_1af7dfb',
  group: 'profiles.save_to_group_61b8606',
  review: 'profiles.review_182d2a2',
  back: 'profiles.edit_source_b2b9cf5',
  cancel: 'profiles.cancel_bf4c449',
  close: 'profiles.close_c9a286c',
  import: 'profiles.import_selected_0635d08',
  importing: 'profiles.importing_4901cbd',
  found: 'profiles.recognized_9f30d9b',
  selected: 'profiles.selected_f19a934',
  errors: 'profiles.errors_9546b09',
  name: 'profiles.name_5163a2e',
  line: 'profiles.entry_b7345cb',
  check: 'profiles.validate_configuration_6bfeffd',
  checking: 'profiles.validating_4629974',
  valid: 'profiles.core_accepted_this_configuration_34ebdce',
  notTested: 'profiles.import_does_not_connect_to_the_server_da24789',
  json: 'profiles.show_configuration_87bb60f',
  hide: 'profiles.hide_configuration_45ed799',
  unhandledQuery: 'profiles.parameters_not_transferred_fa75f4e',
  unhandledWg: 'profiles.file_directives_not_applied_a8955ed',
  unhandledWgSetting: 'profiles.wg_interface_setting_not_applied',
  unhandledWgAction: 'profiles.wg_host_command_not_executed',
  unhandledLink: 'profiles.link_parameter_not_applied',
  defaultAllowed: 'profiles.allowedips_is_missing_both_default_routes_will_b_897b9d7',
  acknowledge: 'profiles.i_reviewed_the_parameters_that_will_not_be_appli_0aa188c',
  fileError: 'profiles.could_not_read_this_file_dd265de',
  empty: 'profiles.no_connections_found_ae0bc54',
  invalid_content: 'profiles.invalid_connection_data_86bc697',
  unsupported_link: 'profiles.this_link_format_is_not_supported_yet_14724d9',
  unsupported_content: 'profiles.use_connection_links_json_or_a_wireguard_configu_985ee63',
  invalid_link: 'profiles.check_the_server_address_and_port_in_the_link_4126c7b',
  invalid_encoding: 'profiles.invalid_percent_encoding_58a5774',
  invalid_base64: 'profiles.invalid_base64_data_2ca0d25',
  invalid_json: 'profiles.invalid_json_b59bb4a',
  unsupported_json: 'profiles.could_not_identify_the_configuration_format_6448a6a',
  invalid_number: 'profiles.a_numeric_parameter_is_invalid_c0e3e73',
  invalid_boolean: 'profiles.use_true_or_false_for_a_switch_02f69df',
  invalid_range: 'profiles.invalid_numeric_range_6411c5d',
  invalid_headers: 'profiles.invalid_http_headers_f649f31',
  unsupported_transport: 'profiles.this_transport_is_not_supported_by_the_selected__5534e5e',
  unsupported_version: 'profiles.this_protocol_version_is_not_supported_63a7add',
  missing_key: 'profiles.a_required_wireguard_key_is_missing_08ca3eb',
  missing_address: 'profiles.tunnel_addresses_are_missing_3a11ce4',
  missing_credentials: 'profiles.connection_credentials_are_missing_f167bc3',
  missing_server: 'profiles.the_server_or_its_credentials_are_missing_0c37770',
  missing_port: 'profiles.server_ports_are_missing_a10db32',
  mixed_mieru_transports: 'profiles.a_mieru_profile_must_use_one_transport_0f5a33c',
  multiple_interfaces: 'profiles.use_one_wireguard_interface_per_file_5726a6c',
  unsupported_section: 'profiles.unknown_wireguard_section_9224b97',
  invalid_wireguard: 'profiles.invalid_wireguard_configuration_d893ca4',
  invalid_endpoint: 'profiles.check_the_peer_address_and_port_a92daab',
  import_too_large: 'profiles.import_size_limit',
  too_many_profiles: 'profiles.import_profile_limit',
  selectAll: 'profiles.select_all_859baa3',
  placeholder: 'profiles.paste_a_subscription_url_connection_link_or_conf_7f27a9f',
} satisfies Record<string, Label>;

export const messageKeys = importWords;

export function importMessage(code: string, language: Language) {
  return label(
    messageKeys[
      Object.prototype.hasOwnProperty.call(messageKeys, code)
        ? (code as keyof typeof messageKeys)
        : 'invalid_content'
    ],
    language,
  );
}

/** Why a file the system asked to open could not be read for import. */
export function importProblem(code: string, language: Language) {
  return importMessage(code === 'unreadable' ? 'fileError' : code, language);
}

export function importWarning(value: string, language: Language) {
  return value === 'wg-default-allowed'
    ? importMessage('defaultAllowed', language)
    : importMessage(
        value.startsWith('query:')
          ? 'unhandledQuery'
          : value.startsWith('file-relative:')
            ? 'unhandledRelativeFile'
            : value.startsWith('file-external:')
              ? 'unhandledExternalFile'
              : value.startsWith('file:')
                ? 'unhandledFile'
                : value.startsWith('wg-setting:')
                  ? 'unhandledWgSetting'
                  : value.startsWith('wg-action:')
                    ? 'unhandledWgAction'
                    : value.startsWith('link:')
                      ? 'unhandledLink'
                      : 'unhandledWg',
        language,
      ) +
        ': ' +
        value.slice(value.indexOf(':') + 1);
}

export type ImportMethod = 'link' | 'file' | 'qr';
