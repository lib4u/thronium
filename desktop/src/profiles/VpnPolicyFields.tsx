import { Button, Checkbox, Field } from '../shared/ui/controls';
import { translate, type Language } from '../shared/i18n/index.ts';
import type { VpnPolicy } from '../api';

export default function VpnPolicyFields({
  value,
  language,
  disabled,
  node = false,
  change,
}: {
  value: VpnPolicy | null;
  language: Language;
  disabled: boolean;
  /** A Tailscale node: only Qt's global DNS switch applies. */
  node?: boolean;
  change(value: VpnPolicy | null): void;
}) {
  if (!value)
    return (
      <div className="feature-section">
        <p className="field-hint">
          {translate(
            language,
            node
              ? 'profiles.tailscale_dns_hint'
              : 'profiles.the_current_routing_and_dns_rules_apply_this_vpn_fb7a195',
          )}
        </p>
        <Button
          id="vpn-policy-enable"
          type="button"
          className="button secondary"
          disabled={disabled}
          onClick={() =>
            change({
              onlyAdvertisedRoutes: !node,
              useTunnelDns: true,
              blockOutsideDns: false,
            })
          }
        >
          {translate(
            language,
            node ? 'profiles.tailscale_global_dns' : 'profiles.configure_vpn_policy_461bda5',
          )}
        </Button>
      </div>
    );
  const fields: { key: keyof VpnPolicy; title: string; hint: string }[] = node
    ? [
        {
          key: 'useTunnelDns',
          title: translate(language, 'profiles.tailscale_global_dns'),
          hint: translate(language, 'profiles.tailscale_global_dns_hint'),
        },
      ]
    : [
        {
          key: 'onlyAdvertisedRoutes',
          title: translate(language, 'profiles.use_only_routes_advertised_by_the_vpn_5bd0286'),
          hint: translate(language, 'profiles.when_this_vpn_is_the_default_route_only_its_adve_0907b61'),
        },
        {
          key: 'useTunnelDns',
          title: translate(language, 'profiles.use_dns_servers_advertised_by_the_vpn_c83826d'),
          hint: translate(language, 'profiles.domains_advertised_by_the_vpn_use_its_dns_restri_b887dc3'),
        },
        {
          key: 'blockOutsideDns',
          title: translate(language, 'profiles.prevent_direct_dns_fallback_when_routes_are_rest_b028632'),
          hint: translate(language, 'profiles.a_query_that_the_vpn_cannot_handle_will_fail_exp_b61ca40'),
        },
      ];
  return (
    <div className="feature-section" id="vpn-policy-fields">
      {fields.map((field) => (
        <Field
          key={field.key}
          className="feature-field"
          label={
            <>
              <Checkbox
                id={'vpn-policy-' + field.key}
                type="checkbox"
                checked={value[field.key]}
                disabled={disabled}
                onChange={(event) => change({ ...value, [field.key]: event.target.checked })}
              />{' '}
              {field.title}
            </>
          }
        >
          <small className="field-hint">{field.hint}</small>
        </Field>
      ))}
      <p className="field-hint">
        {translate(language, 'profiles.changes_take_effect_after_saving_and_reconnectin_09d08d2')}
      </p>
      <Button
        id="vpn-policy-clear"
        type="button"
        className="text-button"
        disabled={disabled}
        onClick={() => change(null)}
      >
        {translate(language, 'profiles.remove_separate_policy_6c3563e')}
      </Button>
    </div>
  );
}
