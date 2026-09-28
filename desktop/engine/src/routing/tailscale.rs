//! DNS of a Tailscale node, as Qt generates it (`generate.cpp`, `isTailscale`):
//! the node answers for its own names, the control plane is resolved outside the
//! tunnel, and the profile's policy decides whether the node also answers
//! everything else (Qt's `globalDNS`, sing-box `accept_default_resolvers`).
use crate::store::{Profile, ProfileKind};
use serde_json::{json, Value};

const TAG: &str = "dns-tailscale";
const DIRECT: &str = "dns-direct";
/// Names of the coordination service, which must resolve without the node.
const CONTROL: [&str; 3] = [
    "controlplane.tailscale.com",
    "login.tailscale.com",
    "log.tailscale.io",
];
const CONTROL_SUFFIXES: [&str; 3] = ["tailscale.com", "tailscale.net", "tailscale.io"];
/// Names the node itself answers for.
const NODE_SUFFIXES: [&str; 2] = ["ts.net", "tailscale.net"];

pub(crate) fn is_node(profile: &Profile) -> bool {
    profile.kind == ProfileKind::SingBoxOutbound && profile.config["type"] == "tailscale"
}
/// Adds the node's DNS to a generated configuration. A DNS section that already
/// describes a Tailscale server is the user's own and is left alone.
pub(crate) fn apply(dns: &mut Value, profile: &Profile) {
    if !is_node(profile) {
        return;
    }
    let servers = dns["servers"].as_array().cloned().unwrap_or_default();
    if servers.iter().any(|server| server["type"] == "tailscale") {
        return;
    }
    let global = profile
        .vpn_policy
        .is_some_and(|policy| policy.use_tunnel_dns);
    let mut servers = servers;
    servers.push(json!({
        "type": "tailscale",
        "tag": TAG,
        "endpoint": "proxy",
        "accept_default_resolvers": global,
    }));
    dns["servers"] = json!(servers);
    let mut rules = vec![json!({
        "domain_suffix": NODE_SUFFIXES,
        "action": "route",
        "server": TAG,
    })];
    // Without a local resolver in this profile the control plane follows the
    // section's own final server, as any other name does.
    if servers
        .iter()
        .any(|server| server["tag"] == DIRECT && server["type"] != "tailscale")
    {
        rules.insert(
            0,
            json!({
                "domain": CONTROL,
                "domain_suffix": CONTROL_SUFFIXES,
                "action": "route",
                "server": DIRECT,
            }),
        );
    }
    rules.extend(dns["rules"].as_array().cloned().unwrap_or_default());
    dns["rules"] = json!(rules);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ProfileKind;

    fn node(policy: Option<crate::vpn_policy::Policy>) -> Profile {
        Profile {
            vpn_policy: policy,
            id: "node".into(),
            name: "Tailnet".into(),
            group_id: crate::store::PERSONAL_GROUP.into(),
            kind: ProfileKind::SingBoxOutbound,
            config: json!({"type":"tailscale","auth_key":"tskey-fixture"}),
            favorite: false,
        }
    }
    fn global() -> Option<crate::vpn_policy::Policy> {
        Some(crate::vpn_policy::Policy {
            only_advertised_routes: false,
            use_tunnel_dns: true,
            block_outside_dns: false,
        })
    }

    #[test]
    fn a_node_answers_for_its_names_while_the_control_plane_stays_outside() {
        let mut dns = json!({"servers":[{"type":"local","tag":"dns-direct"}],"final":"dns-direct"});
        apply(&mut dns, &node(None));
        assert_eq!(
            dns["servers"][1],
            json!({"type":"tailscale","tag":TAG,"endpoint":"proxy","accept_default_resolvers":false})
        );
        assert_eq!(dns["rules"][0]["server"], json!(DIRECT));
        assert_eq!(dns["rules"][0]["domain"][0], json!(CONTROL[0]));
        assert_eq!(dns["rules"][1]["server"], json!(TAG));
        assert_eq!(dns["rules"][1]["domain_suffix"], json!(NODE_SUFFIXES));
        // The policy is Qt's globalDNS and nothing else changes.
        let mut global_dns = json!({"servers":[{"type":"local","tag":"dns-direct"}]});
        apply(&mut global_dns, &node(global()));
        assert_eq!(
            global_dns["servers"][1]["accept_default_resolvers"],
            json!(true)
        );
    }

    #[test]
    fn other_profiles_and_an_existing_tailscale_server_are_left_alone() {
        let mut other = node(global());
        other.config = json!({"type":"vless","server":"192.0.2.10"});
        let mut dns = json!({"servers":[{"type":"local","tag":"dns-direct"}]});
        let before = dns.clone();
        apply(&mut dns, &other);
        assert_eq!(dns, before);
        let mut owned =
            json!({"servers":[{"type":"tailscale","tag":"mine","endpoint":"proxy"}],"rules":[]});
        let before = owned.clone();
        apply(&mut owned, &node(global()));
        assert_eq!(owned, before);
        // Without a local resolver the control plane follows the section's final.
        let mut remote =
            json!({"servers":[{"type":"udp","tag":"dns-remote","server":"192.0.2.53"}]});
        apply(&mut remote, &node(None));
        assert_eq!(remote["rules"].as_array().unwrap().len(), 1);
        assert_eq!(remote["rules"][0]["server"], json!(TAG));
    }
}
