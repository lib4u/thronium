use super::Method;
use crate::store::{Library, Profile, ProfileKind};
use serde_json::Value;

pub(super) struct Target {
    pub host: String,
    pub port: u16,
    pub first_hop: bool,
}

pub(super) fn target(p: &Profile, library: &Library, method: Method) -> Result<Target, String> {
    if p.kind == ProfileKind::ExternalCore {
        return Err("probe_target_ambiguous".into());
    }
    let policy = crate::group_chains::policy(library, p);
    let (p, first_hop) = if let Some(id) = policy.front {
        (
            library
                .profiles
                .iter()
                .find(|p| p.id == id)
                .ok_or("probe_target_missing")?,
            true,
        )
    } else {
        (p, false)
    };
    let (p, first_hop) = if p.kind == ProfileKind::Chain {
        (
            *crate::chains::flatten(p, &library.profiles)
                .map_err(|_| "probe_target_ambiguous")?
                .first()
                .ok_or("probe_target_missing")?,
            true,
        )
    } else {
        (p, first_hop)
    };
    if p.kind == ProfileKind::AutoSelector {
        return Err("probe_target_ambiguous".into());
    }
    let config = if matches!(p.kind, ProfileKind::SingBoxConfig | ProfileKind::XrayConfig) {
        // Never start a full config's inbounds, TUN or services to inspect it.
        crate::profile_descriptor::single_outbound(&p.config).ok_or("probe_target_ambiguous")?
    } else {
        &p.config
    };
    let protocol = config["type"]
        .as_str()
        .or(config["protocol"].as_str())
        .unwrap_or("");
    // UDP and QUIC protocols have no TCP listener to reach; NaiveProxy and
    // TrustTunnel use QUIC only when their `quic` switch is on.
    if method == Method::Tcp
        && (matches!(
            protocol,
            "wireguard" | "hysteria" | "hysteria2" | "tuic" | "juicity" | "tailscale" | "masque"
        ) || (matches!(protocol, "naive" | "trusttunnel") && config["quic"] == true)
            || matches!(
                config["transport"]["type"]
                    .as_str()
                    .or(config["streamSettings"]["network"].as_str()),
                Some("quic" | "kcp" | "mkcp")
            )
            || (protocol == crate::vpn_endpoint::OPENVPN && config["network"] != "tcp"))
    {
        return Err("probe_tcp_inapplicable".into());
    }
    let (host, port) = if let Some(host) = config["server"].as_str() {
        (host.to_owned(), number(&config["server_port"]))
    } else if protocol == "wireguard" {
        let peers = config["peers"]
            .as_array()
            .or(config["settings"]["peers"].as_array())
            .ok_or("probe_target_missing")?;
        if peers.len() != 1 {
            return Err("probe_target_ambiguous".into());
        }
        let peer = &peers[0];
        if let Some(host) = peer["address"].as_str() {
            (host.into(), number(&peer["port"]))
        } else {
            split_endpoint(peer["endpoint"].as_str().ok_or("probe_target_missing")?)?
        }
    } else if let Some(host) = config["settings"]["address"].as_str() {
        (host.into(), number(&config["settings"]["port"]))
    } else {
        let list = config["settings"]["vnext"]
            .as_array()
            .or(config["settings"]["servers"].as_array())
            .ok_or("probe_target_missing")?;
        if list.len() != 1 {
            return Err("probe_target_ambiguous".into());
        }
        (
            list[0]["address"]
                .as_str()
                .ok_or("probe_target_missing")?
                .into(),
            number(&list[0]["port"]),
        )
    };
    let host = host.trim_matches(['[', ']']).to_owned();
    if host.is_empty()
        || host.len() > 253
        || host
            .chars()
            .any(|c| c.is_whitespace() || "\0/\\?#@".contains(c))
    {
        return Err("probe_target_missing".into());
    }
    if method == Method::Tcp && port.is_none() {
        return Err("probe_target_missing".into());
    }
    Ok(Target {
        host,
        port: port.unwrap_or(0),
        first_hop,
    })
}

fn number(v: &Value) -> Option<u16> {
    v.as_u64()
        .or_else(|| v.as_str()?.parse().ok())
        .and_then(|n| u16::try_from(n).ok())
        .filter(|n| *n != 0)
}
fn split_endpoint(value: &str) -> Result<(String, Option<u16>), String> {
    let (host, port) = value.rsplit_once(':').ok_or("probe_target_missing")?;
    Ok((
        host.trim_matches(['[', ']']).into(),
        port.parse::<u16>().ok().filter(|p| *p != 0),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn profile(kind: ProfileKind, config: Value) -> Profile {
        Profile {
            vpn_policy: None,
            id: "p".into(),
            name: "Not an address".into(),
            group_id: "personal".into(),
            kind,
            config,
            favorite: false,
        }
    }
    fn library() -> Library {
        Library::default()
    }

    #[test]
    fn extracts_real_server_instead_of_labels_tls_names_or_proxy_bridges() {
        for (kind, config, host, port) in [
            (
                ProfileKind::SingBoxOutbound,
                json!({"type":"vless","server":"vpn.example","server_port":443,"tls":{"server_name":"sni.example"}}),
                "vpn.example",
                443,
            ),
            (
                ProfileKind::XrayOutbound,
                json!({"protocol":"vless","settings":{"vnext":[{"address":"2001:db8::1","port":8443}]}}),
                "2001:db8::1",
                8443,
            ),
            (
                ProfileKind::XrayOutbound,
                json!({"protocol":"trojan","settings":{"address":"vpn.example","port":443}}),
                "vpn.example",
                443,
            ),
            (
                ProfileKind::XrayOutbound,
                json!({"protocol":"shadowsocks","settings":{"servers":[{"address":"ss.example","port":443}]}}),
                "ss.example",
                443,
            ),
        ] {
            let t = target(&profile(kind, config), &library(), Method::Tcp).unwrap();
            assert_eq!((t.host.as_str(), t.port), (host, port));
        }
    }
    #[test]
    fn amnezia_and_udp_profiles_support_icmp_but_not_tcp() {
        for config in [
            json!({"type":"wireguard","amnezia_wg":{},"peers":[{"address":"203.0.113.1","port":51820}]}),
            json!({"type":"hysteria2","server":"203.0.113.1","server_port":443}),
            json!({"type":"tuic","server":"203.0.113.1","server_port":443}),
            json!({"type":"juicity","server":"203.0.113.1","server_port":443}),
            json!({"type":"naive","server":"203.0.113.1","server_port":443,"quic":true}),
            json!({"type":"trusttunnel","server":"203.0.113.1","server_port":443,"quic":true}),
        ] {
            let p = profile(ProfileKind::SingBoxOutbound, config);
            assert_eq!(
                target(&p, &library(), Method::Icmp).unwrap().host,
                "203.0.113.1"
            );
            assert_eq!(
                target(&p, &library(), Method::Tcp).err().unwrap(),
                "probe_tcp_inapplicable"
            );
        }
        for config in [
            json!({"type":"naive","server":"203.0.113.1","server_port":443}),
            json!({"type":"trusttunnel","server":"203.0.113.1","server_port":443,"quic":false}),
        ] {
            let p = profile(ProfileKind::SingBoxOutbound, config);
            assert!(
                target(&p, &library(), Method::Tcp).is_ok(),
                "without QUIC they listen on TCP"
            );
        }
    }
    #[test]
    fn full_json_and_peers_require_one_unambiguous_server() {
        let p = profile(
            ProfileKind::SingBoxConfig,
            json!({"inbounds":[{"type":"tun"}],"outbounds":[{"type":"direct"},{"type":"socks","server":"example.test","server_port":1080}]}),
        );
        assert_eq!(
            target(&p, &library(), Method::Tcp).unwrap().host,
            "example.test"
        );
        for p in [
            profile(
                ProfileKind::SingBoxConfig,
                json!({"outbounds":[{"type":"selector","outbounds":["a","b"]},{"type":"socks","server":"a"},{"type":"socks","server":"b"}]}),
            ),
            profile(
                ProfileKind::SingBoxOutbound,
                json!({"type":"wireguard","peers":[{"address":"a"},{"address":"b"}]}),
            ),
            profile(ProfileKind::AutoSelector, json!({"members":["a","b"]})),
        ] {
            assert_eq!(
                target(&p, &library(), Method::Icmp).err().unwrap(),
                "probe_target_ambiguous"
            );
        }
    }
    #[test]
    fn chain_and_group_front_measure_the_first_hop() {
        let mut l = library();
        let mut a = profile(
            ProfileKind::SingBoxOutbound,
            json!({"type":"socks","server":"front.test","server_port":1080}),
        );
        a.id = "front".into();
        let mut b = a.clone();
        b.id = "exit".into();
        b.config["server"] = json!("exit.test");
        l.profiles = vec![a, b.clone()];
        let p = profile(ProfileKind::Chain, json!({"hops":["front","exit"]}));
        let t = target(&p, &l, Method::Tcp).unwrap();
        assert_eq!(t.host, "front.test");
        assert!(t.first_hop);
        l.groups[0].proxy_chain.front = Some("front".into());
        let t = target(&b, &l, Method::Icmp).unwrap();
        assert_eq!(t.host, "front.test");
        assert!(t.first_hop);
    }
}
