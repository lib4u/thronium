use super::*;
use serde_json::json;

#[test]
fn amnezia_versions_follow_the_fields_amnezia_gates_per_version() {
    let base = json!({"jc":4,"jmin":10,"jmax":50,"s1":20,"s2":30,"h1":"700001","h2":"700002","h3":"700003","h4":"700004"});
    assert_eq!(amnezia_version(&base), "AmneziaWG 1.0");
    assert_eq!(amnezia_version(&json!({})), "AmneziaWG 1.0");
    let mut v15 = base.clone();
    v15["i1"] = json!("<r 64>");
    assert_eq!(amnezia_version(&v15), "AmneziaWG 1.5");
    let mut v2 = v15.clone();
    v2["s3"] = json!(40);
    v2["s4"] = json!(50);
    assert_eq!(amnezia_version(&v2), "AmneziaWG 2.0");
    for (key, value) in [
        ("header_protection_key", json!("CqRG")),
        ("content_padding_addition", json!("16")),
        ("content_padding_addition", json!(16)),
        ("rekey_after_time", json!("120-180")),
        ("random_trailers", json!(true)),
        ("disable_cookies", json!(true)),
    ] {
        let mut v31 = v2.clone();
        v31[key] = value;
        assert_eq!(amnezia_version(&v31), "AmneziaWG 3.1", "{key}");
    }
    // Off switches, zero sizes and empty text do not raise the version.
    let mut quiet = v2.clone();
    quiet["random_trailers"] = json!(false);
    quiet["content_padding_addition"] = json!(0);
    quiet["header_protection_key"] = json!("");
    assert_eq!(amnezia_version(&quiet), "AmneziaWG 2.0");
    let mut plain = base.clone();
    plain["s3"] = json!(0);
    plain["i1"] = json!("");
    assert_eq!(amnezia_version(&plain), "AmneziaWG 1.0");
}

#[test]
fn descriptor_labels_amnezia_profiles_with_their_version() {
    let profile = Profile {
        vpn_policy: None,
        id: "p".into(),
        name: "Peer".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        favorite: false,
        config: json!({"type":"wireguard","private_key":"k","peers":[{"address":"203.0.113.7","port":51820}],
            "amnezia_wg":{"jc":4,"s3":40,"s4":50,"i1":"<r 64>","header_protection_key":"k","random_trailers":true}}),
    };
    let descriptor = describe(&profile);
    assert_eq!(descriptor.protocol, "AmneziaWG 3.1");
    assert_eq!(descriptor.address, "203.0.113.7");
    let plain = Profile {
        config: json!({"type":"wireguard","private_key":"k","peers":[{"address":"h"}]}),
        ..profile
    };
    assert_eq!(describe(&plain).protocol, "wireguard");
}

fn fixture(kind: ProfileKind, config: serde_json::Value) -> Profile {
    Profile {
        vpn_policy: None,
        id: "p".into(),
        name: "P".into(),
        group_id: "personal".into(),
        kind,
        favorite: false,
        config,
    }
}

#[test]
fn descriptor_reports_the_port_next_to_the_host_for_every_address_shape() {
    let cases = [
        (
            ProfileKind::SingBoxOutbound,
            json!({"type":"trojan","server":"h.example","server_port":8443,"password":"s"}),
            ("h.example", Some(8443)),
        ),
        (
            ProfileKind::XrayOutbound,
            json!({"protocol":"vless","settings":{"address":"x.example","port":443,"id":"u"}}),
            ("x.example", Some(443)),
        ),
        (
            ProfileKind::XrayOutbound,
            json!({"protocol":"vless","settings":{"vnext":[{"address":"v.example","port":2053,"users":[]}]}}),
            ("v.example", Some(2053)),
        ),
        (
            ProfileKind::SingBoxOutbound,
            json!({"type":"wireguard","peers":[{"address":"203.0.113.7","port":51820}]}),
            ("203.0.113.7", Some(51820)),
        ),
        (
            ProfileKind::SingBoxOutbound,
            json!({"type":"wireguard","peers":[{"endpoint":"[2001:db8::1]:51821"}]}),
            ("2001:db8::1", Some(51821)),
        ),
        (
            ProfileKind::SingBoxOutbound,
            json!({"type":"socks","server":"s.example","server_port":70000}),
            ("s.example", None),
        ),
        (
            ProfileKind::SingBoxOutbound,
            json!({"type":"tailscale"}),
            ("", None),
        ),
    ];
    for (kind, config, (host, port)) in cases {
        let profile = fixture(kind, config.clone());
        let descriptor = describe(&profile);
        assert_eq!(
            (descriptor.address, descriptor.port),
            (host, port),
            "{config}"
        );
    }
    let external = fixture(
        ProfileKind::ExternalCore,
        json!({"type":"extracore","socks_address":"127.0.0.1","socks_port":1080}),
    );
    assert_eq!(describe(&external).port, Some(1080));
    let chain = fixture(ProfileKind::Chain, json!({"type":"chain","hops":["a"]}));
    assert_eq!(
        (describe(&chain).address, describe(&chain).port),
        ("", None)
    );
}

#[test]
fn security_level_follows_qt_classes_and_reads_insecure_flags_of_both_cores() {
    assert_eq!(
        security_level(&json!({"type":"vless","tls":{"enabled":true,"reality":{"enabled":true}}})),
        SECURITY_SECURE
    );
    assert_eq!(
        security_level(&json!({"type":"trojan","tls":{"enabled":true}})),
        SECURITY_SECURE
    );
    assert_eq!(
        security_level(&json!({"type":"trojan","tls":{"enabled":true,"insecure":true}})),
        SECURITY_WEAK
    );
    assert_eq!(security_level(&json!({"type":"vmess"})), SECURITY_NONE);
    assert_eq!(
        security_level(&json!({"type":"vless","tls":{"enabled":false}})),
        SECURITY_NONE
    );
    // Protocols with their own encryption are not raw, merely unclassified.
    for config in [
        json!({"type":"wireguard","private_key":"k"}),
        json!({"type":"shadowsocks","method":"aes-256-gcm"}),
        json!({"type":"openvpn-client","server":"h"}),
    ] {
        assert_eq!(security_level(&config), SECURITY_UNKNOWN, "{config}");
    }
    assert_eq!(
        security_level(
            &json!({"protocol":"vless","streamSettings":{"security":"tls","tlsSettings":{"allowInsecure":true}}})
        ),
        SECURITY_WEAK
    );
    assert_eq!(
        security_level(&json!({"protocol":"vless","streamSettings":{"security":"reality"}})),
        SECURITY_SECURE
    );
    assert_eq!(
        security_level(
            &json!({"protocol":"vless","streamSettings":{"network":"raw","security":"none"}})
        ),
        SECURITY_NONE
    );
    // The label is unchanged by the level: an insecure TLS row still reads "TLS".
    let weak = fixture(
        ProfileKind::SingBoxOutbound,
        json!({"type":"trojan","server":"h","server_port":443,"password":"s","tls":{"enabled":true,"insecure":true}}),
    );
    let descriptor = describe(&weak);
    assert_eq!(descriptor.security, "TLS");
    assert_eq!(descriptor.security_level, SECURITY_WEAK);
}

#[test]
fn plain_tcp_is_no_transport_and_every_named_transport_is_shown() {
    for (config, label) in [
        (json!({"type":"wireguard"}), ""),
        (json!({"type":"direct"}), ""),
        (json!({"type":"vless","transport":{"type":"tcp"}}), ""),
        (
            json!({"protocol":"vless","streamSettings":{"network":"raw","security":"tls"}}),
            "TLS",
        ),
        (
            json!({"protocol":"vless","streamSettings":{"network":"splithttp"}}),
            "xhttp",
        ),
        (
            json!({"protocol":"vmess","streamSettings":{"network":"kcp"}}),
            "kcp",
        ),
        (
            json!({"type":"trojan","tls":{"enabled":true},"transport":{"type":"ws"}}),
            "TLS · ws",
        ),
    ] {
        assert_eq!(security(&config), label, "{config}");
    }
}

#[test]
fn groups_and_loopback_do_not_make_a_full_config_server_ambiguous() {
    let server = json!({"type":"vless","tag":"proxy","server":"192.0.2.10","server_port":443});
    let sing = json!({"outbounds":[
        {"type":"selector","tag":"select","outbounds":["proxy"]},
        {"type":"urltest","tag":"auto","outbounds":["proxy"]},
        server,
        {"type":"direct","tag":"direct"}
    ]});
    assert_eq!(single_outbound(&sing), Some(&server));
    let xray_server = json!({"protocol":"trojan","tag":"proxy"});
    let xray = json!({"outbounds":[xray_server,{"protocol":"loopback","tag":"back"},{"protocol":"freedom"}]});
    assert_eq!(single_outbound(&xray), Some(&xray_server));
    let two = json!({"outbounds":[server, {"type":"trojan","tag":"second"}]});
    assert_eq!(single_outbound(&two), None);
}
