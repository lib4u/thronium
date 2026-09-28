use super::*;
use crate::transport::tun::supports_system_dns;
#[test]
fn system_dns_capabilities_preserve_resolved_and_gate_openresolv() {
    assert!(supports_system_dns("resolved", Some(1)));
    assert!(supports_system_dns("resolved", Some(2)));
    assert!(supports_system_dns("resolvconf", Some(2)));
    for mode in ["resolved", "resolvconf"] {
        for version in [None, Some(0), Some(3)] {
            assert!(!supports_system_dns(mode, version));
        }
    }
    assert!(!supports_system_dns("resolvconf", Some(1)));
    assert!(!supports_system_dns("foreign", Some(2)));
}
#[test]
fn frame_matches_upstream_wire_format() {
    assert_eq!(
        request_frame(7, "Stop", &[]).unwrap(),
        [7, 0, 0, 0, 4, 0, b'S', b't', b'o', b'p', 0, 0, 0, 0]
    );
}
#[test]
fn rejects_unrelated_or_oversized_responses() {
    assert!(response_header(1, [2, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    assert!(response_header(1, [1, 0, 0, 0, 0, 255, 255, 255, 255]).is_err());
    assert_eq!(
        response_header(1, [1, 0, 0, 0, 1, 8, 0, 0, 0]).unwrap(),
        (1, 8)
    );
}
