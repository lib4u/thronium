//! Supervisor-owned, generation-bound replacement. No opaque configuration on wire.
use crate::{proto, transport::Rpc};
use prost::Message;
use std::time::Duration;

const MAX_RESPONSE: usize = 16 * 1024;
const AMBIGUOUS: &str = "vpn_credentials_replace_ambiguous";

pub(super) enum Outcome {
    Rejected {
        generation: u64,
        code: &'static str,
    },
    Applied(u64),
    Restored(u64),
    Failed {
        generation: u64,
        cleanup_failed: bool,
    },
}

fn invalid<T>() -> Result<T, String> {
    Err(AMBIGUOUS.into())
}

fn varint(data: &mut &[u8]) -> Result<u64, String> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let Some((&byte, rest)) = data.split_first() else {
            return invalid();
        };
        *data = rest;
        if shift == 63 && byte > 1 {
            return invalid();
        }
        value |= u64::from(byte & 127) << shift;
        if byte & 128 == 0 {
            if shift > 0 && byte == 0 {
                return invalid();
            }
            return Ok(value);
        }
    }
    invalid()
}

fn decode(data: &[u8]) -> Result<proto::ManagedVpnReplaceCredentialsResponse, String> {
    if data.len() > MAX_RESPONSE {
        return invalid();
    }
    let mut remaining = data;
    let mut fields = 0u8;
    while !remaining.is_empty() {
        let key = varint(&mut remaining)?;
        let tag = key >> 3;
        if !(1..=5).contains(&tag) || fields & (1 << tag) != 0 {
            return invalid();
        }
        fields |= 1 << tag;
        if tag < 5 {
            if key & 7 != 0 {
                return invalid();
            }
            let value = varint(&mut remaining)?;
            if matches!(tag, 1 | 4) && value > u64::from(u32::MAX) {
                return invalid();
            }
        } else {
            if key & 7 != 2 {
                return invalid();
            }
            let size = usize::try_from(varint(&mut remaining)?).map_err(|_| AMBIGUOUS)?;
            if size > remaining.len() || size > 128 {
                return invalid();
            }
            if std::str::from_utf8(&remaining[..size]).is_err() {
                return invalid();
            }
            remaining = &remaining[size..];
        }
    }
    if fields != 0b11_1110 {
        return invalid();
    }
    proto::ManagedVpnReplaceCredentialsResponse::decode(data).map_err(|_| AMBIGUOUS.into())
}

fn outcome(
    reply: proto::ManagedVpnReplaceCredentialsResponse,
    expected: u64,
) -> Result<Outcome, String> {
    if expected == 0 || reply.version != Some(1) || reply.previous_generation != Some(expected) {
        return invalid();
    }
    let generation = reply.generation.ok_or(AMBIGUOUS)?;
    let code = reply.error_code.as_deref().ok_or(AMBIGUOUS)?;
    match reply.outcome {
        Some(1) => {
            let code = match code {
                "managed_vpn_credentials_invalid_request" => "vpn_credentials_invalid",
                "managed_vpn_credentials_unsupported_version" => {
                    "vpn_credentials_managed_unsupported"
                }
                "managed_vpn_credentials_stale" => "vpn_credentials_stale",
                "managed_vpn_credentials_unavailable"
                | "managed_vpn_credentials_generation_exhausted"
                | "managed_vpn_credentials_deadline_exceeded" => "vpn_credentials_unavailable",
                "managed_vpn_credentials_configuration_unsupported" => {
                    "vpn_credentials_configuration_unsupported"
                }
                "managed_vpn_credentials_check_failed" => "vpn_credentials_check_failed",
                _ => return invalid(),
            };
            Ok(Outcome::Rejected { generation, code })
        }
        Some(2) if expected.checked_add(1) == Some(generation) && code.is_empty() => {
            Ok(Outcome::Applied(generation))
        }
        Some(3)
            if expected.checked_add(2) == Some(generation)
                && code == "managed_vpn_credentials_restart_failed" =>
        {
            Ok(Outcome::Restored(generation))
        }
        Some(4)
            if expected.checked_add(1) == Some(generation)
                || expected.checked_add(2) == Some(generation) =>
        {
            match code {
                "managed_vpn_credentials_cleanup_failed" => Ok(Outcome::Failed {
                    generation,
                    cleanup_failed: true,
                }),
                "managed_vpn_credentials_restart_failed"
                | "managed_vpn_credentials_deadline_exceeded" => Ok(Outcome::Failed {
                    generation,
                    cleanup_failed: false,
                }),
                _ => invalid(),
            }
        }
        _ => invalid(),
    }
}

pub(super) async fn replace(
    rpc: &mut Rpc,
    generation: u64,
    username: String,
    password: String,
) -> Result<Outcome, String> {
    if !rpc.managed() || generation == 0 {
        return invalid();
    }
    let request = proto::ManagedVpnReplaceCredentialsRequest {
        version: Some(1),
        generation: Some(generation),
        endpoint_tag: Some("proxy".into()),
        username: Some(username),
        password: Some(password),
    };
    let reply = rpc
        .call_checked(
            "ManagedVPNReplaceCredentials",
            request,
            Duration::from_secs(135),
            MAX_RESPONSE,
            decode,
        )
        .await
        .map_err(|_| AMBIGUOUS)?;
    outcome(reply, generation)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response(g: u64, result: i32, code: &str) -> proto::ManagedVpnReplaceCredentialsResponse {
        proto::ManagedVpnReplaceCredentialsResponse {
            version: Some(1),
            previous_generation: Some(g),
            generation: Some(g + 1),
            outcome: Some(result),
            error_code: Some(code.into()),
        }
    }
    #[test]
    fn exact_typed_outcomes_and_large_generation_do_not_retarget() {
        for g in [1, (1u64 << 53) + 1, u64::MAX - 2] {
            let applied = response(g, 2, "");
            assert!(
                matches!(outcome(decode(&applied.encode_to_vec()).unwrap(), g), Ok(Outcome::Applied(n)) if n == g+1)
            );
            let mut restored = response(g, 3, "managed_vpn_credentials_restart_failed");
            restored.generation = Some(g + 2);
            assert!(matches!(outcome(restored, g), Ok(Outcome::Restored(n)) if n == g+2));
            let mut stale = response(g, 1, "managed_vpn_credentials_stale");
            stale.generation = Some(0);
            assert!(matches!(
                outcome(stale, g),
                Ok(Outcome::Rejected {
                    generation: 0,
                    code: "vpn_credentials_stale"
                })
            ));
            for result in [0, 5, i32::MAX] {
                assert!(outcome(response(g, result, ""), g).is_err());
            }
            assert!(outcome(applied.clone(), g + 1).is_err());
            let mut wrong = applied;
            wrong.generation = Some(g);
            assert!(outcome(wrong, g).is_err());
            assert!(outcome(response(g, 2, "private server error"), g).is_err());
        }
    }
    #[test]
    fn duplicate_unknown_missing_noncanonical_fields_cannot_acknowledge_success() {
        let good = response(1, 2, "").encode_to_vec();
        assert!(decode(&good).is_ok());
        for extra in [vec![8, 1], vec![48, 1], vec![42, 0]] {
            let mut bytes = good.clone();
            bytes.extend(extra);
            assert!(decode(&bytes).is_err());
        }
        let mut missing = response(1, 2, "");
        missing.error_code = None;
        assert!(decode(&missing.encode_to_vec()).is_err());
        let mut nonminimal = vec![0x88, 0, 1];
        nonminimal.extend_from_slice(&good[2..]);
        assert!(decode(&nonminimal).is_err());
        let mut badvalue = vec![8, 0x81, 0];
        badvalue.extend_from_slice(&good[2..]);
        assert!(decode(&badvalue).is_err());
        assert!(decode(&vec![0; MAX_RESPONSE + 1]).is_err());
    }
}
