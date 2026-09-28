//! Only the supervisor's typed, generation-bound method may carry managed auth.
use crate::{proto, transport::Rpc};
use std::time::Duration;

fn response(
    reply: proto::ManagedVpnResponse,
    generation: u64,
) -> Result<proto::managed_vpn_response::Result, String> {
    if reply.version != Some(1) {
        return Err("vpn_auth_managed_unsupported".into());
    }
    // Refusals report the supervisor's CURRENT generation, which can differ.
    // Read the safe error before validating a successful response's binding.
    match reply.error_code.as_deref().unwrap_or("") {
        "" => {}
        "managed_vpn_stale_generation" => return Err("vpn_auth_stale".into()),
        "managed_vpn_unsupported_version" => return Err("vpn_auth_managed_unsupported".into()),
        _ => return Err("vpn_status_unavailable".into()),
    }
    if generation == 0 || reply.generation != Some(generation) {
        return Err("vpn_auth_stale".into());
    }
    reply.result.ok_or_else(|| "vpn_status_unavailable".into())
}

async fn exchange(
    rpc: &mut Rpc,
    generation: u64,
    operation: proto::managed_vpn_request::Operation,
    timeout: Duration,
) -> Result<proto::managed_vpn_response::Result, String> {
    if !rpc.managed() || generation == 0 {
        return Err("vpn_auth_stale".into());
    }
    let reply = rpc
        .call_with_timeout::<_, proto::ManagedVpnResponse>(
            "ManagedVPN",
            proto::ManagedVpnRequest {
                version: Some(1),
                generation: Some(generation),
                operation: Some(operation),
            },
            timeout,
        )
        .await
        .map_err(|_| "vpn_status_unavailable".to_string())?;
    response(reply, generation)
}

pub(super) async fn query(
    rpc: &mut Rpc,
    generation: u64,
    request: proto::VpnStatusRequest,
) -> Result<proto::VpnStatusResponse, String> {
    match exchange(
        rpc,
        generation,
        proto::managed_vpn_request::Operation::Query(request),
        Duration::from_secs(5),
    )
    .await?
    {
        proto::managed_vpn_response::Result::Status(status) => Ok(status),
        _ => Err("vpn_status_unavailable".into()),
    }
}

pub(super) async fn action(
    rpc: &mut Rpc,
    generation: u64,
    cancel: bool,
    request: proto::SubmitVpnChallengeRequest,
) -> Result<proto::ErrorResp, String> {
    let operation = if cancel {
        proto::managed_vpn_request::Operation::Cancel(request)
    } else {
        proto::managed_vpn_request::Operation::Submit(request)
    };
    match exchange(rpc, generation, operation, Duration::from_secs(7)).await? {
        proto::managed_vpn_response::Result::Action(result) => Ok(result),
        _ => Err("vpn_status_unavailable".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn envelope_versions_errors_result_and_large_generations_are_strict() {
        for generation in [1, (1u64 << 53) + 1, u64::MAX] {
            let make = || proto::ManagedVpnResponse {
                version: Some(1),
                generation: Some(generation),
                error_code: None,
                result: Some(proto::managed_vpn_response::Result::Action(
                    proto::ErrorResp::default(),
                )),
            };
            assert!(response(make(), generation).is_ok());
            let mut r = make();
            r.generation = Some(0);
            assert_eq!(
                response(r, generation).err().as_deref(),
                Some("vpn_auth_stale")
            );
            let mut r = make();
            r.generation = Some(0);
            r.error_code = Some("managed_vpn_unavailable".into());
            assert_eq!(
                response(r, generation).err().as_deref(),
                Some("vpn_status_unavailable")
            );
            let mut r = make();
            r.version = Some(2);
            assert_eq!(
                response(r, generation).err().as_deref(),
                Some("vpn_auth_managed_unsupported")
            );
            let mut r = make();
            r.result = None;
            assert_eq!(
                response(r, generation).err().as_deref(),
                Some("vpn_status_unavailable")
            );
            let mut r = make();
            r.error_code = Some("server-controlled-private-error".into());
            assert_eq!(
                response(r, generation).err().as_deref(),
                Some("vpn_status_unavailable")
            );
        }
    }
}
