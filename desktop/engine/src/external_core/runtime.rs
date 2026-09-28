use super::parse;
use crate::{
    proto,
    store::{Library, Profile, ProfileKind},
    Engine,
};
use serde_json::{json, Value};

/// Every profile the selected one reaches by being a chain of chains: what a
/// single core compiles for itself, without an auxiliary routing target.
fn chained<'a>(library: &'a Library, selected: &'a Profile) -> std::collections::HashSet<&'a str> {
    let mut seen = std::collections::HashSet::from([selected.id.as_str()]);
    let mut pending = vec![selected];
    while let Some(profile) = pending.pop() {
        if profile.kind != ProfileKind::Chain {
            continue;
        }
        for id in crate::references::members(profile).unwrap_or_default() {
            if let Some(member) = library.profiles.iter().find(|p| p.id == id) {
                if seen.insert(member.id.as_str()) {
                    pending.push(member);
                }
            }
        }
    }
    seen
}
/// Qt's `resolveExtraCoreProfile`: the external core of a connection is the
/// selected profile itself or the first physical hop of its chain, the only
/// place a chain may hold one.
pub(crate) fn carrier<'a>(profiles: &'a [Profile], selected: &'a Profile) -> Option<&'a Profile> {
    if selected.kind == ProfileKind::ExternalCore {
        return Some(selected);
    }
    if selected.kind != ProfileKind::Chain {
        return None;
    }
    crate::chains::flatten(selected, profiles)
        .ok()?
        .first()
        .copied()
        .filter(|hop| hop.kind == ProfileKind::ExternalCore)
}
pub(crate) fn context(library: &Library, selected: &Profile) -> Result<(), String> {
    let needed = crate::vless::relevant(library, selected)?;
    let Some(external) = carrier(&library.profiles, selected) else {
        // A configuration that carries an external core anywhere else has no
        // way to start it.
        if library.profiles.iter().any(|p| {
            p.id != selected.id && needed.contains(&p.id) && p.kind == ProfileKind::ExternalCore
        }) {
            return Err("external_auxiliary_unsupported".into());
        }
        return Ok(());
    };
    if !cfg!(any(target_os = "linux", target_os = "windows")) {
        return Err("external_platform_unsupported".into());
    }
    parse(&external.config)?;
    if library.routing.active()?.legacy_constraints.is_some()
        || crate::geodata::enabled(selected, library)
    {
        return Err("external_routing_unsupported".into());
    }
    if crate::group_chains::policy(library, selected).enabled() {
        return Err("external_chain_unsupported".into());
    }
    // Only the chain that dials the external core may carry other profiles: an
    // auxiliary routing target would need a second core to reach it.
    if needed
        .iter()
        .any(|id| !chained(library, selected).contains(id.as_str()))
    {
        return Err("external_auxiliary_unsupported".into());
    }
    Ok(())
}
/// Qt keeps the traffic of the external core itself off the tunnel and off the
/// resolver of the managed core: both are matched by the path of the program
/// the person runs. Without them a tunnel would carry the external core's own
/// connections back into itself.
pub(crate) fn own_traffic_rules(profile: &Profile) -> Result<(Value, Value), String> {
    let path = parse(&profile.config)?.extra_core_path;
    Ok((
        json!({"action":"route","process_path":[path.clone()],"outbound":"direct"}),
        json!({"action":"route","process_path":[path],"server":"dns-direct"}),
    ))
}
pub(crate) fn attach(request: &mut proto::LoadConfigReq, profile: &Profile) -> Result<(), String> {
    let draft = parse(&profile.config)?;
    request.need_extra_process = Some(true);
    request.extra_process_path = Some(draft.extra_core_path);
    request.extra_process_args = Some(draft.extra_core_args);
    request.extra_process_conf = Some(draft.extra_core_conf);
    request.extra_no_out = Some(draft.no_logs);
    request.extra_process_options = Some(proto::ExtraProcessOptions {
        version: Some(1),
        socks_address: Some(draft.socks_address),
        socks_port: Some(u32::from(draft.socks_port)),
        startup_timeout_ms: Some(10000),
    });
    Ok(())
}
pub(crate) fn is_request(request: &proto::LoadConfigReq) -> bool {
    request.need_extra_process == Some(true)
}
fn capability(status: &proto::QueryExtraProcessResp) -> Result<(), String> {
    if status.version != Some(1) || status.supported != Some(true) {
        return Err("external_core_capability_missing".into());
    }
    Ok(())
}
/// A registered external core code; the external status reports nothing else.
pub(crate) fn safe_error(reason: &str) -> Option<&'static str> {
    reason
        .starts_with("external_")
        .then(|| crate::ipc::registered(reason))
        .flatten()
}
fn failure(status: &proto::QueryExtraProcessResp) -> String {
    status
        .reason
        .as_deref()
        .and_then(safe_error)
        .unwrap_or("external_process_failed")
        .into()
}
fn instance(status: &proto::QueryExtraProcessResp) -> Result<String, String> {
    capability(status)?;
    if status.state.as_deref() != Some("ready") {
        return Err(failure(status));
    }
    status
        .instance
        .as_deref()
        .filter(|s| {
            s.len() == 32
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .map(str::to_owned)
        .ok_or_else(|| "external_process_failed".into())
}
pub(crate) fn configuration(request: &proto::LoadConfigReq) -> Result<Value, String> {
    let options = request
        .extra_process_options
        .as_ref()
        .ok_or("external_profile_invalid")?;
    Ok(
        json!({"type":"extracore", "socks_address":options.socks_address, "socks_port":options.socks_port,
        "extra_core_path":request.extra_process_path,"extra_core_args":request.extra_process_args,
        "extra_core_conf":request.extra_process_conf,"no_logs":request.extra_no_out}),
    )
}
pub(crate) fn port(request: &proto::LoadConfigReq) -> Option<u16> {
    is_request(request).then_some(())?;
    let options = request.extra_process_options.as_ref()?;
    (options.socks_address.as_deref() == Some("127.0.0.1")).then_some(())?;
    u16::try_from(options.socks_port?)
        .ok()
        .filter(|p| *p >= 1024)
}
// Evaluate the final policy/settings output, including custom listeners and a
// randomly allocated mixed port. Reject before Check/Stop, not after child launch.
pub(crate) fn validate_request(request: &proto::LoadConfigReq) -> Result<(), String> {
    let Some(port) = port(request) else {
        return Ok(());
    };
    let core: Value = serde_json::from_str(
        request
            .core_config
            .as_deref()
            .ok_or("invalid_configuration")?,
    )
    .map_err(|_| "invalid_configuration")?;
    for listener in core["inbounds"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(core["services"].as_array().into_iter().flatten())
    {
        if listener["listen_port"].as_u64() == Some(u64::from(port)) {
            return Err("external_port_conflict".into());
        }
    }
    // The core's own API servers listen too, as `host:port` addresses.
    for address in [
        &core["experimental"]["clash_api"]["external_controller"],
        &core["experimental"]["v2ray_api"]["listen"],
    ] {
        let listening = address
            .as_str()
            .and_then(|a| a.rsplit_once(':'))
            .and_then(|(_, p)| p.parse::<u16>().ok());
        if listening == Some(port) {
            return Err("external_port_conflict".into());
        }
    }
    Ok(())
}
// SO_REUSEADDR avoids mistaking TIME_WAIT for a live listener. We never listen,
// send traffic, inspect an arbitrary PID, or terminate a port's current owner.
// On Windows the same option lets a bind succeed over a live listener, and
// TIME_WAIT does not block the bind there anyway, so it is not set.
fn endpoint_released(port: u16) -> bool {
    tokio::net::TcpSocket::new_v4()
        .and_then(|socket| {
            #[cfg(unix)]
            socket.set_reuseaddr(true)?;
            socket.bind(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
        })
        .is_ok()
}
impl Engine {
    pub(crate) fn queue_external_cleanup(&mut self) {
        if let Some(port) = self
            .active_connection
            .as_ref()
            .and_then(|c| port(&c.request))
        {
            self.external_cleanup_ports.insert(port);
        }
    }
    pub(crate) async fn wait_external_cleanup(&mut self) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while !self.external_cleanup_ports.is_empty() {
            self.external_cleanup_ports
                .retain(|p| !endpoint_released(*p));
            if self.external_cleanup_ports.is_empty() {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("external_core_cleanup_failed".into());
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        Ok(())
    }

    pub(crate) async fn check_external_capability(&mut self) -> Result<(), String> {
        let status: proto::QueryExtraProcessResp = self
            .ensure_rpc()
            .await?
            .call("QueryExtraProcess", proto::EmptyReq {})
            .await
            .map_err(|_| "external_core_capability_missing")?;
        capability(&status)
    }
    pub(crate) async fn external_instance(&mut self) -> Result<String, String> {
        let rpc = self.rpc.as_mut().ok_or("external_process_failed")?;
        if !rpc.is_alive() {
            return Err("external_process_failed".into());
        }
        let status: proto::QueryExtraProcessResp = rpc
            .call("QueryExtraProcess", proto::EmptyReq {})
            .await
            .map_err(|_| "external_process_failed")?;
        instance(&status)
    }
    pub async fn observe_external(&mut self) {
        let Some(expected) = self
            .active_connection
            .as_ref()
            .and_then(|c| c.external_instance.clone())
        else {
            return;
        };
        let observed = self.external_instance().await;
        if observed.as_ref().is_ok_and(|id| *id == expected) {
            return;
        }
        let _ = self.disconnect().await;
        self.clear_connection();
        self.error = Some(
            observed
                .err()
                .unwrap_or_else(|| "external_process_failed".into()),
        );
        self.logs.event("error", "external_core_exited", None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn external_status_requires_exact_capability_ready_and_opaque_instance() {
        let ready = proto::QueryExtraProcessResp {
            version: Some(1),
            supported: Some(true),
            state: Some("ready".into()),
            instance: Some("0123456789abcdef0123456789abcdef".into()),
            ..Default::default()
        };
        assert_eq!(
            instance(&ready).unwrap(),
            "0123456789abcdef0123456789abcdef"
        );
        for value in [None, Some(0), Some(2)] {
            let mut bad = ready.clone();
            bad.version = value;
            assert_eq!(
                instance(&bad).err().as_deref(),
                Some("external_core_capability_missing")
            );
        }
        for value in [None, Some(false)] {
            let mut bad = ready.clone();
            bad.supported = value;
            assert_eq!(
                instance(&bad).err().as_deref(),
                Some("external_core_capability_missing")
            );
        }
        for id in [
            "",
            "private-secret/path",
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef0123456789abcdeg",
        ] {
            let mut bad = ready.clone();
            bad.instance = Some(id.into());
            assert_eq!(
                instance(&bad).err().as_deref(),
                Some("external_process_failed")
            );
        }
        for state in ["inactive", "starting", "stopping", "failed", "future"] {
            let mut bad = ready.clone();
            bad.state = Some(state.into());
            bad.reason = Some("/private/secret failed command".into());
            assert_eq!(
                instance(&bad).err().as_deref(),
                Some("external_process_failed")
            );
            bad.reason = Some("external_core_exited".into());
            assert_eq!(
                instance(&bad).err().as_deref(),
                Some("external_core_exited")
            );
        }
    }
    #[tokio::test]
    async fn external_observer_never_spawns_a_missing_core() {
        let dir = tempfile::tempdir().unwrap();
        let mut e = Engine::open(dir.path(), &dir.path().join("core-must-not-be-started")).unwrap();
        assert_eq!(
            e.external_instance().await.err().as_deref(),
            Some("external_process_failed")
        );
        assert!(e.rpc.is_none());
    }
}
