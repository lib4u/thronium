//! TUN configuration. On Linux the managed supervisor owns elevation and
//! recovery, on Windows ThroniumService does.
use crate::{
    proto::LoadConfigReq,
    store::{Preferences, Profile, ProfileKind},
    system_proxy::ConnectionMode,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::IpAddr;

pub const INTERFACE: &str = "thronium-tun";
pub const RULE_PRIORITY: u64 = 18900;
const IPV4_ADDRESS: &str = "172.19.0.1/30";
const IPV6_ADDRESS: &str = "fdfe:dcba:9876::1/126";

// Linux abstract sockets are scoped to the network namespace. Keep a lease
// across Start/Stop so two Thronium instances cannot both pass an empty preflight.
pub(crate) struct Lease {
    #[cfg(target_os = "linux")]
    _listener: std::os::unix::net::UnixListener,
}
impl Lease {
    pub(crate) fn acquire() -> Result<Self, String> {
        #[cfg(target_os = "linux")]
        {
            use std::os::{
                linux::net::SocketAddrExt,
                unix::net::{SocketAddr, UnixListener},
            };
            let address = SocketAddr::from_abstract_name(b"thronium-tun-18900")
                .map_err(|_| "tun_network_check_failed")?;
            let listener = UnixListener::bind_addr(&address).map_err(|_| "tun_conflict")?;
            Ok(Self {
                _listener: listener,
            })
        }
        #[cfg(not(target_os = "linux"))]
        Err("tun_unavailable".into())
    }
}

#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Stack {
    System,
    #[default]
    Gvisor,
    Mixed,
}

/// Who points the system at the TUN's DNS: on Linux the chosen resolver
/// manager, on Windows the default interface's server list. A value of the
/// other system is kept but has no effect, so a library moves whole.
#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SystemDns {
    #[default]
    Disabled,
    Resolved,
    Resolvconf,
    Interface,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Settings {
    pub request_permission: bool,
    pub auto_reconnect: bool,
    pub mtu: u16,
    pub stack: Stack,
    pub ipv6: bool,
    pub strict_route: bool,
    pub dns_hijack: bool,
    pub system_dns: SystemDns,
    pub exclude_addresses: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            request_permission: true,
            auto_reconnect: true,
            mtu: 1500,
            // Windows starts where Qt-Throne does there: the system stack, and
            // WFP keeps traffic and DNS from leaving outside the TUN. A library
            // keeps whatever it stored when it moves between systems.
            stack: if cfg!(windows) {
                Stack::System
            } else {
                Stack::Gvisor
            },
            ipv6: false,
            strict_route: cfg!(windows),
            dns_hijack: true,
            system_dns: SystemDns::Disabled,
            exclude_addresses: vec![
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "169.254.0.0/16",
                "224.0.0.0/4",
                "fc00::/7",
                "fe80::/10",
                "ff00::/8",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        }
    }
}

pub const MTU: std::ops::RangeInclusive<u16> = 1280..=9000;
pub const MAX_EXCLUDE_ADDRESSES: usize = 64;

impl Settings {
    pub fn validate(&self) -> Result<(), String> {
        if self.system_dns != SystemDns::Disabled && !self.dns_hijack {
            return Err("tun_system_dns_requires_hijack".into());
        }
        if !MTU.contains(&self.mtu)
            || self.exclude_addresses.len() > MAX_EXCLUDE_ADDRESSES
            || self.exclude_addresses.iter().any(|s| !valid_cidr(s))
        {
            return Err("invalid_tun_settings".into());
        }
        Ok(())
    }
}

pub(crate) fn valid_cidr(s: &str) -> bool {
    let Some((ip, prefix)) = s.split_once('/') else {
        return false;
    };
    let (Ok(ip), Ok(prefix)) = (ip.parse::<IpAddr>(), prefix.parse::<u8>()) else {
        return false;
    };
    match ip {
        IpAddr::V4(ip) => {
            prefix <= 32 && u32::from(ip) & (u32::MAX.checked_shr(prefix as u32).unwrap_or(0)) == 0
        }
        IpAddr::V6(ip) => {
            prefix <= 128
                && u128::from(ip) & (u128::MAX.checked_shr(prefix as u32).unwrap_or(0)) == 0
        }
    }
}

/// Whether root, which pkexec runs the core as, can reach the core file at
/// all. A FUSE mount — an AppImage run in place — is private to the user who
/// mounted it, and pkexec then fails as if authorization had.
#[cfg(target_os = "linux")]
pub(crate) fn root_can_reach(core: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    const FUSE_SUPER_MAGIC: i64 = 0x6573_5546;
    let Ok(path) = std::ffi::CString::new(core.as_os_str().as_bytes()) else {
        return false;
    };
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    // A path statfs cannot read is left for pkexec to report.
    if unsafe { libc::statfs(path.as_ptr(), &mut stat) } != 0 {
        return true;
    }
    stat.f_type as i64 != FUSE_SUPER_MAGIC
}

/// A copy of `core` that root can run, in `<data>/tun-core/<hash>/`: the data
/// directory is this person's own, and the copy is checked against the core
/// it came from. Older copies are removed.
#[cfg(target_os = "linux")]
pub(crate) fn reachable_copy(
    core: &std::path::Path,
    data: &std::path::Path,
) -> Result<std::path::PathBuf, String> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    let failed = |_| "tun_helper_failed".to_string();
    let bytes = std::fs::read(core).map_err(failed)?;
    let hash = format!("{:x}", Sha256::digest(&bytes));
    let root = data.join("tun-core");
    let folder = root.join(&hash[..16]);
    let copy = folder.join("ThroniumCore");
    let same = |path: &std::path::Path| {
        std::fs::read(path).is_ok_and(|b| format!("{:x}", Sha256::digest(&b)) == hash)
    };
    if !same(&copy) {
        std::fs::create_dir_all(&folder).map_err(failed)?;
        for dir in [&root, &folder] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(failed)?;
        }
        let partial = folder.join("ThroniumCore.partial");
        std::fs::write(&partial, &bytes).map_err(failed)?;
        std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o700))
            .map_err(failed)?;
        std::fs::File::open(&partial)
            .and_then(|f| f.sync_all())
            .map_err(failed)?;
        std::fs::rename(&partial, &copy).map_err(failed)?;
        if !same(&copy) {
            return Err("tun_helper_failed".into());
        }
    }
    if let Ok(entries) = std::fs::read_dir(&root) {
        for entry in entries.flatten() {
            if entry.path() != folder {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    }
    Ok(copy)
}

/// Why TUN cannot be used here: on Windows the service is missing.
pub(crate) fn unavailable() -> String {
    if cfg!(windows) {
        "tun_service_missing"
    } else {
        "tun_unavailable"
    }
    .into()
}

/// On Windows TUN exists only where the installer registered the service.
pub fn supported() -> bool {
    #[cfg(windows)]
    return windows::installed();
    #[cfg(not(windows))]
    cfg!(target_os = "linux")
}

/// The pinned core forwards TCP flows straight into endpoints (WireGuard,
/// AmneziaWG, OpenVPN, Tailscale) instead of terminating them. On the gvisor
/// stack the TUN keeps offloaded checksums, so every data segment after the
/// handshake is dropped by the server; the mixed stack completes them. Proved
/// on the TUN endpoint stand; other profiles keep the chosen stack.
pub(crate) fn effective_stack(chosen: Stack, config: &Value) -> Stack {
    let endpoints = config["endpoints"]
        .as_array()
        .is_some_and(|e| !e.is_empty());
    if chosen == Stack::Gvisor && endpoints {
        Stack::Mixed
    } else {
        chosen
    }
}

pub fn apply(
    request: &mut LoadConfigReq,
    profile: &Profile,
    preferences: &Preferences,
) -> Result<(), String> {
    if preferences.connection_mode != ConnectionMode::Tun {
        return Ok(());
    }
    if !supported() {
        return Err(unavailable());
    }
    preferences.tun.validate()?;
    let mut config: Value = serde_json::from_str(
        request
            .core_config
            .as_deref()
            .ok_or("invalid_configuration")?,
    )
    .map_err(|_| "invalid_configuration")?;
    if profile.kind == ProfileKind::SingBoxConfig {
        adopt_full_config(&mut config)?;
    }
    request.managed_tun_dns_mode =
        inbound::add(&mut config, &preferences.tun, inbound::System::current())?;
    request.core_config = Some(config.to_string());
    Ok(())
}

/// A complete sing-box JSON keeps its own outbounds, routing and DNS; only the
/// managed TUN listener is added, exactly as for compiled profiles. Qt leaves
/// such JSON verbatim, which requires the user to write a privileged inbound
/// themselves; the managed worker instead owns exactly one TUN, so a JSON that
/// already terminates traffic itself cannot be adopted.
fn adopt_full_config(config: &mut Value) -> Result<(), String> {
    if !config.is_object() {
        return Err("invalid_configuration".into());
    }
    if config["inbounds"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|inbound| {
            matches!(
                inbound["type"].as_str(),
                Some("tun" | "redirect" | "tproxy")
            )
        })
    {
        return Err("tun_full_config_inbound_unsupported".into());
    }
    for (key, empty) in [("inbounds", json!([])), ("route", json!({}))] {
        if config[key].is_null() {
            config[key] = empty;
        }
    }
    if !config["inbounds"].is_array() || !config["route"].is_object() {
        return Err("invalid_configuration".into());
    }
    if config["route"]["rules"].is_null() {
        config["route"]["rules"] = json!([]);
    }
    Ok(())
}

pub(crate) fn preflight(pid: u32, owns_interface: bool) -> Result<(), String> {
    if !supported() {
        return Err(unavailable());
    }
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|_| "tun_permission_required")?;
    let capabilities = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|s| u64::from_str_radix(s.trim(), 16).ok())
        .unwrap_or(0);
    if capabilities & (1 << 12) == 0 {
        return Err("tun_permission_required".into());
    }
    if !std::path::Path::new("/dev/net/tun").exists() {
        return Err("tun_device_missing".into());
    }
    if owns_interface {
        return Ok(());
    }
    network_clear()?;
    addresses_available()
}

pub(crate) fn addresses_available() -> Result<(), String> {
    addresses_available_for(&[IPV4_ADDRESS.into(), IPV6_ADDRESS.into()])
}
pub(crate) fn addresses_available_for(addresses: &[String]) -> Result<(), String> {
    if local_addresses()?
        .iter()
        .any(|cidr| addresses.iter().any(|target| overlaps(cidr, target)))
    {
        return Err("tun_conflict".into());
    }
    Ok(())
}

#[cfg(not(windows))]
fn local_addresses() -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for interface in ip_json(&["-j", "address", "show"])? {
        for address in interface["addr_info"].as_array().into_iter().flatten() {
            if let (Some(local), Some(prefix)) =
                (address["local"].as_str(), address["prefixlen"].as_u64())
            {
                out.push(format!("{local}/{prefix}"));
            }
        }
    }
    Ok(out)
}

#[cfg(windows)]
fn local_addresses() -> Result<Vec<String>, String> {
    Ok(windows::adapters()?
        .into_iter()
        .flat_map(|adapter| adapter.addresses)
        .collect())
}

fn overlaps(a: &str, b: &str) -> bool {
    fn parse(value: &str) -> Option<(IpAddr, u32)> {
        let (ip, bits) = value.split_once('/')?;
        Some((ip.parse().ok()?, bits.parse().ok()?))
    }
    let (Some((a, ap)), Some((b, bp))) = (parse(a), parse(b)) else {
        return false;
    };
    let prefix = ap.min(bp);
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) if prefix <= 32 => {
            (u32::from(a) ^ u32::from(b))
                .checked_shr(32 - prefix)
                .unwrap_or(0)
                == 0
        }
        (IpAddr::V6(a), IpAddr::V6(b)) if prefix <= 128 => {
            (u128::from(a) ^ u128::from(b))
                .checked_shr(128 - prefix)
                .unwrap_or(0)
                == 0
        }
        _ => false,
    }
}

/// Windows has no policy rules to collide with; an adapter of the same name
/// is still another session, or one not yet removed.
#[cfg(windows)]
pub(crate) fn network_clear() -> Result<(), String> {
    if windows::adapters()?
        .iter()
        .any(|adapter| adapter.name.eq_ignore_ascii_case(INTERFACE))
    {
        return Err("tun_conflict".into());
    }
    Ok(())
}

#[cfg(not(windows))]
pub(crate) fn network_clear() -> Result<(), String> {
    // sing-tun cleans the entire priority interval on Start. Refuse occupied
    // priorities before it can delete somebody else's policy rules.
    for family in ["-4", "-6"] {
        let rules = ip_json(&[family, "-j", "rule", "show"])?;
        if rules.iter().any(|r| {
            r["priority"]
                .as_u64()
                .is_some_and(|p| (RULE_PRIORITY..=RULE_PRIORITY + 10).contains(&p))
        }) {
            return Err("tun_conflict".into());
        }
    }
    if ip_json(&["-j", "link", "show"])?
        .iter()
        .any(|v| v["ifname"] == INTERFACE)
    {
        return Err("tun_conflict".into());
    }
    Ok(())
}

#[cfg(not(windows))]
fn ip_json(args: &[&str]) -> Result<Vec<Value>, String> {
    let output = std::process::Command::new("ip")
        .args(args)
        .output()
        .map_err(|_| "tun_network_check_failed")?;
    if !output.status.success() {
        return Err("tun_network_check_failed".into());
    }
    serde_json::from_slice(&output.stdout).map_err(|_| "tun_network_check_failed".into())
}

mod inbound;
#[cfg(test)]
mod tests;
#[cfg(windows)]
pub(crate) mod windows;

pub(crate) fn configured_addresses(l: &crate::store::Library) -> Vec<String> {
    let mut addresses = vec![crate::settings::string(l, "vpn_tun_ipv4_cidr")];
    if l.preferences.tun.ipv6 {
        addresses.push(crate::settings::string(l, "vpn_tun_ipv6_cidr"));
    }
    addresses
}
pub(crate) fn apply_settings(
    request: &mut LoadConfigReq,
    l: &crate::store::Library,
) -> Result<(), String> {
    if l.preferences.connection_mode != ConnectionMode::Tun {
        return Ok(());
    }
    let mut c: Value = serde_json::from_str(
        request
            .core_config
            .as_deref()
            .ok_or("invalid_configuration")?,
    )
    .map_err(|_| "invalid_configuration")?;
    let mut excludes: Vec<Value> = vec![];
    if !crate::settings::boolean(l, "disable_private_range_bypass") {
        excludes.extend(l.preferences.tun.exclude_addresses.iter().map(|s| json!(s)));
    }
    if crate::settings::boolean(l, "enable_tun_routing") {
        // Kernel exclusions run before the core's ordered rules. Only a leading
        // sequence of unconditional direct-IP rules can be promoted without skipping
        // an earlier block, proxy, DNS interception or process-specific decision.
        for rule in c["route"]["rules"].as_array().into_iter().flatten() {
            // Annotations and rules that cannot see TUN traffic decide nothing here.
            if crate::routing::builtin::annotates(rule) || bound_elsewhere(rule) {
                continue;
            }
            let direct = rule["outbound"] == "direct"
                && (rule["action"].is_null() || rule["action"] == "route")
                && rule["ip_cidr"].is_array()
                && rule.as_object().is_some_and(|r| {
                    r.keys()
                        .all(|k| matches!(k.as_str(), "action" | "outbound" | "ip_cidr"))
                });
            if !direct {
                break;
            }
            excludes.extend(rule["ip_cidr"].as_array().into_iter().flatten().cloned());
        }
    }
    excludes.extend([
        json!("127.0.0.0/8"),
        json!("255.255.255.255/32"),
        json!("::1/128"),
    ]);
    let i = c["inbounds"]
        .as_array_mut()
        .and_then(|a| a.iter_mut().find(|i| i["tag"] == INTERFACE))
        .ok_or("tun_incompatible")?;
    i["address"] = json!(configured_addresses(l));
    i["auto_redirect"] = json!(crate::settings::boolean(l, "vpn_auto_redirect"));
    i["route_exclude_address"] = json!(excludes);
    if crate::settings::boolean(l, "vpn_l3_bridge") {
        c["outbounds"].as_array_mut().ok_or("invalid_configuration")?.push(json!({"type":"bridge","tag":"settings-l3-direct","bridge_name":"thronium-br","iproute2_rule_index":18890}));
        let rules = c["route"]["rules"]
            .as_array_mut()
            .ok_or("invalid_configuration")?;
        let mut with_twins = vec![];
        for rule in rules.iter() {
            if rule["outbound"] == "direct"
                && (rule["action"].is_null() || rule["action"] == "route")
            {
                let mut twin = rule.clone();
                twin["preferred_by"] = json!(["settings-l3-direct"]);
                twin["action"] = json!("route");
                twin["outbound"] = json!("settings-l3-direct");
                with_twins.push(twin);
            }
            with_twins.push(rule.clone());
        }
        *rules = with_twins;
        if c["route"]["final"] == "direct" {
            c["route"]["rules"].as_array_mut().unwrap().push(json!({"preferred_by":["settings-l3-direct"],"action":"route","outbound":"settings-l3-direct"}));
        }
    }
    request.core_config = Some(c.to_string());
    Ok(())
}
fn bound_elsewhere(rule: &Value) -> bool {
    match rule.get("inbound") {
        Some(Value::String(tag)) => tag != INTERFACE,
        Some(Value::Array(tags)) => !tags.iter().any(|tag| tag == INTERFACE),
        _ => false,
    }
}
pub(crate) fn valid_interface_cidr(s: &str, ipv6: bool) -> bool {
    let Some((ip, prefix)) = s.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => !ipv6 && (8..=30).contains(&prefix) && ip.is_private(),
        Ok(IpAddr::V6(ip)) => ipv6 && (8..=126).contains(&prefix) && ip.is_unique_local(),
        _ => false,
    }
}
