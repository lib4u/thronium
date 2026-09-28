//! Windows TUN runs in ThroniumService: whether it is installed, starting it
//! on demand, and what the network already uses before a session starts.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};
use windows_sys::Win32::{
    Foundation::{
        GetLastError, ERROR_ACCESS_DENIED, ERROR_BUFFER_OVERFLOW, ERROR_SERVICE_ALREADY_RUNNING,
    },
    NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    },
    Networking::WinSock::AF_UNSPEC,
    System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, StartServiceW,
        SC_HANDLE, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS,
        SERVICE_RUNNING, SERVICE_START, SERVICE_STATUS_PROCESS, SERVICE_STOPPED,
    },
};

pub(crate) const SERVICE: &str = "ThroniumService";
pub(crate) const PIPE: &str = r"\\.\pipe\thronium-service";

struct Handle(SC_HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.0) };
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

fn open(access: u32) -> Result<Handle, String> {
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err("tun_service_unavailable".into());
    }
    let manager = Handle(manager);
    let name = wide(SERVICE);
    let service = unsafe { OpenServiceW(manager.0, name.as_ptr(), access) };
    if service.is_null() {
        return Err(match unsafe { GetLastError() } {
            ERROR_ACCESS_DENIED => "tun_service_start_denied",
            _ => "tun_service_missing",
        }
        .into());
    }
    Ok(Handle(service))
}

fn status(service: &Handle) -> Result<SERVICE_STATUS_PROCESS, String> {
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0;
    let ok = unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            &mut status as *mut _ as *mut u8,
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err("tun_service_unavailable".into());
    }
    Ok(status)
}

/// Whether the installer registered the service. The snapshot asks often;
/// the answer is kept for a few seconds.
pub(crate) fn installed() -> bool {
    use std::sync::Mutex;
    static CACHE: Mutex<Option<(Instant, bool)>> = Mutex::new(None);
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, value)) = *cache {
        if at.elapsed() < Duration::from_secs(5) {
            return value;
        }
    }
    let value = open(SERVICE_QUERY_STATUS).is_ok();
    *cache = Some((Instant::now(), value));
    value
}

/// Starts the service if it is stopped (the installer lets interactive users
/// do that) and returns the PID the service control manager gives for it:
/// the pipe's server must be exactly that process.
pub(crate) fn running() -> Result<u32, String> {
    let service =
        open(SERVICE_QUERY_STATUS | SERVICE_START).or_else(|_| open(SERVICE_QUERY_STATUS))?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut started = false;
    loop {
        let current = status(&service)?;
        if current.dwCurrentState == SERVICE_RUNNING && current.dwProcessId != 0 {
            return Ok(current.dwProcessId);
        }
        if current.dwCurrentState == SERVICE_STOPPED {
            if started {
                return Err("tun_service_unavailable".into());
            }
            if unsafe { StartServiceW(service.0, 0, std::ptr::null()) } == 0 {
                match unsafe { GetLastError() } {
                    ERROR_SERVICE_ALREADY_RUNNING => {}
                    ERROR_ACCESS_DENIED => return Err("tun_service_start_denied".into()),
                    _ => return Err("tun_service_unavailable".into()),
                }
            }
            started = true;
        }
        if Instant::now() > deadline {
            return Err("tun_service_unavailable".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// One adapter as the check needs it: its name and its addresses with prefix.
pub(crate) struct Adapter {
    pub name: String,
    pub addresses: Vec<String>,
}

pub(crate) fn adapters() -> Result<Vec<Adapter>, String> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 16 * 1024;
    let mut buffer: Vec<u64>;
    let mut attempts = 0;
    loop {
        buffer = vec![0; (size as usize).div_ceil(8)];
        let first = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        let result = unsafe {
            GetAdaptersAddresses(AF_UNSPEC as u32, flags, std::ptr::null(), first, &mut size)
        };
        match result {
            0 => break,
            ERROR_BUFFER_OVERFLOW if attempts < 3 => attempts += 1,
            _ => return Err("tun_network_check_failed".into()),
        }
    }
    let mut out = Vec::new();
    let mut adapter = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while let Some(current) = unsafe { adapter.as_ref() } {
        let name = unsafe { text(current.FriendlyName) };
        let mut addresses = Vec::new();
        let mut unicast = current.FirstUnicastAddress;
        while let Some(address) = unsafe { unicast.as_ref() } {
            if let Some(ip) = unsafe { ip(address.Address.lpSockaddr as *const u8) } {
                addresses.push(format!("{ip}/{}", address.OnLinkPrefixLength));
            }
            unicast = address.Next;
        }
        out.push(Adapter { name, addresses });
        adapter = current.Next;
    }
    Ok(out)
}

unsafe fn text(value: *const u16) -> String {
    if value.is_null() {
        return String::new();
    }
    let mut length = 0;
    while unsafe { *value.add(length) } != 0 && length < 1024 {
        length += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(value, length) })
}

/// A SOCKADDR_IN or SOCKADDR_IN6, read by its family.
unsafe fn ip(sockaddr: *const u8) -> Option<IpAddr> {
    if sockaddr.is_null() {
        return None;
    }
    let family = u16::from_ne_bytes(unsafe { [*sockaddr, *sockaddr.add(1)] });
    let bytes = |offset: usize, length: usize| unsafe {
        std::slice::from_raw_parts(sockaddr.add(offset), length).to_vec()
    };
    match family {
        2 => {
            let b: [u8; 4] = bytes(4, 4).try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(b)))
        }
        23 => {
            let b: [u8; 16] = bytes(8, 16).try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(b)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapters_list_loopback_with_its_prefix() {
        let adapters = adapters().unwrap();
        assert!(adapters
            .iter()
            .flat_map(|a| &a.addresses)
            .any(|cidr| cidr == "127.0.0.1/8"));
        assert!(crate::tun::addresses_available_for(&["127.0.0.2/32".into()]).is_err());
        // TEST-NET-2 (RFC 5737) is never configured on a real adapter.
        assert!(crate::tun::addresses_available_for(&["198.51.100.1/30".into()]).is_ok());
    }

    #[test]
    fn a_machine_without_the_service_has_no_tun() {
        // Neither this test machine nor Wine has ThroniumService registered.
        if open(SERVICE_QUERY_STATUS).is_ok() {
            return;
        }
        assert!(!installed());
        assert!(!crate::tun::supported());
        assert_eq!(running().unwrap_err(), "tun_service_missing");
    }
}
