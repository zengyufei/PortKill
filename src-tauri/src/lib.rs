use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use windows::core::PWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDP6TABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, TerminateProcess, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
};

const NO_ERROR: u32 = 0;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortEntry {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: u32,
    pub process: String,
    pub path: String,
    pub can_terminate: bool,
    pub deny_reason: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortFilter {
    pub protocol: Option<String>,
    pub state: Option<String>,
    pub query: Option<String>,
    pub listeners_only: bool,
    pub port: Option<u16>,
}

#[derive(Clone, Debug, Default)]
struct ProcessInfo {
    process: String,
    path: String,
}

pub fn list_ports() -> Result<Vec<PortEntry>, String> {
    let current_pid = std::process::id();
    let mut process_cache = HashMap::new();
    let mut entries = Vec::new();

    collect_tcp_v4(&mut entries, current_pid, &mut process_cache)?;
    collect_tcp_v6(&mut entries, current_pid, &mut process_cache)?;
    collect_udp_v4(&mut entries, current_pid, &mut process_cache)?;
    collect_udp_v6(&mut entries, current_pid, &mut process_cache)?;

    entries.sort_by(|a, b| {
        a.local_port
            .cmp(&b.local_port)
            .then_with(|| a.protocol.cmp(&b.protocol))
            .then_with(|| a.state.cmp(&b.state))
            .then_with(|| a.pid.cmp(&b.pid))
    });

    Ok(entries)
}

pub fn list_filtered_ports(filter: &PortFilter) -> Result<Vec<PortEntry>, String> {
    let entries = list_ports()?;
    Ok(apply_filter(entries, filter))
}

pub fn apply_filter(entries: Vec<PortEntry>, filter: &PortFilter) -> Vec<PortEntry> {
    let protocol = filter
        .protocol
        .as_deref()
        .unwrap_or("all")
        .to_ascii_lowercase();
    let state = filter.state.as_deref().unwrap_or("").to_ascii_uppercase();
    let query = filter
        .query
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    entries
        .into_iter()
        .filter(|entry| {
            protocol == "all"
                || protocol.is_empty()
                || entry.protocol.eq_ignore_ascii_case(&protocol)
        })
        .filter(|entry| state.is_empty() || entry.state.eq_ignore_ascii_case(&state))
        .filter(|entry| {
            !filter.listeners_only
                || entry.protocol == "UDP"
                || entry.state.eq_ignore_ascii_case("LISTENING")
        })
        .filter(|entry| filter.port.map_or(true, |port| entry.local_port == port))
        .filter(|entry| {
            if query.is_empty() {
                return true;
            }
            entry.local_port.to_string().contains(&query)
                || entry.remote_port.to_string().contains(&query)
                || entry.pid.to_string().contains(&query)
                || entry.process.to_ascii_lowercase().contains(&query)
                || entry.path.to_ascii_lowercase().contains(&query)
                || entry.local_addr.to_ascii_lowercase().contains(&query)
                || entry.remote_addr.to_ascii_lowercase().contains(&query)
        })
        .collect()
}

pub fn terminate_process_by_pid(pid: u32) -> Result<(), String> {
    if let Some(reason) = termination_deny_reason(pid, std::process::id()) {
        return Err(reason);
    }

    let handle = unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) }
        .map_err(|err| format!("权限不足或进程不存在：{err}"))?;
    let result =
        unsafe { TerminateProcess(handle, 1) }.map_err(|err| format!("结束进程失败：{err}"));
    let _ = unsafe { CloseHandle(handle) };
    result
}

pub fn termination_deny_reason(pid: u32, current_pid: u32) -> Option<String> {
    match pid {
        0 => Some("PID 0 是系统 Idle 进程，不允许结束。".to_string()),
        4 => Some("PID 4 是 Windows System 进程，不允许结束。".to_string()),
        pid if pid == current_pid => Some("不允许结束 portKill 自己的进程。".to_string()),
        _ => None,
    }
}

fn collect_tcp_v4(
    entries: &mut Vec<PortEntry>,
    current_pid: u32,
    process_cache: &mut HashMap<u32, ProcessInfo>,
) -> Result<(), String> {
    let buffer = extended_tcp_table(AF_INET.0 as u32)?;
    if buffer.is_empty() {
        return Ok(());
    }

    unsafe {
        let table = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
        let count = (*table).dwNumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).table.as_ptr(), count);
        for row in rows {
            let local_addr = ipv4_from_dword(row.dwLocalAddr);
            let remote_addr = ipv4_from_dword(row.dwRemoteAddr);
            push_entry(
                entries,
                "TCP",
                local_addr,
                port_from_dword(row.dwLocalPort),
                remote_addr,
                port_from_dword(row.dwRemotePort),
                tcp_state_name(row.dwState).to_string(),
                row.dwOwningPid,
                current_pid,
                process_cache,
            );
        }
    }

    Ok(())
}

fn collect_tcp_v6(
    entries: &mut Vec<PortEntry>,
    current_pid: u32,
    process_cache: &mut HashMap<u32, ProcessInfo>,
) -> Result<(), String> {
    let buffer = extended_tcp_table(AF_INET6.0 as u32)?;
    if buffer.is_empty() {
        return Ok(());
    }

    unsafe {
        let table = buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
        let count = (*table).dwNumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).table.as_ptr(), count);
        for row in rows {
            let local_addr = ipv6_to_string(row.ucLocalAddr, row.dwLocalScopeId);
            let remote_addr = ipv6_to_string(row.ucRemoteAddr, row.dwRemoteScopeId);
            push_entry(
                entries,
                "TCP",
                local_addr,
                port_from_dword(row.dwLocalPort),
                remote_addr,
                port_from_dword(row.dwRemotePort),
                tcp_state_name(row.dwState).to_string(),
                row.dwOwningPid,
                current_pid,
                process_cache,
            );
        }
    }

    Ok(())
}

fn collect_udp_v4(
    entries: &mut Vec<PortEntry>,
    current_pid: u32,
    process_cache: &mut HashMap<u32, ProcessInfo>,
) -> Result<(), String> {
    let buffer = extended_udp_table(AF_INET.0 as u32)?;
    if buffer.is_empty() {
        return Ok(());
    }

    unsafe {
        let table = buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
        let count = (*table).dwNumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).table.as_ptr(), count);
        for row in rows {
            push_entry(
                entries,
                "UDP",
                ipv4_from_dword(row.dwLocalAddr),
                port_from_dword(row.dwLocalPort),
                "-".to_string(),
                0,
                "-".to_string(),
                row.dwOwningPid,
                current_pid,
                process_cache,
            );
        }
    }

    Ok(())
}

fn collect_udp_v6(
    entries: &mut Vec<PortEntry>,
    current_pid: u32,
    process_cache: &mut HashMap<u32, ProcessInfo>,
) -> Result<(), String> {
    let buffer = extended_udp_table(AF_INET6.0 as u32)?;
    if buffer.is_empty() {
        return Ok(());
    }

    unsafe {
        let table = buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID;
        let count = (*table).dwNumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).table.as_ptr(), count);
        for row in rows {
            push_entry(
                entries,
                "UDP",
                ipv6_to_string(row.ucLocalAddr, row.dwLocalScopeId),
                port_from_dword(row.dwLocalPort),
                "-".to_string(),
                0,
                "-".to_string(),
                row.dwOwningPid,
                current_pid,
                process_cache,
            );
        }
    }

    Ok(())
}

fn extended_tcp_table(address_family: u32) -> Result<Vec<u8>, String> {
    let mut size = 0u32;
    let first = unsafe {
        GetExtendedTcpTable(
            None,
            &mut size,
            false,
            address_family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if first != ERROR_INSUFFICIENT_BUFFER && first != NO_ERROR {
        return Err(format!("GetExtendedTcpTable 预读取失败，错误码 {first}"));
    }
    if size == 0 {
        return Ok(Vec::new());
    }

    let mut buffer = vec![0u8; size as usize];
    let status = unsafe {
        GetExtendedTcpTable(
            Some(buffer.as_mut_ptr() as *mut c_void),
            &mut size,
            false,
            address_family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if status != NO_ERROR {
        return Err(format!("GetExtendedTcpTable 读取失败，错误码 {status}"));
    }
    Ok(buffer)
}

fn extended_udp_table(address_family: u32) -> Result<Vec<u8>, String> {
    let mut size = 0u32;
    let first = unsafe {
        GetExtendedUdpTable(
            None,
            &mut size,
            false,
            address_family,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };

    if first != ERROR_INSUFFICIENT_BUFFER && first != NO_ERROR {
        return Err(format!("GetExtendedUdpTable 预读取失败，错误码 {first}"));
    }
    if size == 0 {
        return Ok(Vec::new());
    }

    let mut buffer = vec![0u8; size as usize];
    let status = unsafe {
        GetExtendedUdpTable(
            Some(buffer.as_mut_ptr() as *mut c_void),
            &mut size,
            false,
            address_family,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if status != NO_ERROR {
        return Err(format!("GetExtendedUdpTable 读取失败，错误码 {status}"));
    }
    Ok(buffer)
}

#[allow(clippy::too_many_arguments)]
fn push_entry(
    entries: &mut Vec<PortEntry>,
    protocol: &str,
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    state: String,
    pid: u32,
    current_pid: u32,
    process_cache: &mut HashMap<u32, ProcessInfo>,
) {
    let process_info = process_cache
        .entry(pid)
        .or_insert_with(|| query_process_info(pid))
        .clone();
    let deny_reason = termination_deny_reason(pid, current_pid).unwrap_or_default();
    let can_terminate = deny_reason.is_empty();

    entries.push(PortEntry {
        protocol: protocol.to_string(),
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        state,
        pid,
        process: process_info.process,
        path: process_info.path,
        can_terminate,
        deny_reason,
    });
}

fn query_process_info(pid: u32) -> ProcessInfo {
    if pid == 0 {
        return ProcessInfo {
            process: "Idle".to_string(),
            path: String::new(),
        };
    }
    if pid == 4 {
        return ProcessInfo {
            process: "System".to_string(),
            path: String::new(),
        };
    }

    match query_process_path(pid) {
        Some(path) => {
            let process = Path::new(&path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("unknown")
                .to_string();
            ProcessInfo { process, path }
        }
        None => ProcessInfo {
            process: format!("PID {pid}"),
            path: String::new(),
        },
    }
}

fn query_process_path(pid: u32) -> Option<String> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut buffer = vec![0u16; 32768];
    let mut size = buffer.len() as u32;
    let result = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
    };
    let _ = unsafe { CloseHandle(handle) };

    result
        .ok()
        .map(|_| String::from_utf16_lossy(&buffer[..size as usize]))
}

pub fn port_from_dword(port: u32) -> u16 {
    u16::from_be((port & 0xffff) as u16)
}

pub fn ipv4_from_dword(addr: u32) -> String {
    Ipv4Addr::from(addr.to_ne_bytes()).to_string()
}

pub fn ipv6_to_string(addr: [u8; 16], scope_id: u32) -> String {
    let ip = Ipv6Addr::from(addr);
    if scope_id == 0 {
        ip.to_string()
    } else {
        format!("{ip}%{scope_id}")
    }
}

pub fn tcp_state_name(state: u32) -> &'static str {
    match state {
        1 => "CLOSED",
        2 => "LISTENING",
        3 => "SYN_SENT",
        4 => "SYN_RECEIVED",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT_1",
        7 => "FIN_WAIT_2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, UdpSocket};
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::Duration;

    fn sample_entry(protocol: &str, port: u16, state: &str, pid: u32, process: &str) -> PortEntry {
        PortEntry {
            protocol: protocol.to_string(),
            local_addr: "127.0.0.1".to_string(),
            local_port: port,
            remote_addr: "-".to_string(),
            remote_port: 0,
            state: state.to_string(),
            pid,
            process: process.to_string(),
            path: format!("C:\\Tools\\{process}"),
            can_terminate: true,
            deny_reason: String::new(),
        }
    }

    #[test]
    fn converts_ports_from_network_order() {
        assert_eq!(port_from_dword(0xB80B), 3000);
        assert_eq!(port_from_dword(0x901F), 8080);
    }

    #[test]
    fn maps_tcp_states() {
        assert_eq!(tcp_state_name(2), "LISTENING");
        assert_eq!(tcp_state_name(5), "ESTABLISHED");
        assert_eq!(tcp_state_name(999), "UNKNOWN");
    }

    #[test]
    fn formats_ip_addresses() {
        assert_eq!(ipv4_from_dword(0x0100007f), "127.0.0.1");
        assert_eq!(ipv6_to_string(Ipv6Addr::LOCALHOST.octets(), 0), "::1");
        assert_eq!(ipv6_to_string(Ipv6Addr::LOCALHOST.octets(), 12), "::1%12");
    }

    #[test]
    fn filters_entries() {
        let entries = vec![
            sample_entry("TCP", 3000, "LISTENING", 10, "vite.exe"),
            sample_entry("TCP", 3000, "ESTABLISHED", 11, "chrome.exe"),
            sample_entry("UDP", 5353, "-", 12, "mdns.exe"),
        ];

        let filtered = apply_filter(
            entries.clone(),
            &PortFilter {
                listeners_only: true,
                ..Default::default()
            },
        );
        assert_eq!(filtered.len(), 2);

        let filtered = apply_filter(
            entries,
            &PortFilter {
                protocol: Some("tcp".to_string()),
                state: Some("LISTENING".to_string()),
                query: Some("vite".to_string()),
                listeners_only: false,
                port: Some(3000),
            },
        );
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].process, "vite.exe");
    }

    #[test]
    fn protects_special_pids() {
        assert!(termination_deny_reason(0, 100).is_some());
        assert!(termination_deny_reason(4, 100).is_some());
        assert!(termination_deny_reason(100, 100).is_some());
        assert!(termination_deny_reason(101, 100).is_none());
    }

    #[test]
    fn finds_temp_tcp_and_udp_sockets() {
        let tcp = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
        let tcp_port = tcp.local_addr().unwrap().port();
        let udp = UdpSocket::bind("127.0.0.1:0").expect("bind udp");
        let udp_port = udp.local_addr().unwrap().port();
        thread::sleep(Duration::from_millis(100));

        let entries = list_ports().expect("list ports");
        let current_pid = std::process::id();
        assert!(entries.iter().any(|entry| {
            entry.protocol == "TCP"
                && entry.local_port == tcp_port
                && entry.state == "LISTENING"
                && entry.pid == current_pid
        }));
        assert!(entries.iter().any(|entry| {
            entry.protocol == "UDP" && entry.local_port == udp_port && entry.pid == current_pid
        }));
    }

    #[test]
    fn terminates_test_child_process_only() {
        let mut child = Command::new("cmd")
            .args(["/C", "timeout", "/T", "30", "/NOBREAK"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child");

        let pid = child.id();
        terminate_process_by_pid(pid).expect("terminate child");
        let status = child.wait().expect("wait child");
        assert!(!status.success());
    }
}
