use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::ffi::c_void;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use windows::core::{BSTR, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDP6TABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, SidTypeUnknown, TokenUser, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoInitializeSecurity, CoSetProxyBlanket, CoUninitialize,
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
    RPC_C_IMP_LEVEL_IMPERSONATE,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, TerminateProcess,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
};
use windows::Win32::System::Variant::{VariantClear, VARIANT, VT_BSTR};
use windows::Win32::System::Wmi::{
    IEnumWbemClassObject, IWbemLocator, WbemLocator, WBEM_FLAG_FORWARD_ONLY,
    WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_GENERIC_FLAG_TYPE, WBEM_INFINITE,
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
    pub user: String,
    pub command: String,
    pub process_type: String,
    pub can_terminate: bool,
    pub deny_reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessGroup {
    pub pid: u32,
    pub process: String,
    pub path: String,
    pub user: String,
    pub command: String,
    pub process_type: String,
    pub ports: Vec<PortEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessDetailRequest {
    pub pid: u32,
    pub process: String,
    pub path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessDetails {
    pub pid: u32,
    pub user: String,
    pub command: String,
    pub process_type: String,
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
    user: String,
    command: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortableSettings {
    pub favorites: Vec<u16>,
}

pub fn list_ports() -> Result<Vec<PortEntry>, String> {
    let current_pid = std::process::id();
    let process_names = snapshot_process_names();
    let mut process_cache = HashMap::new();
    let mut entries = Vec::new();

    collect_tcp_v4(
        &mut entries,
        current_pid,
        &process_names,
        &mut process_cache,
    )?;
    collect_tcp_v6(
        &mut entries,
        current_pid,
        &process_names,
        &mut process_cache,
    )?;
    collect_udp_v4(
        &mut entries,
        current_pid,
        &process_names,
        &mut process_cache,
    )?;
    collect_udp_v6(
        &mut entries,
        current_pid,
        &process_names,
        &mut process_cache,
    )?;

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

pub fn query_process_details(requests: &[ProcessDetailRequest]) -> Vec<ProcessDetails> {
    let mut seen = HashMap::new();
    let mut details = Vec::new();

    for request in requests {
        if seen.insert(request.pid, true).is_some() {
            continue;
        }

        let user = match request.pid {
            0 => String::new(),
            4 => "NT AUTHORITY\\SYSTEM".to_string(),
            pid => query_process_user(pid).unwrap_or_default(),
        };
        let command = match request.pid {
            0 | 4 => String::new(),
            pid => query_process_command(pid).unwrap_or_default(),
        };
        let process_type = detect_process_type(&request.process, &request.path, &command);

        details.push(ProcessDetails {
            pid: request.pid,
            user,
            command,
            process_type,
        });
    }

    details
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
                || entry.user.to_ascii_lowercase().contains(&query)
                || entry.command.to_ascii_lowercase().contains(&query)
                || process_type_label(&entry.process_type)
                    .to_ascii_lowercase()
                    .contains(&query)
                || entry.process_type.to_ascii_lowercase().contains(&query)
                || entry.local_addr.to_ascii_lowercase().contains(&query)
                || entry.remote_addr.to_ascii_lowercase().contains(&query)
        })
        .collect()
}

pub fn group_by_process(entries: &[PortEntry]) -> Vec<ProcessGroup> {
    let mut grouped: BTreeMap<(String, u32), Vec<PortEntry>> = BTreeMap::new();
    for entry in entries {
        grouped
            .entry((entry.process.to_ascii_lowercase(), entry.pid))
            .or_default()
            .push(entry.clone());
    }

    grouped
        .into_values()
        .map(|mut ports| {
            ports.sort_by(|a, b| {
                a.local_port
                    .cmp(&b.local_port)
                    .then_with(|| a.protocol.cmp(&b.protocol))
                    .then_with(|| a.state.cmp(&b.state))
            });
            let first = ports.first().cloned().unwrap_or_else(|| PortEntry {
                protocol: String::new(),
                local_addr: String::new(),
                local_port: 0,
                remote_addr: String::new(),
                remote_port: 0,
                state: String::new(),
                pid: 0,
                process: String::new(),
                path: String::new(),
                user: String::new(),
                command: String::new(),
                process_type: "other".to_string(),
                can_terminate: false,
                deny_reason: String::new(),
            });
            ProcessGroup {
                pid: first.pid,
                process: first.process,
                path: first.path,
                user: first.user,
                command: first.command,
                process_type: first.process_type,
                ports,
            }
        })
        .collect()
}

pub fn settings_path() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|err| format!("无法定位程序路径：{err}"))?;
    let dir = exe
        .parent()
        .ok_or_else(|| "无法定位程序所在目录。".to_string())?;
    Ok(dir.join("portKill-settings.json"))
}

pub fn load_favorites() -> Result<Vec<u16>, String> {
    load_favorites_from_path(&settings_path()?)
}

pub fn save_favorites(favorites: &[u16]) -> Result<(), String> {
    save_favorites_to_path(&settings_path()?, favorites)
}

pub fn load_favorites_from_path(path: &Path) -> Result<Vec<u16>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(path).map_err(|err| format!("读取收藏失败：{err}"))?;
    let mut settings = serde_json::from_str::<PortableSettings>(&content).unwrap_or_default();
    settings.favorites.sort_unstable();
    settings.favorites.dedup();
    Ok(settings.favorites)
}

pub fn save_favorites_to_path(path: &Path, favorites: &[u16]) -> Result<(), String> {
    let mut unique = favorites.to_vec();
    unique.sort_unstable();
    unique.dedup();
    let settings = PortableSettings { favorites: unique };
    let json = serde_json::to_string_pretty(&settings).map_err(|err| err.to_string())?;
    fs::write(path, json).map_err(|err| format!("保存收藏失败：{err}"))
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
    process_names: &HashMap<u32, String>,
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
                process_names,
                process_cache,
            );
        }
    }

    Ok(())
}

fn collect_tcp_v6(
    entries: &mut Vec<PortEntry>,
    current_pid: u32,
    process_names: &HashMap<u32, String>,
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
                process_names,
                process_cache,
            );
        }
    }

    Ok(())
}

fn collect_udp_v4(
    entries: &mut Vec<PortEntry>,
    current_pid: u32,
    process_names: &HashMap<u32, String>,
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
                process_names,
                process_cache,
            );
        }
    }

    Ok(())
}

fn collect_udp_v6(
    entries: &mut Vec<PortEntry>,
    current_pid: u32,
    process_names: &HashMap<u32, String>,
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
                process_names,
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
    process_names: &HashMap<u32, String>,
    process_cache: &mut HashMap<u32, ProcessInfo>,
) {
    let process_info = process_cache
        .entry(pid)
        .or_insert_with(|| query_process_info(pid, process_names))
        .clone();
    let deny_reason = termination_deny_reason(pid, current_pid).unwrap_or_default();
    let can_terminate = deny_reason.is_empty();
    let process_type = detect_process_type(
        &process_info.process,
        &process_info.path,
        &process_info.command,
    );

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
        user: process_info.user,
        command: process_info.command,
        process_type,
        can_terminate,
        deny_reason,
    });
}

fn query_process_info(pid: u32, process_names: &HashMap<u32, String>) -> ProcessInfo {
    if pid == 0 {
        return ProcessInfo {
            process: "Idle".to_string(),
            path: String::new(),
            user: String::new(),
            command: String::new(),
        };
    }
    if pid == 4 {
        return ProcessInfo {
            process: "System".to_string(),
            path: String::new(),
            user: "NT AUTHORITY\\SYSTEM".to_string(),
            command: String::new(),
        };
    }

    let path = query_process_path(pid).unwrap_or_default();
    let process = Path::new(&path)
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_string())
        .or_else(|| process_names.get(&pid).cloned())
        .unwrap_or_else(|| format!("PID {pid}"));
    ProcessInfo {
        process,
        path,
        user: String::new(),
        command: String::new(),
    }
}

fn snapshot_process_names() -> HashMap<u32, String> {
    let mut names = HashMap::new();
    let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(handle) => handle,
        Err(_) => return names,
    };

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    if unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok() {
        loop {
            let name = process_entry_name(&entry.szExeFile);
            if !name.is_empty() {
                names.insert(entry.th32ProcessID, name);
            }
            if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }

    let _ = unsafe { CloseHandle(snapshot) };
    names
}

fn process_entry_name(buffer: &[u16]) -> String {
    let len = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..len])
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

fn query_process_user(pid: u32) -> Option<String> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut token = HANDLE::default();
    let token_result = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
    let _ = unsafe { CloseHandle(process) };
    token_result.ok()?;

    let mut size = 0u32;
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut size) };
    if size == 0 {
        let _ = unsafe { CloseHandle(token) };
        return None;
    }

    let mut buffer = vec![0u8; size as usize];
    let info_result = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut c_void),
            size,
            &mut size,
        )
    };
    let _ = unsafe { CloseHandle(token) };
    info_result.ok()?;

    let token_user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
    let sid = token_user.User.Sid;

    let mut name_len = 0u32;
    let mut domain_len = 0u32;
    let mut sid_type = SidTypeUnknown;
    let _ = unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            None,
            &mut name_len,
            None,
            &mut domain_len,
            &mut sid_type,
        )
    };
    if name_len == 0 {
        return None;
    }

    let mut name = vec![0u16; name_len as usize];
    let mut domain = vec![0u16; domain_len as usize];
    unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut sid_type,
        )
    }
    .ok()?;

    let account = String::from_utf16_lossy(&name[..name_len as usize]);
    let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
    if domain.is_empty() {
        Some(account)
    } else {
        Some(format!("{domain}\\{account}"))
    }
}

fn query_process_command(pid: u32) -> Option<String> {
    unsafe {
        let init_hr = CoInitializeEx(None, COINIT_MULTITHREADED);
        let initialized = init_hr.is_ok();
        if !initialized && init_hr.0 != 0x80010106u32 as i32 {
            return None;
        }

        let _ = CoInitializeSecurity(
            None,
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
            None,
        );

        let result = query_process_command_wmi(pid);
        if initialized {
            CoUninitialize();
        }
        result
    }
}

unsafe fn query_process_command_wmi(pid: u32) -> Option<String> {
    let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER).ok()?;
    let empty = BSTR::new();
    let services = locator
        .ConnectServer(
            &BSTR::from("ROOT\\CIMV2"),
            &empty,
            &empty,
            &empty,
            0,
            &empty,
            None,
        )
        .ok()?;
    let _ = CoSetProxyBlanket(
        &services,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        PCWSTR::null(),
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        None,
        EOAC_NONE,
    );

    let query = format!("SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
    let flags = WBEM_GENERIC_FLAG_TYPE(WBEM_FLAG_FORWARD_ONLY.0 | WBEM_FLAG_RETURN_IMMEDIATELY.0);
    let enumerator: IEnumWbemClassObject = services
        .ExecQuery(&BSTR::from("WQL"), &BSTR::from(query), flags, None)
        .ok()?;
    let mut objects = [None];
    let mut returned = 0u32;
    let hr = enumerator.Next(WBEM_INFINITE, &mut objects, &mut returned);
    if !hr.is_ok() || returned == 0 {
        return None;
    }

    let object = objects[0].as_ref()?;
    let mut variant = VARIANT::default();
    let property = wide_null("CommandLine");
    object
        .Get(PCWSTR(property.as_ptr()), 0, &mut variant, None, None)
        .ok()?;
    let value = variant_to_string(&variant);
    let _ = VariantClear(&mut variant);
    value
}

fn variant_to_string(variant: &VARIANT) -> Option<String> {
    unsafe {
        if variant.Anonymous.Anonymous.vt != VT_BSTR {
            return None;
        }
        let bstr = &variant.Anonymous.Anonymous.Anonymous.bstrVal;
        let value = bstr.to_string();
        if value.is_empty() {
            None
        } else {
            Some(value)
        }
    }
}

pub fn detect_process_type(process: &str, path: &str, command: &str) -> String {
    let haystack = format!("{process} {path} {command}").to_ascii_lowercase();
    if contains_any(
        &haystack,
        &[
            "nginx",
            "apache",
            "httpd",
            "caddy",
            "traefik",
            "lighttpd",
            "iis",
            "iisexpress",
        ],
    ) {
        return "web_server".to_string();
    }
    if contains_any(
        &haystack,
        &[
            "postgres",
            "postgresql",
            "postmaster",
            "pg_ctl",
            "pgsql",
            "mysql",
            "mysqld",
            "mysqladmin",
            "mariadb",
            "mariadbd",
            "redis",
            "mongo",
            "sqlite",
            "cockroach",
            "clickhouse",
            "sqlservr",
            "mssql",
        ],
    ) {
        return "database".to_string();
    }
    if contains_any(
        &haystack,
        &[
            "node", "npm", "yarn", "python", "ruby", "php", "java", "go", "cargo", "dotnet",
            "vite", "webpack", "esbuild", "next", "nuxt", "remix", "bun", "deno",
        ],
    ) {
        return "development".to_string();
    }
    if contains_any(
        &haystack,
        &[
            "svchost", "csrss", "lsass", "winlogon", "services", "system", "smss", "dwm",
        ],
    ) {
        return "system".to_string();
    }
    "other".to_string()
}

pub fn process_type_label(process_type: &str) -> &'static str {
    match process_type {
        "web_server" => "Web Server",
        "database" => "Database",
        "development" => "Development",
        "system" => "System",
        _ => "Other",
    }
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
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
            user: "LOCAL\\tester".to_string(),
            command: format!("{process} --port {port}"),
            process_type: detect_process_type(process, &format!("C:\\Tools\\{process}"), ""),
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

        let filtered = apply_filter(
            vec![sample_entry("TCP", 5432, "LISTENING", 13, "postgres.exe")],
            &PortFilter {
                query: Some("tester".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(filtered.len(), 1);

        let filtered = apply_filter(
            vec![sample_entry("TCP", 5173, "LISTENING", 14, "node.exe")],
            &PortFilter {
                query: Some("--port 5173".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn detects_process_types() {
        assert_eq!(detect_process_type("nginx.exe", "", ""), "web_server");
        assert_eq!(detect_process_type("sqlservr.exe", "", ""), "database");
        assert_eq!(detect_process_type("mysqld.exe", "", ""), "database");
        assert_eq!(detect_process_type("postmaster.exe", "", ""), "database");
        assert_eq!(
            detect_process_type("wrapper.exe", "", "pgsql data server"),
            "database"
        );
        assert_eq!(detect_process_type("node.exe", "", ""), "development");
        assert_eq!(detect_process_type("svchost.exe", "", ""), "system");
        assert_eq!(detect_process_type("custom-app.exe", "", ""), "other");
        assert_eq!(
            detect_process_type("wrapper.exe", "", "python app.py"),
            "development"
        );
    }

    #[test]
    fn falls_back_to_snapshot_process_name() {
        let mut names = HashMap::new();
        names.insert(999_999, "mysqld.exe".to_string());

        let info = query_process_info(999_999, &names);
        assert_eq!(info.process, "mysqld.exe");
        assert_eq!(
            detect_process_type(&info.process, &info.path, ""),
            "database"
        );
    }

    #[test]
    fn builds_process_details_without_duplicates() {
        let requests = vec![
            ProcessDetailRequest {
                pid: 0,
                process: "Idle".to_string(),
                path: String::new(),
            },
            ProcessDetailRequest {
                pid: 0,
                process: "Idle".to_string(),
                path: String::new(),
            },
            ProcessDetailRequest {
                pid: 4,
                process: "System".to_string(),
                path: String::new(),
            },
        ];

        let details = query_process_details(&requests);
        assert_eq!(details.len(), 2);
        assert!(details.iter().any(|detail| detail.pid == 0));
        let system = details.iter().find(|detail| detail.pid == 4).unwrap();
        assert_eq!(system.user, "NT AUTHORITY\\SYSTEM");
        assert_eq!(system.process_type, "system");
    }

    #[test]
    fn groups_entries_by_pid() {
        let entries = vec![
            sample_entry("TCP", 3000, "LISTENING", 10, "node.exe"),
            sample_entry("UDP", 3001, "-", 10, "node.exe"),
            sample_entry("TCP", 5432, "LISTENING", 11, "postgres.exe"),
        ];

        let groups = group_by_process(&entries);
        assert_eq!(groups.len(), 2);
        let node = groups.iter().find(|group| group.pid == 10).unwrap();
        assert_eq!(node.ports.len(), 2);
        assert_eq!(node.ports[0].local_port, 3000);
        assert_eq!(node.ports[1].local_port, 3001);
    }

    #[test]
    fn reads_and_writes_favorites_settings() {
        let path = std::env::temp_dir().join(format!(
            "portKill-settings-test-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);

        assert_eq!(load_favorites_from_path(&path).unwrap(), Vec::<u16>::new());
        save_favorites_to_path(&path, &[3000, 8080, 3000]).unwrap();
        assert_eq!(load_favorites_from_path(&path).unwrap(), vec![3000, 8080]);

        fs::write(&path, "{not-json").unwrap();
        assert_eq!(load_favorites_from_path(&path).unwrap(), Vec::<u16>::new());
        let _ = fs::remove_file(path);
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
        let current = entries
            .iter()
            .find(|entry| entry.pid == current_pid)
            .expect("current process entry");
        assert!(
            !current.user.is_empty() || !current.command.is_empty() || !current.path.is_empty()
        );
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
