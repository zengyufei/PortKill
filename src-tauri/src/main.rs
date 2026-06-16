#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use portkill_core::{
    group_by_process, list_filtered_ports, list_ports, load_favorites as load_favorites_core,
    query_process_details as query_process_details_core, save_favorites as save_favorites_core,
    terminate_process_by_pid, PortEntry, PortFilter, ProcessDetailRequest, ProcessDetails,
    ProcessGroup,
};

async fn run_blocking<T, F>(task: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(task)
        .await
        .map_err(|err| format!("后台任务失败：{err}"))?
}

#[tauri::command]
async fn get_ports() -> Result<Vec<PortEntry>, String> {
    run_blocking(list_ports).await
}

#[tauri::command]
async fn get_filtered_ports(filter: PortFilter) -> Result<Vec<PortEntry>, String> {
    run_blocking(move || list_filtered_ports(&filter)).await
}

#[tauri::command]
async fn get_process_details(
    requests: Vec<ProcessDetailRequest>,
) -> Result<Vec<ProcessDetails>, String> {
    run_blocking(move || Ok(query_process_details_core(&requests))).await
}

#[tauri::command]
async fn get_process_groups() -> Result<Vec<ProcessGroup>, String> {
    run_blocking(|| {
        let entries = list_ports()?;
        Ok(group_by_process(&entries))
    })
    .await
}

#[tauri::command]
fn load_favorites() -> Result<Vec<u16>, String> {
    load_favorites_core()
}

#[tauri::command]
fn save_favorites(favorites: Vec<u16>) -> Result<(), String> {
    save_favorites_core(&favorites)
}

#[tauri::command]
async fn terminate_process(pid: u32) -> Result<(), String> {
    run_blocking(move || terminate_process_by_pid(pid)).await
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_ports,
            get_filtered_ports,
            get_process_details,
            get_process_groups,
            load_favorites,
            save_favorites,
            terminate_process
        ])
        .run(tauri::generate_context!())
        .expect("failed to run portKill");
}
