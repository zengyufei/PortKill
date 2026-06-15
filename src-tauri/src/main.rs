#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use portkill_core::{
    list_filtered_ports, list_ports, terminate_process_by_pid, PortEntry, PortFilter,
};

#[tauri::command]
fn get_ports() -> Result<Vec<PortEntry>, String> {
    list_ports()
}

#[tauri::command]
fn get_filtered_ports(filter: PortFilter) -> Result<Vec<PortEntry>, String> {
    list_filtered_ports(&filter)
}

#[tauri::command]
fn terminate_process(pid: u32) -> Result<(), String> {
    terminate_process_by_pid(pid)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_ports,
            get_filtered_ports,
            terminate_process
        ])
        .run(tauri::generate_context!())
        .expect("failed to run portKill");
}
