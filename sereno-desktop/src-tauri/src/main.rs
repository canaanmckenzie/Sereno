// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod driver;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(commands::DriverState::default())
        .invoke_handler(tauri::generate_handler![
            commands::get_driver_status,
            commands::get_bandwidth,
            commands::get_connections,
            commands::get_rules,
            commands::create_rule,
            commands::delete_rule,
            commands::toggle_rule,
            commands::send_verdict,
        ])
        .setup(|_app| {
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
