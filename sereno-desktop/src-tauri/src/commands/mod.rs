//! Tauri IPC commands for driver communication
//!
//! These commands bridge the React frontend to the kernel driver.

use crate::driver::{DriverHandle, BandwidthEntry, get_process_name_by_pid};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::State;

/// Shared driver handle state
pub struct DriverState {
    pub handle: Mutex<Option<DriverHandle>>,
}

impl Default for DriverState {
    fn default() -> Self {
        Self {
            handle: Mutex::new(DriverHandle::open().ok()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub id: String,
    pub time: String,
    #[serde(rename = "authStatus")]
    pub auth_status: String,
    pub direction: String,
    #[serde(rename = "signatureStatus")]
    pub signature_status: String,
    #[serde(rename = "processName")]
    pub process_name: String,
    #[serde(rename = "processId")]
    pub process_id: u32,
    pub destination: String,
    #[serde(rename = "remoteAddress")]
    pub remote_address: String,
    #[serde(rename = "remotePort")]
    pub remote_port: u16,
    pub protocol: String,
    #[serde(rename = "bytesSent")]
    pub bytes_sent: u64,
    #[serde(rename = "bytesReceived")]
    pub bytes_received: u64,
    #[serde(rename = "isActive")]
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bandwidth {
    pub up: u64,
    pub down: u64,
    pub flows: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub process_name: String,
    pub destination: String,
    pub port: Option<u16>,
    pub action: String,
    pub enabled: bool,
}

/// Get driver status
#[tauri::command]
pub fn get_driver_status(state: State<'_, DriverState>) -> String {
    let guard = state.handle.lock().unwrap();
    if guard.is_some() {
        "running".to_string()
    } else {
        "stopped".to_string()
    }
}

/// Get current bandwidth statistics from driver
#[tauri::command]
pub fn get_bandwidth(state: State<'_, DriverState>) -> Bandwidth {
    let guard = state.handle.lock().unwrap();

    if let Some(ref handle) = *guard {
        if let Ok(entries) = handle.get_bandwidth_stats() {
            let mut total_up = 0u64;
            let mut total_down = 0u64;
            let flows = entries.len() as u32;

            for entry in &entries {
                total_up += entry.bytes_sent;
                total_down += entry.bytes_received;
            }

            return Bandwidth {
                up: total_up,
                down: total_down,
                flows,
            };
        }
    }

    Bandwidth { up: 0, down: 0, flows: 0 }
}

/// Convert BandwidthEntry to Connection for frontend display
fn bandwidth_to_connection(entry: &BandwidthEntry, index: usize) -> Connection {
    let process_name = get_process_name_by_pid(entry.process_id)
        .unwrap_or_else(|| {
            if entry.process_id == 0 {
                "TLM".to_string()
            } else if entry.process_id == 4 {
                "System".to_string()
            } else {
                format!("PID:{}", entry.process_id)
            }
        });

    let now = chrono::Local::now();
    let time = now.format("%H:%M:%S").to_string();

    Connection {
        id: format!("{}", entry.flow_handle),
        time,
        auth_status: "auto".to_string(), // TLM flows are auto-permitted
        direction: "outbound".to_string(),
        signature_status: "unknown".to_string(),
        process_name,
        process_id: entry.process_id,
        destination: entry.remote_address.to_string(),
        remote_address: entry.remote_address.to_string(),
        remote_port: entry.remote_port,
        protocol: "tcp".to_string(),
        bytes_sent: entry.bytes_sent,
        bytes_received: entry.bytes_received,
        is_active: entry.bytes_sent > 0 || entry.bytes_received > 0,
    }
}

/// Get list of active connections from TLM bandwidth stats
#[tauri::command]
pub fn get_connections(state: State<'_, DriverState>) -> Vec<Connection> {
    let guard = state.handle.lock().unwrap();

    if let Some(ref handle) = *guard {
        if let Ok(entries) = handle.get_bandwidth_stats() {
            return entries.iter()
                .enumerate()
                .map(|(i, e)| bandwidth_to_connection(e, i))
                .collect();
        }
    }

    vec![]
}

/// Get list of rules
#[tauri::command]
pub fn get_rules() -> Vec<Rule> {
    // TODO: Connect to actual database via sereno-core
    vec![]
}

/// Create a new rule
#[tauri::command]
pub fn create_rule(
    process_name: String,
    destination: String,
    port: Option<u16>,
    action: String,
) -> Result<Rule, String> {
    // TODO: Implement rule creation via sereno-core
    Ok(Rule {
        id: uuid::Uuid::new_v4().to_string(),
        process_name,
        destination,
        port,
        action,
        enabled: true,
    })
}

/// Delete a rule
#[tauri::command]
pub fn delete_rule(_id: String) -> Result<(), String> {
    // TODO: Implement rule deletion via sereno-core
    Ok(())
}

/// Toggle rule enabled state
#[tauri::command]
pub fn toggle_rule(_id: String) -> Result<bool, String> {
    // TODO: Implement rule toggle via sereno-core
    Ok(true)
}

/// Send verdict for a pending connection
#[tauri::command]
pub fn send_verdict(_request_id: u64, _allow: bool, _remember: bool) -> Result<(), String> {
    // TODO: Implement verdict sending via sereno-core
    Ok(())
}
