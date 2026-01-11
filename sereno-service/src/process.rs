//! Process information resolution
//!
//! Multiple fallback methods to get process details even for protected processes.

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::Path;
use std::sync::Mutex;
use once_cell::sync::Lazy;

#[cfg(windows)]
use windows::{
    core::PWSTR,
    Win32::{
        Foundation::{CloseHandle, HANDLE, MAX_PATH},
        System::{
            ProcessStatus::{GetModuleFileNameExW, GetProcessImageFileNameW},
            Threading::{
                OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
                PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
            },
        },
    },
};

/// Cache for process info to avoid repeated lookups
static PROCESS_CACHE: Lazy<Mutex<HashMap<u32, Option<ProcessInfo>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Clone, Debug)]
pub struct ProcessInfo {
    pub path: String,
    pub name: String,
    pub publisher: Option<String>,
}

/// Get process information with multiple fallback methods
#[cfg(windows)]
pub fn get_process_info(pid: u32) -> Option<ProcessInfo> {
    // Check cache first
    {
        let cache = PROCESS_CACHE.lock().unwrap();
        if let Some(cached) = cache.get(&pid) {
            return cached.clone();
        }
    }

    let info = get_process_info_impl(pid);

    // Cache the result
    {
        let mut cache = PROCESS_CACHE.lock().unwrap();
        cache.insert(pid, info.clone());
        // Limit cache size
        if cache.len() > 1000 {
            cache.clear();
        }
    }

    info
}

#[cfg(windows)]
fn get_process_info_impl(pid: u32) -> Option<ProcessInfo> {
    // Try methods in order of preference
    if let Some(path) = try_query_full_process_image_name(pid) {
        return Some(make_process_info(path));
    }

    if let Some(path) = try_get_module_filename_ex(pid) {
        return Some(make_process_info(path));
    }

    if let Some(path) = try_get_process_image_filename(pid) {
        return Some(make_process_info(path));
    }

    // Last resort: try to get from WMI or other system info
    if let Some(name) = get_process_name_from_system(pid) {
        return Some(ProcessInfo {
            path: format!("(system) {}", name),
            name,
            publisher: Some("Microsoft Windows".to_string()),
        });
    }

    None
}

fn make_process_info(path: String) -> ProcessInfo {
    let name = Path::new(&path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let publisher = get_publisher_from_path(&path);

    ProcessInfo {
        path,
        name,
        publisher,
    }
}

/// Method 1: QueryFullProcessImageNameW - works for most processes
#[cfg(windows)]
fn try_query_full_process_image_name(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let result = query_full_image_name(handle);
        let _ = CloseHandle(handle);
        result
    }
}

#[cfg(windows)]
unsafe fn query_full_image_name(handle: HANDLE) -> Option<String> {
    let mut buffer = [0u16; MAX_PATH as usize];
    let mut size = buffer.len() as u32;

    if QueryFullProcessImageNameW(
        handle,
        PROCESS_NAME_FORMAT(0), // Win32 path format
        PWSTR::from_raw(buffer.as_mut_ptr()),
        &mut size,
    )
    .is_ok()
    {
        let path = OsString::from_wide(&buffer[..size as usize])
            .to_string_lossy()
            .to_string();
        if !path.is_empty() {
            return Some(path);
        }
    }
    None
}

/// Method 2: GetModuleFileNameExW - requires more permissions
#[cfg(windows)]
fn try_get_module_filename_ex(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).ok()?;

        let mut buffer = [0u16; MAX_PATH as usize];
        let len = GetModuleFileNameExW(handle, None, &mut buffer);

        let _ = CloseHandle(handle);

        if len > 0 {
            let path = OsString::from_wide(&buffer[..len as usize])
                .to_string_lossy()
                .to_string();
            return Some(path);
        }
    }
    None
}

/// Method 3: GetProcessImageFileNameW - returns device path
#[cfg(windows)]
fn try_get_process_image_filename(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;

        let mut buffer = [0u16; MAX_PATH as usize];
        let len = GetProcessImageFileNameW(handle, &mut buffer);

        let _ = CloseHandle(handle);

        if len > 0 {
            let device_path = OsString::from_wide(&buffer[..len as usize])
                .to_string_lossy()
                .to_string();
            // Convert device path to DOS path
            return Some(convert_device_path_to_dos(&device_path));
        }
    }
    None
}

/// Convert NT device path to DOS path
fn convert_device_path_to_dos(device_path: &str) -> String {
    // Common device path prefixes
    if device_path.starts_with("\\Device\\HarddiskVolume") {
        // Try to map to drive letter - simplified version
        // In production, would enumerate volumes properly
        if let Some(rest) = device_path.strip_prefix("\\Device\\HarddiskVolume1") {
            return format!("C:{}", rest);
        }
        if let Some(rest) = device_path.strip_prefix("\\Device\\HarddiskVolume2") {
            return format!("D:{}", rest);
        }
        if let Some(rest) = device_path.strip_prefix("\\Device\\HarddiskVolume3") {
            return format!("C:{}", rest);
        }
    }
    device_path.to_string()
}

/// Get well-known system process names
fn get_process_name_from_system(pid: u32) -> Option<String> {
    match pid {
        0 => Some("System Idle Process".to_string()),
        4 => Some("System".to_string()),
        _ => None,
    }
}

/// Extract publisher from executable (simplified - would use Authenticode in production)
fn get_publisher_from_path(path: &str) -> Option<String> {
    let path_lower = path.to_lowercase();

    if path_lower.contains("\\windows\\") {
        Some("Microsoft Windows".to_string())
    } else if path_lower.contains("\\microsoft\\") {
        Some("Microsoft Corporation".to_string())
    } else if path_lower.contains("\\google\\") {
        Some("Google LLC".to_string())
    } else if path_lower.contains("\\mozilla") {
        Some("Mozilla Foundation".to_string())
    } else if path_lower.contains("\\node") || path_lower.contains("nodejs") {
        Some("Node.js Foundation".to_string())
    } else {
        None
    }
}

/// Clear the process cache
pub fn clear_cache() {
    if let Ok(mut cache) = PROCESS_CACHE.lock() {
        cache.clear();
    }
}

#[cfg(not(windows))]
pub fn get_process_info(_pid: u32) -> Option<ProcessInfo> {
    None
}

#[cfg(not(windows))]
pub fn clear_cache() {}
