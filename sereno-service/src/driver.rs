//! Kernel driver communication module
//!
//! Handles IOCTL communication with the SerenoFilter kernel driver.

use std::ffi::OsStr;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;

use sereno_core::types::{Direction, Protocol};
use tracing::{info, warn};
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::core::PCWSTR;

/// Device path for the Sereno driver
const DEVICE_PATH: &str = r"\\.\SerenoFilter";

/// IOCTL codes (must match driver.h)
const FILE_DEVICE_SERENO: u32 = 0x8000;

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

const METHOD_BUFFERED: u32 = 0;
const FILE_READ_ACCESS: u32 = 1;
const FILE_WRITE_ACCESS: u32 = 2;

const IOCTL_SERENO_GET_PENDING: u32 = ctl_code(FILE_DEVICE_SERENO, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS);
const IOCTL_SERENO_SET_VERDICT: u32 = ctl_code(FILE_DEVICE_SERENO, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS);
const IOCTL_SERENO_GET_STATS: u32 = ctl_code(FILE_DEVICE_SERENO, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS);
const IOCTL_SERENO_ENABLE: u32 = ctl_code(FILE_DEVICE_SERENO, 0x805, METHOD_BUFFERED, FILE_WRITE_ACCESS);
const IOCTL_SERENO_DISABLE: u32 = ctl_code(FILE_DEVICE_SERENO, 0x806, METHOD_BUFFERED, FILE_WRITE_ACCESS);

/// Verdict values (must match driver.h)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverVerdict {
    Pending = 0,
    Allow = 1,
    Block = 2,
}

/// Connection request from the kernel driver
#[repr(C, packed)]
#[derive(Clone)]
pub struct DriverConnectionRequest {
    pub request_id: u64,
    pub timestamp: u64,
    pub process_id: u32,
    pub protocol: u8,
    pub direction: u8,
    pub ip_version: u8,
    pub reserved: u8,
    pub local_address_v4: u32,
    pub remote_address_v4: u32,
    pub local_address_v6: [u8; 16],
    pub remote_address_v6: [u8; 16],
    pub local_port: u16,
    pub remote_port: u16,
    pub application_path: [u16; 260],
    pub application_path_length: u32,
    pub domain_name: [u16; 256],
    pub domain_name_length: u32,
}

/// Verdict response to send to kernel driver
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct DriverVerdictResponse {
    pub request_id: u64,
    pub verdict: u32,
    pub reserved: u32,
}

/// Driver statistics
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DriverStats {
    pub total_connections: u64,
    pub allowed_connections: u64,
    pub blocked_connections: u64,
    pub pending_requests: u64,
    pub timed_out_requests: u64,
    pub dropped_requests: u64,
}

/// Parsed connection request for user-mode processing
#[derive(Debug, Clone)]
pub struct ConnectionRequest {
    pub request_id: u64,
    pub timestamp: u64,
    pub process_id: u32,
    pub protocol: Protocol,
    pub direction: Direction,
    pub local_address: IpAddr,
    pub remote_address: IpAddr,
    pub local_port: u16,
    pub remote_port: u16,
    pub application_path: PathBuf,
    pub domain_name: Option<String>,
}

impl DriverConnectionRequest {
    /// Parse the raw driver request into a user-friendly format
    pub fn parse(&self) -> ConnectionRequest {
        // Copy packed fields to local variables to avoid unaligned access
        let protocol_byte = self.protocol;
        let direction_byte = self.direction;
        let ip_version = self.ip_version;
        let local_v4 = self.local_address_v4;
        let remote_v4 = self.remote_address_v4;
        let local_v6 = self.local_address_v6;
        let remote_v6 = self.remote_address_v6;
        let local_port = self.local_port;
        let remote_port = self.remote_port;
        let request_id = self.request_id;
        let timestamp = self.timestamp;
        let process_id = self.process_id;
        let app_path_len = self.application_path_length;
        let domain_len = self.domain_name_length;

        // Copy arrays to local buffers using raw pointer reads (avoiding references to packed fields)
        let mut app_path_buf = [0u16; 260];
        let mut domain_buf = [0u16; 256];
        unsafe {
            let app_ptr = std::ptr::addr_of!(self.application_path) as *const u16;
            let domain_ptr = std::ptr::addr_of!(self.domain_name) as *const u16;
            std::ptr::copy_nonoverlapping(app_ptr, app_path_buf.as_mut_ptr(), 260);
            std::ptr::copy_nonoverlapping(domain_ptr, domain_buf.as_mut_ptr(), 256);
        }

        let protocol = match protocol_byte {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 => Protocol::Icmp,
            _ => Protocol::Any,
        };

        let direction = match direction_byte {
            0 => Direction::Outbound,
            1 => Direction::Inbound,
            _ => Direction::Any,
        };

        let (local_address, remote_address) = if ip_version == 6 {
            (
                IpAddr::V6(Ipv6Addr::from(local_v6)),
                IpAddr::V6(Ipv6Addr::from(remote_v6)),
            )
        } else {
            (
                IpAddr::V4(Ipv4Addr::from(local_v4.to_be())),
                IpAddr::V4(Ipv4Addr::from(remote_v4.to_be())),
            )
        };

        let path_len = (app_path_len as usize).min(260);
        let application_path = if path_len > 0 {
            PathBuf::from(String::from_utf16_lossy(&app_path_buf[..path_len]))
        } else {
            PathBuf::new()
        };

        let domain_name_len = (domain_len as usize).min(256);
        let domain_name = if domain_name_len > 0 {
            Some(String::from_utf16_lossy(&domain_buf[..domain_name_len]))
        } else {
            None
        };

        ConnectionRequest {
            request_id,
            timestamp,
            process_id,
            protocol,
            direction,
            local_address,
            remote_address,
            local_port,
            remote_port,
            application_path,
            domain_name,
        }
    }
}

/// Handle to the kernel driver
pub struct DriverHandle {
    handle: HANDLE,
}

impl DriverHandle {
    /// Open a handle to the driver
    pub fn open() -> io::Result<Self> {
        let device_path: Vec<u16> = OsStr::new(DEVICE_PATH)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            CreateFileW(
                PCWSTR(device_path.as_ptr()),
                0x80000000 | 0x40000000, // GENERIC_READ | GENERIC_WRITE
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };

        match handle {
            Ok(h) if h != INVALID_HANDLE_VALUE => Ok(Self { handle: h }),
            Ok(_) => Err(io::Error::last_os_error()),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, format!("{}", e))),
        }
    }

    /// Check if the driver is available
    pub fn is_available() -> bool {
        Self::open().is_ok()
    }

    /// Enable filtering in the driver
    pub fn enable_filtering(&self) -> io::Result<()> {
        let mut bytes_returned = 0u32;
        let result = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_SERENO_ENABLE,
                None,
                0,
                None,
                0,
                Some(&mut bytes_returned),
                None,
            )
        };

        if result.is_ok() {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Disable filtering in the driver
    pub fn disable_filtering(&self) -> io::Result<()> {
        let mut bytes_returned = 0u32;
        let result = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_SERENO_DISABLE,
                None,
                0,
                None,
                0,
                Some(&mut bytes_returned),
                None,
            )
        };

        if result.is_ok() {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Get pending connection request from the driver
    pub fn get_pending_request(&self) -> io::Result<Option<DriverConnectionRequest>> {
        let mut request: DriverConnectionRequest = unsafe { mem::zeroed() };
        let mut bytes_returned = 0u32;

        let result = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_SERENO_GET_PENDING,
                None,
                0,
                Some(&mut request as *mut _ as *mut _),
                mem::size_of::<DriverConnectionRequest>() as u32,
                Some(&mut bytes_returned),
                None,
            )
        };

        if result.is_ok() {
            if bytes_returned >= mem::size_of::<DriverConnectionRequest>() as u32 {
                Ok(Some(request))
            } else {
                Ok(None)
            }
        } else {
            let err = io::Error::last_os_error();
            // ERROR_NO_MORE_ITEMS or similar means no pending requests
            if err.raw_os_error() == Some(259) {
                Ok(None)
            } else {
                Err(err)
            }
        }
    }

    /// Send verdict for a pending request
    pub fn set_verdict(&self, request_id: u64, verdict: DriverVerdict) -> io::Result<()> {
        let response = DriverVerdictResponse {
            request_id,
            verdict: verdict as u32,
            reserved: 0,
        };

        let mut bytes_returned = 0u32;

        let result = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_SERENO_SET_VERDICT,
                Some(&response as *const _ as *const _),
                mem::size_of::<DriverVerdictResponse>() as u32,
                None,
                0,
                Some(&mut bytes_returned),
                None,
            )
        };

        if result.is_ok() {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Get driver statistics
    pub fn get_stats(&self) -> io::Result<DriverStats> {
        let mut stats: DriverStats = unsafe { mem::zeroed() };
        let mut bytes_returned = 0u32;

        let result = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_SERENO_GET_STATS,
                None,
                0,
                Some(&mut stats as *mut _ as *mut _),
                mem::size_of::<DriverStats>() as u32,
                Some(&mut bytes_returned),
                None,
            )
        };

        if result.is_ok() {
            Ok(stats)
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl Drop for DriverHandle {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

// Make DriverHandle Send + Sync since HANDLE is just a pointer
unsafe impl Send for DriverHandle {}
unsafe impl Sync for DriverHandle {}

/// Driver communication service
pub struct DriverService {
    handle: Option<DriverHandle>,
}

impl DriverService {
    /// Create a new driver service
    pub fn new() -> Self {
        Self { handle: None }
    }

    /// Try to connect to the driver
    pub fn connect(&mut self) -> io::Result<()> {
        match DriverHandle::open() {
            Ok(handle) => {
                info!("Connected to SerenoFilter driver");
                self.handle = Some(handle);
                Ok(())
            }
            Err(e) => {
                warn!("Failed to connect to driver: {}", e);
                Err(e)
            }
        }
    }

    /// Check if connected to the driver
    pub fn is_connected(&self) -> bool {
        self.handle.is_some()
    }

    /// Enable filtering
    pub fn enable(&self) -> io::Result<()> {
        self.handle
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Not connected to driver"))?
            .enable_filtering()
    }

    /// Disable filtering
    pub fn disable(&self) -> io::Result<()> {
        self.handle
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Not connected to driver"))?
            .disable_filtering()
    }

    /// Get pending request
    pub fn get_pending(&self) -> io::Result<Option<ConnectionRequest>> {
        let handle = self
            .handle
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Not connected to driver"))?;

        match handle.get_pending_request()? {
            Some(raw) => Ok(Some(raw.parse())),
            None => Ok(None),
        }
    }

    /// Set verdict for a request
    pub fn set_verdict(&self, request_id: u64, allow: bool) -> io::Result<()> {
        let verdict = if allow {
            DriverVerdict::Allow
        } else {
            DriverVerdict::Block
        };

        self.handle
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Not connected to driver"))?
            .set_verdict(request_id, verdict)
    }

    /// Get statistics
    pub fn get_stats(&self) -> io::Result<DriverStats> {
        self.handle
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Not connected to driver"))?
            .get_stats()
    }
}

impl Default for DriverService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioctl_codes() {
        // Verify IOCTL codes calculated correctly
        // CTL_CODE(device_type, function, method, access) = (device_type << 16) | (access << 14) | (function << 2) | method
        // GET_PENDING: device=0x8000, func=0x801, method=0, access=1(READ)
        assert_eq!(IOCTL_SERENO_GET_PENDING, 0x80006004);
        // SET_VERDICT: device=0x8000, func=0x802, method=0, access=2(WRITE)
        assert_eq!(IOCTL_SERENO_SET_VERDICT, 0x8000A008);
    }

    #[test]
    fn test_driver_verdict_values() {
        assert_eq!(DriverVerdict::Pending as u32, 0);
        assert_eq!(DriverVerdict::Allow as u32, 1);
        assert_eq!(DriverVerdict::Block as u32, 2);
    }

    #[test]
    fn test_struct_sizes() {
        // Verify struct sizes match C definitions
        assert_eq!(mem::size_of::<DriverVerdictResponse>(), 16);
        assert_eq!(mem::size_of::<DriverStats>(), 48);
    }
}
