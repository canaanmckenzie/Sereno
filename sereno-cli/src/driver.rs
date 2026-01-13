//! Kernel driver communication for TUI
//!
//! Simplified driver communication for the interactive TUI.

#[cfg(windows)]
mod windows_impl {
    use sereno_core::types::{Direction, Protocol};
    use std::ffi::OsStr;
    use std::io;
    use std::mem;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::windows::ffi::OsStrExt;
    use std::path::PathBuf;

    use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;
    use windows::core::PCWSTR;

    const DEVICE_PATH: &str = r"\\.\SerenoFilter";
    const FILE_DEVICE_SERENO: u32 = 0x8000;

    const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
        (device_type << 16) | (access << 14) | (function << 2) | method
    }

    const METHOD_BUFFERED: u32 = 0;
    const FILE_READ_ACCESS: u32 = 1;
    const FILE_WRITE_ACCESS: u32 = 2;

    const IOCTL_SERENO_GET_PENDING: u32 = ctl_code(FILE_DEVICE_SERENO, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS);
    const IOCTL_SERENO_SET_VERDICT: u32 = ctl_code(FILE_DEVICE_SERENO, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS);
    const IOCTL_SERENO_ENABLE: u32 = ctl_code(FILE_DEVICE_SERENO, 0x805, METHOD_BUFFERED, FILE_WRITE_ACCESS);
    const IOCTL_SERENO_GET_SNI: u32 = ctl_code(FILE_DEVICE_SERENO, 0x807, METHOD_BUFFERED, FILE_READ_ACCESS);
    const IOCTL_SERENO_ADD_BLOCKED_DOMAIN: u32 = ctl_code(FILE_DEVICE_SERENO, 0x808, METHOD_BUFFERED, FILE_WRITE_ACCESS);
    const IOCTL_SERENO_CLEAR_BLOCKED_DOMAINS: u32 = ctl_code(FILE_DEVICE_SERENO, 0x809, METHOD_BUFFERED, FILE_WRITE_ACCESS);

    #[repr(u32)]
    #[derive(Debug, Clone, Copy)]
    pub enum DriverVerdict {
        Allow = 1,
        Block = 2,
    }

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

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct DriverVerdictResponse {
        pub request_id: u64,
        pub verdict: u32,
        pub reserved: u32,
    }

    /// Raw SNI notification from driver
    #[repr(C, packed)]
    #[derive(Clone)]
    pub struct DriverSniNotification {
        pub timestamp: u64,
        pub process_id: u32,
        pub ip_version: u8,
        pub reserved: [u8; 3],
        pub remote_address_v4: u32,
        pub remote_address_v6: [u8; 16],
        pub local_port: u16,
        pub remote_port: u16,
        pub domain_name: [u16; 256],
        pub domain_name_length: u32,
    }

    /// Parsed SNI notification
    #[derive(Debug, Clone)]
    pub struct SniNotification {
        pub remote_address: IpAddr,
        pub local_port: u16,
        pub remote_port: u16,
        pub domain: String,
    }

    /// Blocked domain request - sent to kernel to add domain to blocklist
    /// Must match C struct which is inside #pragma pack(push, 1)
    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct DriverBlockedDomainRequest {
        pub domain_name: [u16; 256],
        pub domain_name_length: u32,
    }

    impl DriverBlockedDomainRequest {
        pub fn new(domain: &str) -> Self {
            let mut request = Self {
                domain_name: [0u16; 256],
                domain_name_length: 0,
            };

            let chars: Vec<u16> = domain.encode_utf16().collect();
            let len = chars.len().min(255);

            // Copy using raw pointers to avoid unaligned reference issues with packed struct
            unsafe {
                let dst = std::ptr::addr_of_mut!(request.domain_name) as *mut u16;
                std::ptr::copy_nonoverlapping(chars.as_ptr(), dst, len);
            }
            request.domain_name_length = len as u32;

            request
        }
    }

    impl DriverSniNotification {
        pub fn parse(&self) -> SniNotification {
            let ip_version = self.ip_version;
            let remote_v4 = self.remote_address_v4;
            let remote_v6 = self.remote_address_v6;
            let local_port = self.local_port;
            let remote_port = self.remote_port;
            let domain_len = self.domain_name_length;

            let mut domain_buf = [0u16; 256];
            unsafe {
                let domain_ptr = std::ptr::addr_of!(self.domain_name) as *const u16;
                std::ptr::copy_nonoverlapping(domain_ptr, domain_buf.as_mut_ptr(), 256);
            }

            let remote_address = if ip_version == 6 {
                IpAddr::V6(Ipv6Addr::from(remote_v6))
            } else {
                IpAddr::V4(Ipv4Addr::from(u32::from_be(remote_v4)))
            };

            let domain_name_len = (domain_len as usize).min(256);
            let domain = String::from_utf16_lossy(&domain_buf[..domain_name_len]);

            SniNotification {
                remote_address,
                local_port,
                remote_port,
                domain,
            }
        }
    }

    /// Parsed connection request
    #[derive(Debug, Clone)]
    pub struct ConnectionRequest {
        pub request_id: u64,
        pub process_id: u32,
        pub process_name: String,
        pub process_path: PathBuf,
        pub protocol: Protocol,
        pub direction: Direction,
        pub remote_address: IpAddr,
        pub remote_port: u16,
        pub local_port: u16,
        pub domain: Option<String>,
    }

    impl DriverConnectionRequest {
        pub fn parse(&self) -> ConnectionRequest {
            let protocol_byte = self.protocol;
            let direction_byte = self.direction;
            let ip_version = self.ip_version;
            let remote_v4 = self.remote_address_v4;
            let remote_v6 = self.remote_address_v6;
            let local_port = self.local_port;
            let remote_port = self.remote_port;
            let request_id = self.request_id;
            let process_id = self.process_id;
            let app_path_len = self.application_path_length;
            let domain_len = self.domain_name_length;

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

            // WFP provides IPv4 addresses with raw bytes in memory (network byte order)
            // On little-endian systems, reading as uint32 gives byte-swapped value
            // Ipv4Addr::from(u32) expects native endian, so we need to swap back
            let remote_address = if ip_version == 6 {
                IpAddr::V6(Ipv6Addr::from(remote_v6))
            } else {
                // remote_v4 from WFP on LE is byte-swapped; swap to get correct IP
                IpAddr::V4(Ipv4Addr::from(u32::from_be(remote_v4)))
            };

            let path_len = (app_path_len as usize).min(260);
            let process_path = if path_len > 0 {
                PathBuf::from(String::from_utf16_lossy(&app_path_buf[..path_len]))
            } else {
                PathBuf::new()
            };

            let process_name = process_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("Unknown")
                .to_string();

            let domain_name_len = (domain_len as usize).min(256);
            let domain = if domain_name_len > 0 {
                Some(String::from_utf16_lossy(&domain_buf[..domain_name_len]))
            } else {
                None
            };

            ConnectionRequest {
                request_id,
                process_id,
                process_name,
                process_path,
                protocol,
                direction,
                remote_address,
                remote_port,
                local_port,
                domain,
            }
        }
    }

    pub struct DriverHandle {
        handle: HANDLE,
    }

    impl DriverHandle {
        pub fn open() -> io::Result<Self> {
            let device_path: Vec<u16> = OsStr::new(DEVICE_PATH)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let handle = unsafe {
                CreateFileW(
                    PCWSTR(device_path.as_ptr()),
                    0x80000000 | 0x40000000,
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

        pub fn is_available() -> bool {
            Self::open().is_ok()
        }

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

        pub fn get_pending(&self) -> io::Result<Option<ConnectionRequest>> {
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
                    Ok(Some(request.parse()))
                } else {
                    Ok(None)
                }
            } else {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(259) {
                    Ok(None)
                } else {
                    Err(err)
                }
            }
        }

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

        /// Get next SNI notification from driver (extracted from TLS ClientHello)
        pub fn get_sni(&self) -> io::Result<Option<SniNotification>> {
            let mut notification: DriverSniNotification = unsafe { mem::zeroed() };
            let mut bytes_returned = 0u32;

            let result = unsafe {
                DeviceIoControl(
                    self.handle,
                    IOCTL_SERENO_GET_SNI,
                    None,
                    0,
                    Some(&mut notification as *mut _ as *mut _),
                    mem::size_of::<DriverSniNotification>() as u32,
                    Some(&mut bytes_returned),
                    None,
                )
            };

            if result.is_ok() {
                if bytes_returned >= mem::size_of::<DriverSniNotification>() as u32 {
                    Ok(Some(notification.parse()))
                } else {
                    Ok(None)
                }
            } else {
                let err = io::Error::last_os_error();
                // STATUS_NO_MORE_ENTRIES = 0x8000001A = 2147483674 decimal
                // But Windows returns it as NTSTATUS which maps to error code 259 (ERROR_NO_MORE_ITEMS)
                // or raw NTSTATUS 0x8000001A
                if err.raw_os_error() == Some(259) || err.raw_os_error() == Some(0x1A) {
                    Ok(None)
                } else {
                    Err(err)
                }
            }
        }

        /// Add a domain to the kernel blocklist for SNI-based blocking
        pub fn add_blocked_domain(&self, domain: &str) -> io::Result<()> {
            let request = DriverBlockedDomainRequest::new(domain);
            let mut bytes_returned = 0u32;

            let result = unsafe {
                DeviceIoControl(
                    self.handle,
                    IOCTL_SERENO_ADD_BLOCKED_DOMAIN,
                    Some(&request as *const _ as *const _),
                    mem::size_of::<DriverBlockedDomainRequest>() as u32,
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

        /// Clear all blocked domains from the kernel blocklist
        pub fn clear_blocked_domains(&self) -> io::Result<()> {
            let mut bytes_returned = 0u32;

            let result = unsafe {
                DeviceIoControl(
                    self.handle,
                    IOCTL_SERENO_CLEAR_BLOCKED_DOMAINS,
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

    unsafe impl Send for DriverHandle {}
    unsafe impl Sync for DriverHandle {}
}

#[cfg(windows)]
pub use windows_impl::*;

#[cfg(not(windows))]
pub mod stub {
    use sereno_core::types::{Direction, Protocol};
    use std::io;
    use std::net::IpAddr;
    use std::path::PathBuf;

    #[derive(Debug, Clone, Copy)]
    pub enum DriverVerdict {
        Allow = 1,
        Block = 2,
    }

    #[derive(Debug, Clone)]
    pub struct ConnectionRequest {
        pub request_id: u64,
        pub process_id: u32,
        pub process_name: String,
        pub process_path: PathBuf,
        pub protocol: Protocol,
        pub direction: Direction,
        pub remote_address: IpAddr,
        pub remote_port: u16,
        pub local_port: u16,
        pub domain: Option<String>,
    }

    #[derive(Debug, Clone)]
    pub struct SniNotification {
        pub remote_address: IpAddr,
        pub local_port: u16,
        pub remote_port: u16,
        pub domain: String,
    }

    pub struct DriverHandle;

    impl DriverHandle {
        pub fn open() -> io::Result<Self> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "Windows only"))
        }

        pub fn is_available() -> bool {
            false
        }

        pub fn enable_filtering(&self) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "Windows only"))
        }

        pub fn get_pending(&self) -> io::Result<Option<ConnectionRequest>> {
            Ok(None)
        }

        pub fn set_verdict(&self, _request_id: u64, _verdict: DriverVerdict) -> io::Result<()> {
            Ok(())
        }

        pub fn get_sni(&self) -> io::Result<Option<SniNotification>> {
            Ok(None)
        }

        pub fn add_blocked_domain(&self, _domain: &str) -> io::Result<()> {
            Ok(())
        }

        pub fn clear_blocked_domains(&self) -> io::Result<()> {
            Ok(())
        }
    }
}

#[cfg(not(windows))]
pub use stub::*;
