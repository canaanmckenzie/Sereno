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
    const IOCTL_SERENO_GET_BANDWIDTH: u32 = ctl_code(FILE_DEVICE_SERENO, 0x80A, METHOD_BUFFERED, FILE_READ_ACCESS);
    const IOCTL_SERENO_GET_FLOW_STATE: u32 = ctl_code(FILE_DEVICE_SERENO, 0x80B, METHOD_BUFFERED, FILE_READ_ACCESS);

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

    // ============================================================================
    // ICMP Notification Structures
    // ============================================================================

    const IOCTL_SERENO_GET_ICMP: u32 = ctl_code(FILE_DEVICE_SERENO, 0x80C, METHOD_BUFFERED, FILE_READ_ACCESS);

    /// Raw ICMP notification from kernel - matches SERENO_ICMP_NOTIFICATION in driver.h
    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct DriverIcmpNotification {
        pub timestamp: u64,
        pub process_id: u32,
        pub ip_version: u8,
        pub direction: u8,
        pub icmp_type: u8,
        pub icmp_code: u8,
        pub local_address_v4: u32,
        pub remote_address_v4: u32,
        pub local_address_v6: [u8; 16],
        pub remote_address_v6: [u8; 16],
        pub reserved: u32,
    }

    /// Parsed ICMP notification for usermode
    #[derive(Debug, Clone)]
    pub struct IcmpNotification {
        pub local_address: IpAddr,
        pub remote_address: IpAddr,
        pub direction: Direction,
        pub icmp_type: u8,
        pub icmp_code: u8,
    }

    impl DriverIcmpNotification {
        pub fn parse(&self) -> IcmpNotification {
            let ip_version = self.ip_version;
            let local_v4 = self.local_address_v4;
            let remote_v4 = self.remote_address_v4;
            let local_v6 = self.local_address_v6;
            let remote_v6 = self.remote_address_v6;
            let direction = if self.direction == 0 { Direction::Outbound } else { Direction::Inbound };
            let icmp_type = self.icmp_type;
            let icmp_code = self.icmp_code;

            let (local_address, remote_address) = if ip_version == 6 {
                (
                    IpAddr::V6(Ipv6Addr::from(local_v6)),
                    IpAddr::V6(Ipv6Addr::from(remote_v6)),
                )
            } else {
                let local_bytes = local_v4.to_be_bytes();
                let remote_bytes = remote_v4.to_be_bytes();
                (
                    IpAddr::V4(Ipv4Addr::new(local_bytes[0], local_bytes[1], local_bytes[2], local_bytes[3])),
                    IpAddr::V4(Ipv4Addr::new(remote_bytes[0], remote_bytes[1], remote_bytes[2], remote_bytes[3])),
                )
            };

            IcmpNotification {
                local_address,
                remote_address,
                direction,
                icmp_type,
                icmp_code,
            }
        }
    }

    // ============================================================================
    // TLM Bandwidth Statistics Structures
    // ============================================================================

    const BANDWIDTH_BATCH_SIZE: usize = 1024;

    /// Raw bandwidth entry from kernel - matches SERENO_BANDWIDTH_ENTRY in driver.h
    /// NOTE: Using repr(C) without packed to match C's natural alignment (8-byte aligned)
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct DriverBandwidthEntry {
        pub flow_handle: u64,
        pub bytes_sent: u64,
        pub bytes_received: u64,
        pub start_time: u64,
        pub last_activity: u64,
        pub timestamp: u64,         // For TTL expiration and LRU eviction
        pub process_id: u32,
        pub local_port: u16,
        pub remote_port: u16,
        pub local_address_v4: u32,
        pub remote_address_v4: u32,
        pub is_ipv6: u8,
        pub in_use: u8,
        // Padding to match C's 8-byte alignment (2 BOOLEANs + 6 bytes padding = 8 bytes)
        pub _padding: [u8; 6],
    }

    /// Raw bandwidth stats response from kernel - matches SERENO_BANDWIDTH_STATS in driver.h
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct DriverBandwidthStats {
        pub total_entries: u32,
        pub returned_count: u32,
        pub start_index: u32,
        pub reserved: u32,
        pub entries: [DriverBandwidthEntry; BANDWIDTH_BATCH_SIZE],
    }

    // Compile-time size assertions to catch struct mismatches
    // C sizes: SERENO_BANDWIDTH_ENTRY = 72 bytes, SERENO_BANDWIDTH_STATS = 73744 bytes (1024 entries)
    const _: () = assert!(std::mem::size_of::<DriverBandwidthEntry>() == 72);
    const _: () = assert!(std::mem::size_of::<DriverBandwidthStats>() == 73744);

    /// Parsed bandwidth entry for usermode
    #[derive(Debug, Clone)]
    pub struct BandwidthEntry {
        pub flow_handle: u64,
        pub bytes_sent: u64,
        pub bytes_received: u64,
        pub process_id: u32,
        pub local_port: u16,
        pub remote_port: u16,
        pub local_address: IpAddr,
        pub remote_address: IpAddr,
        pub is_ipv6: bool,
        /// Duration since connection started (in seconds)
        pub duration_secs: f64,
    }

    // ============================================================================
    // Connection State Tracking Structures
    // ============================================================================

    /// Connection state enum - matches SERENO_CONNECTION_STATE in driver.h
    #[repr(u8)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ConnectionState {
        Connecting = 0,
        Established = 1,
        Closed = 2,
    }

    impl From<u8> for ConnectionState {
        fn from(value: u8) -> Self {
            match value {
                0 => ConnectionState::Connecting,
                1 => ConnectionState::Established,
                2 => ConnectionState::Closed,
                _ => ConnectionState::Connecting,
            }
        }
    }

    /// Raw flow state notification from kernel - matches SERENO_FLOW_STATE_NOTIFICATION
    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct DriverFlowStateNotification {
        pub timestamp: u64,
        pub flow_handle: u64,
        pub process_id: u32,
        pub ip_version: u8,
        pub state: u8,
        pub direction: u8,
        pub protocol: u8,
        pub local_address_v4: u32,
        pub remote_address_v4: u32,
        pub local_address_v6: [u8; 16],
        pub remote_address_v6: [u8; 16],
        pub local_port: u16,
        pub remote_port: u16,
    }

    /// Parsed flow state notification for usermode
    #[derive(Debug, Clone)]
    pub struct FlowStateNotification {
        pub flow_handle: u64,
        pub process_id: u32,
        pub state: ConnectionState,
        pub direction: Direction,
        pub protocol: Protocol,
        pub local_address: IpAddr,
        pub remote_address: IpAddr,
        pub local_port: u16,
        pub remote_port: u16,
    }

    impl DriverFlowStateNotification {
        pub fn parse(&self) -> FlowStateNotification {
            let ip_version = self.ip_version;
            let local_v4 = self.local_address_v4;
            let remote_v4 = self.remote_address_v4;
            let local_v6 = self.local_address_v6;
            let remote_v6 = self.remote_address_v6;
            let local_port = self.local_port;
            let remote_port = self.remote_port;
            let flow_handle = self.flow_handle;
            let process_id = self.process_id;
            let state = ConnectionState::from(self.state);
            let direction = if self.direction == 0 { Direction::Outbound } else { Direction::Inbound };
            let protocol = Protocol::from_protocol_number(self.protocol);

            let (local_address, remote_address) = if ip_version == 6 {
                (
                    IpAddr::V6(Ipv6Addr::from(local_v6)),
                    IpAddr::V6(Ipv6Addr::from(remote_v6)),
                )
            } else {
                let local_bytes = local_v4.to_be_bytes();
                let remote_bytes = remote_v4.to_be_bytes();
                (
                    IpAddr::V4(Ipv4Addr::new(local_bytes[0], local_bytes[1], local_bytes[2], local_bytes[3])),
                    IpAddr::V4(Ipv4Addr::new(remote_bytes[0], remote_bytes[1], remote_bytes[2], remote_bytes[3])),
                )
            };

            FlowStateNotification {
                flow_handle,
                process_id,
                state,
                direction,
                protocol,
                local_address,
                remote_address,
                local_port,
                remote_port,
            }
        }
    }

    impl DriverBandwidthEntry {
        pub fn parse(&self) -> BandwidthEntry {
            let flow_handle = self.flow_handle;
            let bytes_sent = self.bytes_sent;
            let bytes_received = self.bytes_received;
            let start_time = self.start_time;
            let last_activity = self.last_activity;
            let process_id = self.process_id;
            let local_port = self.local_port;
            let remote_port = self.remote_port;
            let local_v4 = self.local_address_v4;
            let remote_v4 = self.remote_address_v4;
            let is_ipv6 = self.is_ipv6 != 0;

            // Calculate duration in seconds (start_time is in 100ns units)
            let duration_100ns = if last_activity > start_time {
                last_activity - start_time
            } else {
                0
            };
            let duration_secs = duration_100ns as f64 / 10_000_000.0;

            let (local_address, remote_address) = if is_ipv6 {
                // IPv6 addresses not stored in uint32 - use placeholder
                (IpAddr::V4(Ipv4Addr::UNSPECIFIED), IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            } else {
                // TLM stores IPs - extract bytes in big-endian order for correct display
                let local_bytes = local_v4.to_be_bytes();
                let remote_bytes = remote_v4.to_be_bytes();
                (
                    IpAddr::V4(Ipv4Addr::new(local_bytes[0], local_bytes[1], local_bytes[2], local_bytes[3])),
                    IpAddr::V4(Ipv4Addr::new(remote_bytes[0], remote_bytes[1], remote_bytes[2], remote_bytes[3])),
                )
            };

            BandwidthEntry {
                flow_handle,
                bytes_sent,
                bytes_received,
                process_id,
                local_port,
                remote_port,
                local_address,
                remote_address,
                is_ipv6,
                duration_secs,
            }
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

            let protocol = Protocol::from_protocol_number(protocol_byte);

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

        /// Get next ICMP notification from driver (ping, traceroute, etc.)
        /// NOTE: Requires driver rebuild with ICMP notification queue support
        pub fn get_icmp(&self) -> io::Result<Option<IcmpNotification>> {
            let mut notification: DriverIcmpNotification = unsafe { mem::zeroed() };
            let mut bytes_returned = 0u32;

            let result = unsafe {
                DeviceIoControl(
                    self.handle,
                    IOCTL_SERENO_GET_ICMP,
                    None,
                    0,
                    Some(&mut notification as *mut _ as *mut _),
                    mem::size_of::<DriverIcmpNotification>() as u32,
                    Some(&mut bytes_returned),
                    None,
                )
            };

            if result.is_ok() {
                if bytes_returned >= mem::size_of::<DriverIcmpNotification>() as u32 {
                    Ok(Some(notification.parse()))
                } else {
                    Ok(None)
                }
            } else {
                let err = io::Error::last_os_error();
                // STATUS_NO_MORE_ENTRIES or ERROR_NO_MORE_ITEMS
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

        /// Get bandwidth statistics from TLM layer
        /// Returns all active bandwidth entries from the kernel cache
        pub fn get_bandwidth_stats(&self) -> io::Result<Vec<BandwidthEntry>> {
            let mut stats: DriverBandwidthStats = unsafe { mem::zeroed() };
            let mut bytes_returned = 0u32;

            let result = unsafe {
                DeviceIoControl(
                    self.handle,
                    IOCTL_SERENO_GET_BANDWIDTH,
                    None,
                    0,
                    Some(&mut stats as *mut _ as *mut _),
                    mem::size_of::<DriverBandwidthStats>() as u32,
                    Some(&mut bytes_returned),
                    None,
                )
            };

            if result.is_err() {
                return Err(io::Error::last_os_error());
            }

            let mut entries = Vec::new();
            let count = stats.returned_count as usize;

            for i in 0..count {
                let raw_entry = &stats.entries[i];
                // Skip entries not in use
                if raw_entry.in_use != 0 {
                    entries.push(raw_entry.parse());
                }
            }

            Ok(entries)
        }

        /// Get next flow state notification from the driver queue
        pub fn get_flow_state(&self) -> io::Result<Option<FlowStateNotification>> {
            let mut notification: DriverFlowStateNotification = unsafe { mem::zeroed() };
            let mut bytes_returned = 0u32;

            let result = unsafe {
                DeviceIoControl(
                    self.handle,
                    IOCTL_SERENO_GET_FLOW_STATE,
                    None,
                    0,
                    Some(&mut notification as *mut _ as *mut _),
                    mem::size_of::<DriverFlowStateNotification>() as u32,
                    Some(&mut bytes_returned),
                    None,
                )
            };

            if result.is_err() {
                return Err(io::Error::last_os_error());
            }

            // If no data returned, queue was empty
            if bytes_returned == 0 {
                return Ok(None);
            }

            Ok(Some(notification.parse()))
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

    // ============================================================================
    // Port-to-Process Lookup (using Windows IP Helper API)
    // ============================================================================

    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable,
        TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    use windows::Win32::System::ProcessStatus::GetModuleBaseNameW;

    /// TCP connection entry with owner PID
    #[repr(C)]
    struct MIB_TCPROW_OWNER_PID {
        dw_state: u32,
        dw_local_addr: u32,
        dw_local_port: u32,
        dw_remote_addr: u32,
        dw_remote_port: u32,
        dw_owning_pid: u32,
    }

    /// TCP table header
    #[repr(C)]
    struct MIB_TCPTABLE_OWNER_PID {
        dw_num_entries: u32,
        table: [MIB_TCPROW_OWNER_PID; 1], // Variable length array
    }

    /// UDP connection entry with owner PID
    #[repr(C)]
    struct MIB_UDPROW_OWNER_PID {
        dw_local_addr: u32,
        dw_local_port: u32,
        dw_owning_pid: u32,
    }

    /// UDP table header
    #[repr(C)]
    struct MIB_UDPTABLE_OWNER_PID {
        dw_num_entries: u32,
        table: [MIB_UDPROW_OWNER_PID; 1], // Variable length array
    }

    /// Get process ID by local port (checks both TCP and UDP)
    pub fn get_pid_by_port(local_port: u16) -> Option<u32> {
        // Try TCP first
        if let Some(pid) = get_tcp_pid_by_port(local_port) {
            return Some(pid);
        }
        // Then try UDP
        get_udp_pid_by_port(local_port)
    }

    /// Get TCP connection's owning PID by local port
    fn get_tcp_pid_by_port(local_port: u16) -> Option<u32> {
        let mut size: u32 = 0;

        // First call to get required buffer size
        unsafe {
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                2u32, // AF_INET
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        }

        if size == 0 {
            return None;
        }

        // Allocate buffer
        let mut buffer: Vec<u8> = vec![0u8; size as usize];

        // Second call to get actual data
        let result = unsafe {
            GetExtendedTcpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                2u32, // AF_INET
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };

        if result != 0 {
            return None;
        }

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let num_entries = table.dw_num_entries as usize;

        // Search for matching local port
        let entries_ptr = &table.table as *const MIB_TCPROW_OWNER_PID;
        for i in 0..num_entries {
            let entry = unsafe { &*entries_ptr.add(i) };
            // Port is stored in network byte order (big endian) in the upper 16 bits
            let port = ((entry.dw_local_port & 0xFF) << 8) | ((entry.dw_local_port >> 8) & 0xFF);
            if port as u16 == local_port {
                return Some(entry.dw_owning_pid);
            }
        }

        None
    }

    /// Get UDP connection's owning PID by local port
    fn get_udp_pid_by_port(local_port: u16) -> Option<u32> {
        let mut size: u32 = 0;

        // First call to get required buffer size
        unsafe {
            let _ = GetExtendedUdpTable(
                None,
                &mut size,
                false,
                2u32, // AF_INET
                UDP_TABLE_OWNER_PID,
                0,
            );
        }

        if size == 0 {
            return None;
        }

        // Allocate buffer
        let mut buffer: Vec<u8> = vec![0u8; size as usize];

        // Second call to get actual data
        let result = unsafe {
            GetExtendedUdpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                2u32, // AF_INET
                UDP_TABLE_OWNER_PID,
                0,
            )
        };

        if result != 0 {
            return None;
        }

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
        let num_entries = table.dw_num_entries as usize;

        // Search for matching local port
        let entries_ptr = &table.table as *const MIB_UDPROW_OWNER_PID;
        for i in 0..num_entries {
            let entry = unsafe { &*entries_ptr.add(i) };
            let port = ((entry.dw_local_port & 0xFF) << 8) | ((entry.dw_local_port >> 8) & 0xFF);
            if port as u16 == local_port {
                return Some(entry.dw_owning_pid);
            }
        }

        None
    }

    /// Get process name by PID
    pub fn get_process_name_by_pid(pid: u32) -> Option<String> {
        if pid == 0 || pid == 4 {
            // System and System Idle Process
            return Some("System".to_string());
        }

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;

            let mut name_buffer = [0u16; 260];
            let len = GetModuleBaseNameW(handle, None, &mut name_buffer);

            let _ = CloseHandle(handle);

            if len > 0 {
                let name = String::from_utf16_lossy(&name_buffer[..len as usize]);
                Some(name)
            } else {
                None
            }
        }
    }
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

    /// Parsed bandwidth entry for usermode
    #[derive(Debug, Clone)]
    pub struct BandwidthEntry {
        pub flow_handle: u64,
        pub bytes_sent: u64,
        pub bytes_received: u64,
        pub process_id: u32,
        pub local_port: u16,
        pub remote_port: u16,
        pub local_address: IpAddr,
        pub remote_address: IpAddr,
        pub is_ipv6: bool,
        pub duration_secs: f64,
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

        pub fn get_bandwidth_stats(&self) -> io::Result<Vec<BandwidthEntry>> {
            Ok(Vec::new())
        }

        pub fn get_flow_state(&self) -> io::Result<Option<FlowStateNotification>> {
            Ok(None)
        }
    }

    /// Connection state enum - stub for non-Windows
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ConnectionState {
        Connecting,
        Established,
        Closed,
    }

    /// Flow state notification - stub for non-Windows
    #[derive(Debug, Clone)]
    pub struct FlowStateNotification {
        pub flow_handle: u64,
        pub process_id: u32,
        pub state: ConnectionState,
        pub direction: Direction,
        pub protocol: Protocol,
        pub local_address: IpAddr,
        pub remote_address: IpAddr,
        pub local_port: u16,
        pub remote_port: u16,
    }

    /// Stub: Get PID by local port (not available on non-Windows)
    pub fn get_pid_by_port(_local_port: u16) -> Option<u32> {
        None
    }

    /// Stub: Get process name by PID (not available on non-Windows)
    pub fn get_process_name_by_pid(_pid: u32) -> Option<String> {
        None
    }
}

#[cfg(not(windows))]
pub use stub::*;
