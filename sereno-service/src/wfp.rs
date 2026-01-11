//! Windows Filtering Platform (WFP) integration for network monitoring and blocking
//!
//! This module provides:
//! - WFP engine management for filter registration
//! - Connection blocking via WFP filters at ALE layers
//! - Connection monitoring via IP Helper API
//! - Process identification with multiple fallback methods

use crate::process;
use crate::{ConnectionEvent, Verdict};
use sereno_core::types::{Direction, Protocol};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[cfg(windows)]
use windows::{
    core::{GUID, PWSTR},
    Win32::{
        Foundation::HANDLE,
        NetworkManagement::WindowsFilteringPlatform::*,
    },
};

static EVENT_ID: AtomicU64 = AtomicU64::new(1);
static FILTER_ID: AtomicU64 = AtomicU64::new(1);

/// GUID for our WFP provider
const SERENO_PROVIDER_GUID: GUID = GUID::from_values(
    0x53455245, // "SERE"
    0x4E4F,     // "NO"
    0x5746,     // "WF"
    [0x50, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
);

/// GUID for our WFP sublayer
const SERENO_SUBLAYER_GUID: GUID = GUID::from_values(
    0x53455245, // "SERE"
    0x4E4F,     // "NO"
    0x534C,     // "SL"
    [0x50, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
);

/// Filter action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterAction {
    Block,
    Permit,
}

/// Filter target specification
#[derive(Debug, Clone)]
pub enum FilterTarget {
    /// Block/allow specific IP address
    IpAddress(IpAddr),
    /// Block/allow IP range (CIDR)
    IpRange { addr: IpAddr, prefix_len: u8 },
    /// Block/allow specific port
    Port(u16),
    /// Block/allow port range
    PortRange { start: u16, end: u16 },
    /// Block/allow specific application by path
    Application(String),
    /// Block/allow specific domain (requires DNS inspection - advanced)
    Domain(String),
}

/// WFP Filter representation
#[derive(Debug, Clone)]
pub struct WfpFilter {
    pub id: u64,
    pub name: String,
    pub action: FilterAction,
    pub target: FilterTarget,
    pub protocol: Option<Protocol>,
    pub direction: Direction,
    /// WFP filter ID returned by the system
    pub wfp_filter_id: Option<u64>,
}

/// WFP Engine handle wrapper with filter management
pub struct WfpEngine {
    #[cfg(windows)]
    handle: HANDLE,
    running: Arc<AtomicBool>,
    /// Active filters (our ID -> WfpFilter)
    filters: Arc<Mutex<HashMap<u64, WfpFilter>>>,
    /// WFP filter IDs for cleanup
    wfp_filter_ids: Arc<Mutex<Vec<u64>>>,
}

impl WfpEngine {
    /// Open a new WFP engine session
    #[cfg(windows)]
    pub fn open() -> Result<Self, WfpError> {
        unsafe {
            let mut handle = HANDLE::default();

            let session = FWPM_SESSION0 {
                displayData: FWPM_DISPLAY_DATA0 {
                    name: PWSTR::null(),
                    description: PWSTR::null(),
                },
                flags: FWPM_SESSION_FLAG_DYNAMIC,
                txnWaitTimeoutInMSec: 0,
                ..Default::default()
            };

            let result = FwpmEngineOpen0(
                None,
                0u32,
                None,
                Some(&session),
                &mut handle,
            );

            if result != 0 {
                return Err(WfpError::EngineOpen(result));
            }

            Ok(Self {
                handle,
                running: Arc::new(AtomicBool::new(true)),
                filters: Arc::new(Mutex::new(HashMap::new())),
                wfp_filter_ids: Arc::new(Mutex::new(Vec::new())),
            })
        }
    }

    #[cfg(not(windows))]
    pub fn open() -> Result<Self, WfpError> {
        Err(WfpError::NotSupported)
    }

    /// Get the engine handle
    #[cfg(windows)]
    pub fn handle(&self) -> HANDLE {
        self.handle
    }

    /// Register our provider and sublayer
    #[cfg(windows)]
    pub fn register_provider(&self) -> Result<(), WfpError> {
        unsafe {
            // Start a transaction
            let result = FwpmTransactionBegin0(self.handle, 0);
            if result != 0 {
                warn!("Transaction begin failed: 0x{:08X}", result);
            }

            let name: Vec<u16> = "Sereno Firewall\0".encode_utf16().collect();
            let desc: Vec<u16> = "Sereno Network Monitor Provider\0".encode_utf16().collect();

            let provider = FWPM_PROVIDER0 {
                providerKey: SERENO_PROVIDER_GUID,
                displayData: FWPM_DISPLAY_DATA0 {
                    name: PWSTR::from_raw(name.as_ptr() as *mut _),
                    description: PWSTR::from_raw(desc.as_ptr() as *mut _),
                },
                flags: FWPM_PROVIDER_FLAG_PERSISTENT,
                ..Default::default()
            };

            let result = FwpmProviderAdd0(self.handle, &provider, None);
            // 0x80320009 = FWP_E_ALREADY_EXISTS
            if result != 0 && result != 0x80320009 {
                warn!("Provider add returned: 0x{:08X}", result);
            }

            let sublayer_name: Vec<u16> = "Sereno Sublayer\0".encode_utf16().collect();
            let sublayer_desc: Vec<u16> = "Sereno Filtering Sublayer\0".encode_utf16().collect();
            let mut provider_key = SERENO_PROVIDER_GUID;

            let sublayer = FWPM_SUBLAYER0 {
                subLayerKey: SERENO_SUBLAYER_GUID,
                displayData: FWPM_DISPLAY_DATA0 {
                    name: PWSTR::from_raw(sublayer_name.as_ptr() as *mut _),
                    description: PWSTR::from_raw(sublayer_desc.as_ptr() as *mut _),
                },
                flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
                providerKey: &mut provider_key as *mut _,
                weight: 0x8000, // High priority
                ..Default::default()
            };

            let result = FwpmSubLayerAdd0(self.handle, &sublayer, None);
            if result != 0 && result != 0x80320009 {
                warn!("Sublayer add returned: 0x{:08X}", result);
            }

            // Commit transaction
            let result = FwpmTransactionCommit0(self.handle);
            if result != 0 {
                warn!("Transaction commit failed: 0x{:08X}", result);
            }

            Ok(())
        }
    }

    #[cfg(not(windows))]
    pub fn register_provider(&self) -> Result<(), WfpError> {
        Err(WfpError::NotSupported)
    }

    /// Add a blocking filter for an IP address
    #[cfg(windows)]
    pub fn add_ip_block_filter(&self, ip: IpAddr, direction: Direction) -> Result<u64, WfpError> {
        let filter = WfpFilter {
            id: FILTER_ID.fetch_add(1, Ordering::SeqCst),
            name: format!("Block IP {}", ip),
            action: FilterAction::Block,
            target: FilterTarget::IpAddress(ip),
            protocol: None,
            direction,
            wfp_filter_id: None,
        };

        self.add_filter(filter)
    }

    /// Add a blocking filter for a port
    #[cfg(windows)]
    pub fn add_port_block_filter(&self, port: u16, protocol: Protocol, direction: Direction) -> Result<u64, WfpError> {
        let filter = WfpFilter {
            id: FILTER_ID.fetch_add(1, Ordering::SeqCst),
            name: format!("Block Port {}", port),
            action: FilterAction::Block,
            target: FilterTarget::Port(port),
            protocol: Some(protocol),
            direction,
            wfp_filter_id: None,
        };

        self.add_filter(filter)
    }

    /// Add a WFP filter
    #[cfg(windows)]
    pub fn add_filter(&self, mut filter: WfpFilter) -> Result<u64, WfpError> {
        unsafe {
            let filter_name: Vec<u16> = format!("{}\0", filter.name).encode_utf16().collect();
            let filter_desc: Vec<u16> = "Sereno filter\0".encode_utf16().collect();

            // Determine which WFP layer to use based on direction
            let layer_key = match filter.direction {
                Direction::Outbound => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                Direction::Inbound => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                Direction::Any => FWPM_LAYER_ALE_AUTH_CONNECT_V4, // Default to outbound for Any
            };

            // Build conditions based on filter target
            let mut conditions: Vec<FWPM_FILTER_CONDITION0> = Vec::new();

            // Storage for condition values (must outlive the API call)
            let mut ip_value: FWP_V4_ADDR_AND_MASK = Default::default();
            let mut ip6_value: FWP_V6_ADDR_AND_MASK = Default::default();
            let mut port_value: u16 = 0;
            let mut port_range: FWP_RANGE0 = Default::default();
            let mut port_start: FWP_VALUE0 = Default::default();
            let mut port_end: FWP_VALUE0 = Default::default();

            match &filter.target {
                FilterTarget::IpAddress(ip) => {
                    match ip {
                        IpAddr::V4(v4) => {
                            ip_value.addr = u32::from_be_bytes(v4.octets());
                            ip_value.mask = 0xFFFFFFFF;

                            conditions.push(FWPM_FILTER_CONDITION0 {
                                fieldKey: if filter.direction == Direction::Outbound {
                                    FWPM_CONDITION_IP_REMOTE_ADDRESS
                                } else {
                                    FWPM_CONDITION_IP_LOCAL_ADDRESS
                                },
                                matchType: FWP_MATCH_EQUAL,
                                conditionValue: FWP_CONDITION_VALUE0 {
                                    r#type: FWP_V4_ADDR_MASK,
                                    Anonymous: FWP_CONDITION_VALUE0_0 {
                                        v4AddrMask: &ip_value as *const _ as *mut _,
                                    },
                                },
                            });
                        }
                        IpAddr::V6(v6) => {
                            ip6_value.addr = v6.octets();
                            ip6_value.prefixLength = 128;

                            conditions.push(FWPM_FILTER_CONDITION0 {
                                fieldKey: if filter.direction == Direction::Outbound {
                                    FWPM_CONDITION_IP_REMOTE_ADDRESS
                                } else {
                                    FWPM_CONDITION_IP_LOCAL_ADDRESS
                                },
                                matchType: FWP_MATCH_EQUAL,
                                conditionValue: FWP_CONDITION_VALUE0 {
                                    r#type: FWP_V6_ADDR_MASK,
                                    Anonymous: FWP_CONDITION_VALUE0_0 {
                                        v6AddrMask: &ip6_value as *const _ as *mut _,
                                    },
                                },
                            });
                        }
                    }
                }
                FilterTarget::IpRange { addr, prefix_len } => {
                    match addr {
                        IpAddr::V4(v4) => {
                            ip_value.addr = u32::from_be_bytes(v4.octets());
                            ip_value.mask = if *prefix_len >= 32 {
                                0xFFFFFFFF
                            } else {
                                0xFFFFFFFFu32 << (32 - prefix_len)
                            };

                            conditions.push(FWPM_FILTER_CONDITION0 {
                                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                                matchType: FWP_MATCH_EQUAL,
                                conditionValue: FWP_CONDITION_VALUE0 {
                                    r#type: FWP_V4_ADDR_MASK,
                                    Anonymous: FWP_CONDITION_VALUE0_0 {
                                        v4AddrMask: &ip_value as *const _ as *mut _,
                                    },
                                },
                            });
                        }
                        IpAddr::V6(v6) => {
                            ip6_value.addr = v6.octets();
                            ip6_value.prefixLength = *prefix_len;

                            conditions.push(FWPM_FILTER_CONDITION0 {
                                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                                matchType: FWP_MATCH_EQUAL,
                                conditionValue: FWP_CONDITION_VALUE0 {
                                    r#type: FWP_V6_ADDR_MASK,
                                    Anonymous: FWP_CONDITION_VALUE0_0 {
                                        v6AddrMask: &ip6_value as *const _ as *mut _,
                                    },
                                },
                            });
                        }
                    }
                }
                FilterTarget::Port(port) => {
                    port_value = *port;
                    conditions.push(FWPM_FILTER_CONDITION0 {
                        fieldKey: if filter.direction == Direction::Outbound {
                            FWPM_CONDITION_IP_REMOTE_PORT
                        } else {
                            FWPM_CONDITION_IP_LOCAL_PORT
                        },
                        matchType: FWP_MATCH_EQUAL,
                        conditionValue: FWP_CONDITION_VALUE0 {
                            r#type: FWP_UINT16,
                            Anonymous: FWP_CONDITION_VALUE0_0 {
                                uint16: port_value,
                            },
                        },
                    });
                }
                FilterTarget::PortRange { start, end } => {
                    port_start = FWP_VALUE0 {
                        r#type: FWP_UINT16,
                        Anonymous: FWP_VALUE0_0 { uint16: *start },
                    };
                    port_end = FWP_VALUE0 {
                        r#type: FWP_UINT16,
                        Anonymous: FWP_VALUE0_0 { uint16: *end },
                    };
                    port_range = FWP_RANGE0 {
                        valueLow: port_start,
                        valueHigh: port_end,
                    };

                    conditions.push(FWPM_FILTER_CONDITION0 {
                        fieldKey: if filter.direction == Direction::Outbound {
                            FWPM_CONDITION_IP_REMOTE_PORT
                        } else {
                            FWPM_CONDITION_IP_LOCAL_PORT
                        },
                        matchType: FWP_MATCH_RANGE,
                        conditionValue: FWP_CONDITION_VALUE0 {
                            r#type: FWP_RANGE_TYPE,
                            Anonymous: FWP_CONDITION_VALUE0_0 {
                                rangeValue: &port_range as *const _ as *mut _,
                            },
                        },
                    });
                }
                FilterTarget::Application(_path) => {
                    // Application filtering requires more complex setup with app ID
                    // For now, log and skip
                    warn!("Application-based filtering not yet implemented");
                }
                FilterTarget::Domain(_domain) => {
                    // Domain filtering requires DNS inspection or callout driver
                    warn!("Domain-based filtering requires callout driver");
                }
            }

            // Add protocol condition if specified (skip for Any)
            let protocol_value: u8;
            if let Some(proto) = filter.protocol {
                if proto != Protocol::Any {
                    protocol_value = match proto {
                        Protocol::Tcp => 6,
                        Protocol::Udp => 17,
                        Protocol::Icmp => 1,
                        Protocol::Any => unreachable!(),
                    };
                    conditions.push(FWPM_FILTER_CONDITION0 {
                        fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                        matchType: FWP_MATCH_EQUAL,
                        conditionValue: FWP_CONDITION_VALUE0 {
                            r#type: FWP_UINT8,
                            Anonymous: FWP_CONDITION_VALUE0_0 {
                                uint8: protocol_value,
                            },
                        },
                    });
                }
            }

            if conditions.is_empty() {
                return Err(WfpError::InvalidFilter("No valid conditions".to_string()));
            }

            let action_type = match filter.action {
                FilterAction::Block => FWP_ACTION_BLOCK,
                FilterAction::Permit => FWP_ACTION_PERMIT,
            };

            let mut sublayer_key = SERENO_SUBLAYER_GUID;
            let mut provider_key = SERENO_PROVIDER_GUID;

            let wfp_filter = FWPM_FILTER0 {
                filterKey: GUID::zeroed(), // Let WFP assign
                displayData: FWPM_DISPLAY_DATA0 {
                    name: PWSTR::from_raw(filter_name.as_ptr() as *mut _),
                    description: PWSTR::from_raw(filter_desc.as_ptr() as *mut _),
                },
                flags: FWPM_FILTER_FLAGS(0),
                providerKey: &mut provider_key as *mut _,
                layerKey: layer_key,
                subLayerKey: sublayer_key,
                weight: FWP_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_VALUE0_0 { uint8: 15 }, // High weight
                },
                numFilterConditions: conditions.len() as u32,
                filterCondition: conditions.as_ptr() as *mut _,
                action: FWPM_ACTION0 {
                    r#type: action_type,
                    Anonymous: FWPM_ACTION0_0 {
                        filterType: GUID::zeroed(),
                    },
                },
                ..Default::default()
            };

            let mut wfp_filter_id: u64 = 0;
            let result = FwpmFilterAdd0(
                self.handle,
                &wfp_filter,
                None,
                Some(&mut wfp_filter_id),
            );

            if result != 0 {
                return Err(WfpError::FilterAdd(result));
            }

            filter.wfp_filter_id = Some(wfp_filter_id);
            let our_id = filter.id;

            // Store filter
            {
                let mut filters = self.filters.lock();
                filters.insert(our_id, filter);
            }
            {
                let mut wfp_ids = self.wfp_filter_ids.lock();
                wfp_ids.push(wfp_filter_id);
            }

            info!("Added WFP filter {} (WFP ID: {})", our_id, wfp_filter_id);
            Ok(our_id)
        }
    }

    /// Remove a filter by our ID
    #[cfg(windows)]
    pub fn remove_filter(&self, filter_id: u64) -> Result<(), WfpError> {
        let wfp_id = {
            let mut filters = self.filters.lock();
            filters.remove(&filter_id).and_then(|f| f.wfp_filter_id)
        };

        if let Some(wfp_filter_id) = wfp_id {
            unsafe {
                let result = FwpmFilterDeleteById0(self.handle, wfp_filter_id);
                if result != 0 && result != 0x80320002 { // FWP_E_FILTER_NOT_FOUND
                    return Err(WfpError::FilterRemove(result));
                }
            }

            let mut wfp_ids = self.wfp_filter_ids.lock();
            wfp_ids.retain(|&id| id != wfp_filter_id);

            info!("Removed WFP filter {} (WFP ID: {})", filter_id, wfp_filter_id);
        }

        Ok(())
    }

    /// Remove all filters
    #[cfg(windows)]
    pub fn remove_all_filters(&self) {
        let wfp_ids: Vec<u64> = {
            let mut filters = self.filters.lock();
            let ids: Vec<u64> = filters.values()
                .filter_map(|f| f.wfp_filter_id)
                .collect();
            filters.clear();
            ids
        };

        for wfp_id in wfp_ids {
            unsafe {
                let _ = FwpmFilterDeleteById0(self.handle, wfp_id);
            }
        }

        let mut wfp_filter_ids = self.wfp_filter_ids.lock();
        wfp_filter_ids.clear();

        info!("Removed all WFP filters");
    }

    /// Get active filter count
    pub fn filter_count(&self) -> usize {
        self.filters.lock().len()
    }

    /// List active filters
    pub fn list_filters(&self) -> Vec<WfpFilter> {
        self.filters.lock().values().cloned().collect()
    }

    #[allow(dead_code)]
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        #[cfg(windows)]
        self.remove_all_filters();
    }

    #[cfg(not(windows))]
    pub fn add_filter(&self, _filter: WfpFilter) -> Result<u64, WfpError> {
        Err(WfpError::NotSupported)
    }

    #[cfg(not(windows))]
    pub fn remove_filter(&self, _filter_id: u64) -> Result<(), WfpError> {
        Err(WfpError::NotSupported)
    }

    #[cfg(not(windows))]
    pub fn add_ip_block_filter(&self, _ip: IpAddr, _direction: Direction) -> Result<u64, WfpError> {
        Err(WfpError::NotSupported)
    }

    #[cfg(not(windows))]
    pub fn add_port_block_filter(&self, _port: u16, _protocol: Protocol, _direction: Direction) -> Result<u64, WfpError> {
        Err(WfpError::NotSupported)
    }

    #[cfg(not(windows))]
    pub fn remove_all_filters(&self) {}
}

#[cfg(windows)]
impl Drop for WfpEngine {
    fn drop(&mut self) {
        self.remove_all_filters();
        unsafe {
            if !self.handle.is_invalid() {
                let _ = FwpmEngineClose0(self.handle);
            }
        }
    }
}

#[cfg(not(windows))]
impl Drop for WfpEngine {
    fn drop(&mut self) {}
}

#[derive(Debug)]
pub enum WfpError {
    EngineOpen(u32),
    ProviderAdd(u32),
    FilterAdd(u32),
    FilterRemove(u32),
    InvalidFilter(String),
    NotSupported,
}

impl std::fmt::Display for WfpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WfpError::EngineOpen(code) => {
                let msg = match *code {
                    0x32 => "Access denied (run as Administrator)",
                    0x5 => "Access denied",
                    _ => "Unknown error",
                };
                write!(f, "{} (0x{:08X})", msg, code)
            }
            WfpError::ProviderAdd(code) => write!(f, "Provider add failed: 0x{:08X}", code),
            WfpError::FilterAdd(code) => {
                let msg = match *code {
                    0x80320009 => "Filter already exists",
                    0x80320003 => "Invalid parameter",
                    _ => "Unknown error",
                };
                write!(f, "Filter add failed: {} (0x{:08X})", msg, code)
            }
            WfpError::FilterRemove(code) => write!(f, "Filter remove failed: 0x{:08X}", code),
            WfpError::InvalidFilter(msg) => write!(f, "Invalid filter: {}", msg),
            WfpError::NotSupported => write!(f, "WFP not supported on this platform"),
        }
    }
}

impl std::error::Error for WfpError {}

/// Connection blocking manager
/// Handles real-time blocking decisions using WFP filters
pub struct BlockingManager {
    engine: Arc<WfpEngine>,
    /// Blocked IPs -> filter ID
    blocked_ips: Arc<Mutex<HashMap<IpAddr, u64>>>,
    /// Blocked ports -> filter ID
    blocked_ports: Arc<Mutex<HashMap<(u16, Protocol), u64>>>,
}

impl BlockingManager {
    pub fn new(engine: Arc<WfpEngine>) -> Self {
        Self {
            engine,
            blocked_ips: Arc::new(Mutex::new(HashMap::new())),
            blocked_ports: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Block an IP address
    pub fn block_ip(&self, ip: IpAddr) -> Result<(), WfpError> {
        let mut blocked = self.blocked_ips.lock();
        if blocked.contains_key(&ip) {
            return Ok(()); // Already blocked
        }

        let filter_id = self.engine.add_ip_block_filter(ip, Direction::Outbound)?;
        blocked.insert(ip, filter_id);
        info!("Blocked IP: {}", ip);
        Ok(())
    }

    /// Unblock an IP address
    pub fn unblock_ip(&self, ip: IpAddr) -> Result<(), WfpError> {
        let mut blocked = self.blocked_ips.lock();
        if let Some(filter_id) = blocked.remove(&ip) {
            self.engine.remove_filter(filter_id)?;
            info!("Unblocked IP: {}", ip);
        }
        Ok(())
    }

    /// Block a port
    pub fn block_port(&self, port: u16, protocol: Protocol) -> Result<(), WfpError> {
        let key = (port, protocol);
        let mut blocked = self.blocked_ports.lock();
        if blocked.contains_key(&key) {
            return Ok(());
        }

        let filter_id = self.engine.add_port_block_filter(port, protocol, Direction::Outbound)?;
        blocked.insert(key, filter_id);
        info!("Blocked port: {} {:?}", port, protocol);
        Ok(())
    }

    /// Unblock a port
    pub fn unblock_port(&self, port: u16, protocol: Protocol) -> Result<(), WfpError> {
        let key = (port, protocol);
        let mut blocked = self.blocked_ports.lock();
        if let Some(filter_id) = blocked.remove(&key) {
            self.engine.remove_filter(filter_id)?;
            info!("Unblocked port: {} {:?}", port, protocol);
        }
        Ok(())
    }

    /// Get blocked IP count
    pub fn blocked_ip_count(&self) -> usize {
        self.blocked_ips.lock().len()
    }

    /// Get blocked port count
    pub fn blocked_port_count(&self) -> usize {
        self.blocked_ports.lock().len()
    }

    /// Clear all blocks
    pub fn clear_all(&self) {
        {
            let mut blocked = self.blocked_ips.lock();
            for (_, filter_id) in blocked.drain() {
                let _ = self.engine.remove_filter(filter_id);
            }
        }
        {
            let mut blocked = self.blocked_ports.lock();
            for (_, filter_id) in blocked.drain() {
                let _ = self.engine.remove_filter(filter_id);
            }
        }
        info!("Cleared all blocks");
    }
}

/// Monitor network connections using Windows IP Helper API
pub struct ConnectionMonitor {
    running: Arc<AtomicBool>,
}

impl ConnectionMonitor {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    #[cfg(windows)]
    pub async fn run(
        &self,
        event_tx: mpsc::Sender<ConnectionEvent>,
        mut verdict_rx: mpsc::Receiver<(u64, Verdict)>,
    ) -> anyhow::Result<()> {
        info!("Connection monitor started");

        let mut seen_connections: HashSet<String> = HashSet::new();

        // Verdict handler
        let running = self.running.clone();
        tokio::spawn(async move {
            while running.load(Ordering::SeqCst) {
                if let Some((id, verdict)) = verdict_rx.recv().await {
                    debug!("Verdict for connection {}: {:?}", id, verdict);
                }
            }
        });

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(250));

        while self.running.load(Ordering::SeqCst) {
            interval.tick().await;

            // Get TCP connections
            if let Ok(connections) = self.get_tcp_connections().await {
                for conn in connections {
                    let key = format!(
                        "tcp:{}:{}:{}:{}",
                        conn.local_address, conn.local_port, conn.remote_address, conn.remote_port
                    );

                    if !seen_connections.contains(&key)
                        && conn.remote_port != 0
                        && !conn.remote_address.is_unspecified()
                    {
                        seen_connections.insert(key);

                        let (process_path, process_name, publisher) =
                            process::get_process_info(conn.process_id)
                                .map(|p| (p.path, p.name, p.publisher))
                                .unwrap_or_else(|| {
                                    (format!("PID:{}", conn.process_id), format!("pid:{}", conn.process_id), None)
                                });

                        let event = ConnectionEvent {
                            id: EVENT_ID.fetch_add(1, Ordering::SeqCst),
                            process_path,
                            process_name,
                            process_id: conn.process_id,
                            publisher,
                            remote_address: conn.remote_address,
                            remote_port: conn.remote_port,
                            local_port: conn.local_port,
                            protocol: Protocol::Tcp,
                            direction: Direction::Outbound,
                            domain: None,
                        };

                        if event_tx.send(event).await.is_err() {
                            break;
                        }
                    }
                }
            }

            // Get UDP connections
            if let Ok(connections) = self.get_udp_connections().await {
                for conn in connections {
                    // UDP is connectionless, but we can track local bindings
                    let key = format!("udp:{}:{}", conn.local_address, conn.local_port);

                    if !seen_connections.contains(&key) && conn.local_port != 0 {
                        seen_connections.insert(key);

                        let (process_path, process_name, publisher) =
                            process::get_process_info(conn.process_id)
                                .map(|p| (p.path, p.name, p.publisher))
                                .unwrap_or_else(|| {
                                    (format!("PID:{}", conn.process_id), format!("pid:{}", conn.process_id), None)
                                });

                        // UDP doesn't have remote address until packet is sent
                        // We log local bindings for awareness
                        debug!("UDP binding: {} {} on port {}", process_name, process_path, conn.local_port);
                    }
                }
            }

            // Cleanup seen connections periodically
            if seen_connections.len() > 5000 {
                seen_connections.clear();
            }
        }

        info!("Connection monitor stopped");
        Ok(())
    }

    #[cfg(windows)]
    async fn get_tcp_connections(&self) -> anyhow::Result<Vec<TcpConnection>> {
        use windows::Win32::NetworkManagement::IpHelper::*;

        let mut connections = Vec::new();

        unsafe {
            let mut size: u32 = 0;
            GetExtendedTcpTable(
                None,
                &mut size,
                false,
                2, // AF_INET
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if size == 0 {
                return Ok(connections);
            }

            let mut buffer = vec![0u8; size as usize];
            let result = GetExtendedTcpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                2,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if result != 0 {
                return Ok(connections);
            }

            let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let entries = std::slice::from_raw_parts(
                table.table.as_ptr(),
                table.dwNumEntries as usize,
            );

            for entry in entries {
                // Track established connections (state 5)
                if entry.dwState == 5 {
                    let local_addr = Ipv4Addr::from(entry.dwLocalAddr.to_ne_bytes());
                    let remote_addr = Ipv4Addr::from(entry.dwRemoteAddr.to_ne_bytes());
                    let local_port = u16::from_be(entry.dwLocalPort as u16);
                    let remote_port = u16::from_be(entry.dwRemotePort as u16);

                    connections.push(TcpConnection {
                        local_address: IpAddr::V4(local_addr),
                        local_port,
                        remote_address: IpAddr::V4(remote_addr),
                        remote_port,
                        process_id: entry.dwOwningPid,
                    });
                }
            }
        }

        Ok(connections)
    }

    #[cfg(windows)]
    async fn get_udp_connections(&self) -> anyhow::Result<Vec<UdpBinding>> {
        use windows::Win32::NetworkManagement::IpHelper::*;

        let mut bindings = Vec::new();

        unsafe {
            let mut size: u32 = 0;
            GetExtendedUdpTable(
                None,
                &mut size,
                false,
                2, // AF_INET
                UDP_TABLE_OWNER_PID,
                0,
            );

            if size == 0 {
                return Ok(bindings);
            }

            let mut buffer = vec![0u8; size as usize];
            let result = GetExtendedUdpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                2,
                UDP_TABLE_OWNER_PID,
                0,
            );

            if result != 0 {
                return Ok(bindings);
            }

            let table = &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
            let entries = std::slice::from_raw_parts(
                table.table.as_ptr(),
                table.dwNumEntries as usize,
            );

            for entry in entries {
                let local_addr = Ipv4Addr::from(entry.dwLocalAddr.to_ne_bytes());
                let local_port = u16::from_be(entry.dwLocalPort as u16);

                bindings.push(UdpBinding {
                    local_address: IpAddr::V4(local_addr),
                    local_port,
                    process_id: entry.dwOwningPid,
                });
            }
        }

        Ok(bindings)
    }

    #[cfg(not(windows))]
    pub async fn run(
        &self,
        _event_tx: mpsc::Sender<ConnectionEvent>,
        _verdict_rx: mpsc::Receiver<(u64, Verdict)>,
    ) -> anyhow::Result<()> {
        warn!("Connection monitoring not supported on this platform");
        Ok(())
    }

    #[allow(dead_code)]
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

struct TcpConnection {
    local_address: IpAddr,
    local_port: u16,
    remote_address: IpAddr,
    remote_port: u16,
    process_id: u32,
}

struct UdpBinding {
    local_address: IpAddr,
    local_port: u16,
    process_id: u32,
}
