//! TUI Application State

use sereno_core::types::Rule;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

/// Active tab in the TUI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Monitor,
    Flows,
    Rules,
    Logs,
    Settings,
}

impl Tab {
    pub fn next(self) -> Self {
        match self {
            Tab::Monitor => Tab::Flows,
            Tab::Flows => Tab::Rules,
            Tab::Rules => Tab::Logs,
            Tab::Logs => Tab::Settings,
            Tab::Settings => Tab::Monitor,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Tab::Monitor => Tab::Settings,
            Tab::Flows => Tab::Monitor,
            Tab::Rules => Tab::Flows,
            Tab::Logs => Tab::Rules,
            Tab::Settings => Tab::Logs,
        }
    }

    pub fn all() -> [Tab; 5] {
        [Tab::Monitor, Tab::Flows, Tab::Rules, Tab::Logs, Tab::Settings]
    }

    pub fn label(self) -> &'static str {
        match self {
            Tab::Monitor => "Monitor",
            Tab::Flows => "Flows",
            Tab::Rules => "Rules",
            Tab::Logs => "Logs",
            Tab::Settings => "Settings",
        }
    }

    pub fn key(self) -> char {
        match self {
            Tab::Monitor => '1',
            Tab::Flows => '2',
            Tab::Rules => '3',
            Tab::Logs => '4',
            Tab::Settings => '5',
        }
    }
}

/// A network flow tracked by TLM (Transport Layer Module)
#[derive(Debug, Clone)]
pub struct Flow {
    pub flow_handle: u64,
    pub process_id: u32,
    pub process_name: String,
    pub local_address: IpAddr,
    pub local_port: u16,
    pub remote_address: IpAddr,
    pub remote_port: u16,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub duration_secs: f64,
    pub is_ipv6: bool,
}

/// Process bandwidth aggregation
#[derive(Debug, Clone)]
pub struct ProcessBandwidth {
    pub process_name: String,
    pub process_id: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub flow_count: usize,
}

/// Bandwidth history sample for sparklines
#[derive(Debug, Clone, Copy)]
pub struct BandwidthSample {
    pub timestamp: u64, // Unix timestamp in seconds
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Known application profile
#[derive(Debug, Clone)]
pub struct AppProfile {
    pub exe_name: &'static str,
    pub display_name: &'static str,
    pub category: &'static str,
}

/// Built-in application profiles for friendly names
pub const APP_PROFILES: &[AppProfile] = &[
    // Browsers
    AppProfile { exe_name: "chrome.exe", display_name: "Google Chrome", category: "Browser" },
    AppProfile { exe_name: "firefox.exe", display_name: "Mozilla Firefox", category: "Browser" },
    AppProfile { exe_name: "msedge.exe", display_name: "Microsoft Edge", category: "Browser" },
    AppProfile { exe_name: "brave.exe", display_name: "Brave Browser", category: "Browser" },
    AppProfile { exe_name: "opera.exe", display_name: "Opera", category: "Browser" },
    AppProfile { exe_name: "vivaldi.exe", display_name: "Vivaldi", category: "Browser" },
    // Development
    AppProfile { exe_name: "code.exe", display_name: "VS Code", category: "Development" },
    AppProfile { exe_name: "devenv.exe", display_name: "Visual Studio", category: "Development" },
    AppProfile { exe_name: "node.exe", display_name: "Node.js", category: "Development" },
    AppProfile { exe_name: "python.exe", display_name: "Python", category: "Development" },
    AppProfile { exe_name: "pythonw.exe", display_name: "Python", category: "Development" },
    AppProfile { exe_name: "cargo.exe", display_name: "Cargo (Rust)", category: "Development" },
    AppProfile { exe_name: "git.exe", display_name: "Git", category: "Development" },
    AppProfile { exe_name: "claude.exe", display_name: "Claude Code", category: "Development" },
    // Communication
    AppProfile { exe_name: "discord.exe", display_name: "Discord", category: "Communication" },
    AppProfile { exe_name: "slack.exe", display_name: "Slack", category: "Communication" },
    AppProfile { exe_name: "teams.exe", display_name: "Microsoft Teams", category: "Communication" },
    AppProfile { exe_name: "zoom.exe", display_name: "Zoom", category: "Communication" },
    AppProfile { exe_name: "telegram.exe", display_name: "Telegram", category: "Communication" },
    // Gaming
    AppProfile { exe_name: "steam.exe", display_name: "Steam", category: "Gaming" },
    AppProfile { exe_name: "steamwebhelper.exe", display_name: "Steam Web", category: "Gaming" },
    AppProfile { exe_name: "epicgameslauncher.exe", display_name: "Epic Games", category: "Gaming" },
    // Media
    AppProfile { exe_name: "spotify.exe", display_name: "Spotify", category: "Media" },
    AppProfile { exe_name: "vlc.exe", display_name: "VLC", category: "Media" },
    // System
    AppProfile { exe_name: "svchost.exe", display_name: "Windows Service Host", category: "System" },
    AppProfile { exe_name: "system", display_name: "Windows Kernel", category: "System" },
    AppProfile { exe_name: "searchhost.exe", display_name: "Windows Search", category: "System" },
    AppProfile { exe_name: "msedgewebview2.exe", display_name: "Edge WebView", category: "System" },
    AppProfile { exe_name: "runtimebroker.exe", display_name: "Runtime Broker", category: "System" },
    // Cloud/Sync
    AppProfile { exe_name: "onedrive.exe", display_name: "OneDrive", category: "Cloud" },
    AppProfile { exe_name: "dropbox.exe", display_name: "Dropbox", category: "Cloud" },
    // Security
    AppProfile { exe_name: "msmpeng.exe", display_name: "Windows Defender", category: "Security" },
    // CLI Tools
    AppProfile { exe_name: "curl.exe", display_name: "cURL", category: "CLI" },
    AppProfile { exe_name: "wget.exe", display_name: "Wget", category: "CLI" },
    AppProfile { exe_name: "ssh.exe", display_name: "SSH", category: "CLI" },
    AppProfile { exe_name: "powershell.exe", display_name: "PowerShell", category: "CLI" },
    AppProfile { exe_name: "pwsh.exe", display_name: "PowerShell Core", category: "CLI" },
];

/// Look up friendly name for a process
pub fn get_app_profile(exe_name: &str) -> Option<&'static AppProfile> {
    let lower = exe_name.to_lowercase();
    APP_PROFILES.iter().find(|p| p.exe_name == lower)
}

/// Sorting options for flows
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FlowSort {
    #[default]
    BytesTotal,
    BytesSent,
    BytesReceived,
    Duration,
    Process,
}

/// Driver status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DriverStatus {
    #[default]
    Unknown,
    Running,
    Stopped,
    NotInstalled,
}

impl DriverStatus {
    pub fn label(self) -> &'static str {
        match self {
            DriverStatus::Unknown => "Unknown",
            DriverStatus::Running => "Running",
            DriverStatus::Stopped => "Stopped",
            DriverStatus::NotInstalled => "Not Installed",
        }
    }

    pub fn is_running(self) -> bool {
        matches!(self, DriverStatus::Running)
    }
}

/// Operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    MonitorOnly,
    UserModeWfp,
    KernelDriver,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Mode::MonitorOnly => "Monitor Only",
            Mode::UserModeWfp => "User-Mode WFP",
            Mode::KernelDriver => "Kernel Driver",
        }
    }
}

/// A connection event displayed in the monitor
#[derive(Debug, Clone)]
pub struct ConnectionEvent {
    pub time: String,
    pub action: String,
    pub process_name: String,
    pub process_id: u32,
    pub destination: String,
    /// Raw remote IP address (for matching SNI updates)
    pub remote_address: String,
    pub port: u16,
    /// Local (source) port - useful for correlating with TLM flows
    pub local_port: u16,
    pub protocol: String,
    pub rule_name: Option<String>,
    pub is_pending: bool,
    /// Driver request ID for pending ASK (needed to send verdict)
    pub request_id: Option<u64>,
}

/// Main application state
pub struct App {
    /// Should the app quit?
    pub should_quit: bool,

    /// Current active tab
    pub active_tab: Tab,

    /// Driver status
    pub driver_status: DriverStatus,

    /// Operating mode
    pub mode: Mode,

    /// Live connection events (most recent first)
    pub connections: VecDeque<ConnectionEvent>,

    /// Maximum connections to keep in memory
    pub max_connections: usize,

    /// Currently selected connection index
    pub selected_connection: usize,

    /// Rules list
    pub rules: Vec<Rule>,

    /// Currently selected rule index
    pub selected_rule: usize,

    /// Selected rule IDs for bulk operations
    pub selected_rules: HashSet<String>,

    /// Log messages
    pub logs: VecDeque<String>,

    /// Maximum logs to keep
    pub max_logs: usize,

    /// Pending ASK connection (if any)
    pub pending_ask: Option<ConnectionEvent>,

    /// Is admin mode?
    pub is_admin: bool,

    /// Total connections this session
    pub total_connections: u64,

    /// Blocked connections this session
    pub blocked_connections: u64,

    /// Scroll offset for connection list
    pub connection_scroll: usize,

    /// Total bytes sent (from TLM bandwidth tracking)
    pub total_bytes_sent: u64,

    /// Total bytes received (from TLM bandwidth tracking)
    pub total_bytes_received: u64,

    /// Active flow count (from TLM bandwidth tracking)
    pub active_flows: usize,

    /// Active flows from TLM (for Flows tab)
    pub flows: Vec<Flow>,

    /// Currently selected flow index
    pub selected_flow: usize,

    /// Scroll offset for flows table (first visible row)
    pub flow_scroll_offset: usize,

    /// Flow sorting mode
    pub flow_sort: FlowSort,

    /// Process bandwidth aggregation (computed from flows)
    pub process_bandwidth: Vec<ProcessBandwidth>,

    /// Bandwidth history for sparklines (last 60 samples = 1 minute at 1s intervals)
    pub bandwidth_history: VecDeque<BandwidthSample>,

    /// Maximum bandwidth history samples
    pub max_bandwidth_history: usize,

    /// Process name cache (PID -> name)
    pub process_names: HashMap<u32, String>,

    /// Per-flow bandwidth history (flow_handle -> history)
    pub flow_history: HashMap<u64, VecDeque<BandwidthSample>>,

    /// Process cache by local port (local_port -> (process_name, remote_ip, destination))
    /// This enables TLM flow correlation since local port is unique per connection
    pub port_process_cache: HashMap<u16, (String, String, String)>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            should_quit: false,
            active_tab: Tab::Monitor,
            driver_status: DriverStatus::Unknown,
            mode: Mode::MonitorOnly,
            connections: VecDeque::with_capacity(500),
            max_connections: 500,
            selected_connection: 0,
            rules: Vec::new(),
            selected_rule: 0,
            selected_rules: HashSet::new(),
            logs: VecDeque::with_capacity(1000),
            max_logs: 1000,
            pending_ask: None,
            is_admin: false,
            total_connections: 0,
            blocked_connections: 0,
            connection_scroll: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            active_flows: 0,
            flows: Vec::new(),
            selected_flow: 0,
            flow_scroll_offset: 0,
            flow_sort: FlowSort::default(),
            process_bandwidth: Vec::new(),
            bandwidth_history: VecDeque::with_capacity(60),
            max_bandwidth_history: 60,
            process_names: HashMap::new(),
            flow_history: HashMap::new(),
            port_process_cache: HashMap::new(),
        }
    }
}

impl App {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a connection event
    pub fn add_connection(&mut self, event: ConnectionEvent) {
        self.total_connections += 1;
        if event.action == "DENY" {
            self.blocked_connections += 1;
        }

        self.connections.push_front(event);
        if self.connections.len() > self.max_connections {
            self.connections.pop_back();
        }
    }

    /// Add a log message
    pub fn log(&mut self, message: String) {
        let timestamp = chrono::Local::now().format("%H:%M:%S").to_string();
        self.logs.push_front(format!("{} {}", timestamp, message));
        if self.logs.len() > self.max_logs {
            self.logs.pop_back();
        }
    }

    /// Switch to next tab
    pub fn next_tab(&mut self) {
        self.active_tab = self.active_tab.next();
    }

    /// Switch to previous tab
    pub fn prev_tab(&mut self) {
        self.active_tab = self.active_tab.prev();
    }

    /// Switch to specific tab
    pub fn switch_tab(&mut self, tab: Tab) {
        self.active_tab = tab;
    }

    /// Move selection up in current list
    pub fn select_up(&mut self) {
        match self.active_tab {
            Tab::Monitor => {
                if self.selected_connection > 0 {
                    self.selected_connection -= 1;
                }
            }
            Tab::Flows => {
                if self.selected_flow > 0 {
                    self.selected_flow -= 1;
                }
            }
            Tab::Rules => {
                if self.selected_rule > 0 {
                    self.selected_rule -= 1;
                }
            }
            _ => {}
        }
    }

    /// Move selection down in current list
    pub fn select_down(&mut self) {
        match self.active_tab {
            Tab::Monitor => {
                if self.selected_connection < self.connections.len().saturating_sub(1) {
                    self.selected_connection += 1;
                }
            }
            Tab::Flows => {
                if self.selected_flow < self.flows.len().saturating_sub(1) {
                    self.selected_flow += 1;
                }
            }
            Tab::Rules => {
                if self.selected_rule < self.rules.len().saturating_sub(1) {
                    self.selected_rule += 1;
                }
            }
            _ => {}
        }
    }

    /// Adjust flow scroll offset to keep selection visible
    /// Call this after changing selected_flow, passing the visible row count
    pub fn adjust_flow_scroll(&mut self, visible_rows: usize) {
        if visible_rows == 0 {
            return;
        }
        // If selection is above visible area, scroll up
        if self.selected_flow < self.flow_scroll_offset {
            self.flow_scroll_offset = self.selected_flow;
        }
        // If selection is below visible area, scroll down
        if self.selected_flow >= self.flow_scroll_offset + visible_rows {
            self.flow_scroll_offset = self.selected_flow.saturating_sub(visible_rows - 1);
        }
    }

    /// Get selected connection
    pub fn selected_connection_event(&self) -> Option<&ConnectionEvent> {
        self.connections.get(self.selected_connection)
    }

    /// Get selected rule
    pub fn selected_rule_item(&self) -> Option<&Rule> {
        self.rules.get(self.selected_rule)
    }

    /// Get selected flow
    pub fn selected_flow_item(&self) -> Option<&Flow> {
        self.flows.get(self.selected_flow)
    }

    /// Update flows from TLM bandwidth entries and compute aggregations
    pub fn update_flows(&mut self, entries: Vec<crate::driver::BandwidthEntry>) {
        // Import port lookup functions
        use crate::driver::{get_pid_by_port, get_process_name_by_pid};

        // Convert bandwidth entries to flows
        self.flows = entries
            .into_iter()
            .map(|e| {
                // Multi-level process lookup:
                // 1. Try port_process_cache (from ALE events)
                // 2. Try process_names cache (by PID if valid)
                // 3. Try OS-level port-to-PID lookup (GetExtendedTcpTable/UdpTable)
                // 4. Fall back to descriptive name based on traffic type

                // Try to identify process - multiple fallback levels
                let process_name =
                    // 1. Try ALE port cache first (most reliable)
                    self.port_process_cache.get(&e.local_port)
                        .map(|(name, _, _)| name.clone())
                    // 2. Try process_names cache by PID
                    .or_else(|| {
                        if e.process_id != 0 {
                            self.process_names.get(&e.process_id).cloned()
                        } else {
                            None
                        }
                    })
                    // 3. Try OS lookup by PID
                    .or_else(|| {
                        if e.process_id != 0 {
                            get_process_name_by_pid(e.process_id).map(|name| {
                                self.process_names.insert(e.process_id, name.clone());
                                name
                            })
                        } else {
                            None
                        }
                    })
                    // 4. Try OS lookup by port
                    .or_else(|| {
                        if e.local_port > 0 {
                            get_pid_by_port(e.local_port).and_then(|pid| {
                                get_process_name_by_pid(pid).map(|name| {
                                    self.process_names.insert(pid, name.clone());
                                    name
                                })
                            })
                        } else {
                            None
                        }
                    })
                    // 5. Always fall back to identify_system_traffic
                    .unwrap_or_else(|| identify_system_traffic(&e));

                Flow {
                    flow_handle: e.flow_handle,
                    process_id: e.process_id,
                    process_name,
                    local_address: e.local_address,
                    local_port: e.local_port,
                    remote_address: e.remote_address,
                    remote_port: e.remote_port,
                    bytes_sent: e.bytes_sent,
                    bytes_received: e.bytes_received,
                    duration_secs: e.duration_secs,
                    is_ipv6: e.is_ipv6,
                }
            })
            .collect();

        // Sort flows based on current sort mode
        self.sort_flows();

        // Compute process bandwidth aggregation
        self.compute_process_bandwidth();

        // Update totals
        self.total_bytes_sent = self.flows.iter().map(|f| f.bytes_sent).sum();
        self.total_bytes_received = self.flows.iter().map(|f| f.bytes_received).sum();
        self.active_flows = self.flows.len();

        // Add bandwidth history sample (total)
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let sample = BandwidthSample {
            timestamp,
            bytes_sent: self.total_bytes_sent,
            bytes_received: self.total_bytes_received,
        };
        self.bandwidth_history.push_back(sample);
        if self.bandwidth_history.len() > self.max_bandwidth_history {
            self.bandwidth_history.pop_front();
        }

        // Track per-flow bandwidth history
        let current_handles: std::collections::HashSet<u64> =
            self.flows.iter().map(|f| f.flow_handle).collect();

        // Remove stale flow histories (flows no longer active)
        self.flow_history.retain(|handle, _| current_handles.contains(handle));

        // Add samples for each active flow
        for flow in &self.flows {
            let flow_sample = BandwidthSample {
                timestamp,
                bytes_sent: flow.bytes_sent,
                bytes_received: flow.bytes_received,
            };

            let history = self.flow_history
                .entry(flow.flow_handle)
                .or_insert_with(|| VecDeque::with_capacity(60));

            history.push_back(flow_sample);
            if history.len() > self.max_bandwidth_history {
                history.pop_front();
            }
        }

        // Clamp selected_flow to valid range
        if self.selected_flow >= self.flows.len() && !self.flows.is_empty() {
            self.selected_flow = self.flows.len() - 1;
        }
    }

    /// Sort flows based on current sort mode
    pub fn sort_flows(&mut self) {
        match self.flow_sort {
            FlowSort::BytesTotal => {
                self.flows.sort_by(|a, b| {
                    (b.bytes_sent + b.bytes_received).cmp(&(a.bytes_sent + a.bytes_received))
                });
            }
            FlowSort::BytesSent => {
                self.flows.sort_by(|a, b| b.bytes_sent.cmp(&a.bytes_sent));
            }
            FlowSort::BytesReceived => {
                self.flows.sort_by(|a, b| b.bytes_received.cmp(&a.bytes_received));
            }
            FlowSort::Duration => {
                self.flows.sort_by(|a, b| {
                    b.duration_secs
                        .partial_cmp(&a.duration_secs)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            }
            FlowSort::Process => {
                self.flows.sort_by(|a, b| a.process_name.cmp(&b.process_name));
            }
        }
    }

    /// Cycle to next flow sort mode
    pub fn next_flow_sort(&mut self) {
        self.flow_sort = match self.flow_sort {
            FlowSort::BytesTotal => FlowSort::BytesSent,
            FlowSort::BytesSent => FlowSort::BytesReceived,
            FlowSort::BytesReceived => FlowSort::Duration,
            FlowSort::Duration => FlowSort::Process,
            FlowSort::Process => FlowSort::BytesTotal,
        };
        self.sort_flows();
    }

    /// Compute process bandwidth aggregation from flows
    fn compute_process_bandwidth(&mut self) {
        let mut by_process: HashMap<u32, ProcessBandwidth> = HashMap::new();

        for flow in &self.flows {
            let entry = by_process.entry(flow.process_id).or_insert_with(|| {
                ProcessBandwidth {
                    process_name: flow.process_name.clone(),
                    process_id: flow.process_id,
                    bytes_sent: 0,
                    bytes_received: 0,
                    flow_count: 0,
                }
            });
            entry.bytes_sent += flow.bytes_sent;
            entry.bytes_received += flow.bytes_received;
            entry.flow_count += 1;
        }

        // Convert to vec and sort by total bytes
        self.process_bandwidth = by_process.into_values().collect();
        self.process_bandwidth.sort_by(|a, b| {
            (b.bytes_sent + b.bytes_received).cmp(&(a.bytes_sent + a.bytes_received))
        });
    }

    /// Cache a process name for PID (called when we see a connection)
    pub fn cache_process_name(&mut self, pid: u32, name: &str) {
        if !name.is_empty() && name != "Unknown" {
            self.process_names.insert(pid, name.to_string());
        }
    }

    /// Cache process info by local port (for TLM flow correlation)
    /// Local port is unique per connection, making this a reliable way to correlate
    pub fn cache_port_process(&mut self, local_port: u16, process_name: &str, remote_ip: &str, destination: &str) {
        if local_port > 0 && !process_name.is_empty() {
            self.port_process_cache.insert(
                local_port,
                (process_name.to_string(), remote_ip.to_string(), destination.to_string()),
            );
        }
    }

    /// Look up process info by local port
    pub fn get_process_by_port(&self, local_port: u16) -> Option<&(String, String, String)> {
        self.port_process_cache.get(&local_port)
    }
}

/// Identify system/network traffic based on port and address patterns
/// Used as fallback when we can't determine the process
fn identify_system_traffic(entry: &crate::driver::BandwidthEntry) -> String {
    let remote_str = entry.remote_address.to_string();

    // Identify by remote port (well-known services)
    match entry.remote_port {
        53 => return "svchost (DNS)".to_string(),
        67 | 68 => return "svchost (DHCP)".to_string(),
        123 => return "svchost (NTP)".to_string(),
        137 | 138 | 139 => return "System (NetBIOS)".to_string(),
        445 => return "System (SMB)".to_string(),
        5353 => return "svchost (mDNS)".to_string(),
        1900 => return "svchost (SSDP)".to_string(),
        3702 => return "svchost (WSD)".to_string(),
        _ => {}
    }

    // Identify by address pattern
    if remote_str.starts_with("224.") || remote_str.starts_with("239.") {
        return "System (multicast)".to_string();
    }
    if remote_str.starts_with("169.254.") {
        return "System (link-local)".to_string();
    }
    if remote_str == "255.255.255.255" {
        return "System (broadcast)".to_string();
    }

    // IPv6 multicast
    if entry.is_ipv6 {
        return "System (IPv6)".to_string();
    }

    // Localhost traffic
    if remote_str.starts_with("127.") || remote_str == "::1" {
        return "localhost".to_string();
    }

    // Generic fallback
    "System".to_string()
}
