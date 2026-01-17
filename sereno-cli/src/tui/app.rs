//! TUI Application State

use indexmap::IndexMap;
use sereno_core::types::Rule;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

/// Rule duration options for time-limited rules
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleDuration {
    Once,           // Single use, then deleted
    OneHour,        // 1 hour from now
    OneDay,         // 24 hours from now
    OneWeek,        // 7 days from now
    Permanent,      // Forever
}

impl RuleDuration {
    pub fn all() -> [RuleDuration; 5] {
        [
            RuleDuration::Once,
            RuleDuration::OneHour,
            RuleDuration::OneDay,
            RuleDuration::OneWeek,
            RuleDuration::Permanent,
        ]
    }

    pub fn label(self) -> &'static str {
        match self {
            RuleDuration::Once => "Once (this time only)",
            RuleDuration::OneHour => "1 hour",
            RuleDuration::OneDay => "1 day",
            RuleDuration::OneWeek => "1 week",
            RuleDuration::Permanent => "Forever",
        }
    }

    pub fn short_label(self) -> &'static str {
        match self {
            RuleDuration::Once => "1x",
            RuleDuration::OneHour => "1h",
            RuleDuration::OneDay => "1d",
            RuleDuration::OneWeek => "1w",
            RuleDuration::Permanent => "∞",
        }
    }

    pub fn to_validity(self) -> sereno_core::types::Validity {
        use chrono::{Duration, Utc};
        use sereno_core::types::Validity;

        match self {
            RuleDuration::Once => Validity::Once,
            RuleDuration::OneHour => Validity::Timed {
                expires_at: Utc::now() + Duration::hours(1),
            },
            RuleDuration::OneDay => Validity::Timed {
                expires_at: Utc::now() + Duration::days(1),
            },
            RuleDuration::OneWeek => Validity::Timed {
                expires_at: Utc::now() + Duration::weeks(1),
            },
            RuleDuration::Permanent => Validity::Permanent,
        }
    }
}

/// State for duration selection prompt
#[derive(Debug, Clone)]
pub struct DurationPrompt {
    pub process_name: String,
    pub destination: String,
    pub port: u16,
    pub selected_index: usize,
}

/// Authorization status for a connection (unified view)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStatus {
    /// TCP authorized (green) - allowed by rule or user
    Allow,
    /// TCP blocked (red) - denied by rule or user
    Deny,
    /// TCP awaiting user decision (yellow)
    Pending,
    /// UDP auto-permitted (cyan) - no authorization needed
    Auto,
    /// Silent Allow mode - auto-allowed for learning (magenta)
    SilentAllow,
}

impl AuthStatus {
    pub fn label(self) -> &'static str {
        match self {
            AuthStatus::Allow => "ALLOW",
            AuthStatus::Deny => "DENY",
            AuthStatus::Pending => "ASK",
            AuthStatus::Auto => "AUTO",
            AuthStatus::SilentAllow => "SA",
        }
    }
}

/// A unified connection combining ALE authorization events and TLM bandwidth data
#[derive(Debug, Clone)]
pub struct UnifiedConnection {
    // Identity (correlation key)
    pub local_port: u16,
    pub remote_address: IpAddr,
    pub remote_port: u16,
    pub protocol: sereno_core::types::Protocol,
    pub direction: sereno_core::types::Direction, // Inbound/Outbound

    // Process info
    pub process_name: String,
    pub process_id: u32,
    pub process_path: String,

    // Authorization (from ALE)
    pub auth_status: AuthStatus,
    pub signature_status: Option<crate::signature::SignatureStatus>,
    pub request_id: Option<u64>,

    // Domain/destination
    pub destination: String, // Best available: SNI > DNS cache > IP

    // Bandwidth (from TLM)
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub duration_secs: f64,

    // State
    pub first_seen: String,
    pub is_active: bool, // True if TLM is still reporting this flow
}

impl UnifiedConnection {
    /// Create a new connection from an ALE authorization event
    pub fn from_ale_event(
        local_port: u16,
        remote_address: IpAddr,
        remote_port: u16,
        protocol: sereno_core::types::Protocol,
        direction: sereno_core::types::Direction,
        process_name: String,
        process_id: u32,
        process_path: String,
        auth_status: AuthStatus,
        destination: String,
        signature_status: Option<crate::signature::SignatureStatus>,
        request_id: Option<u64>,
    ) -> Self {
        Self {
            local_port,
            remote_address,
            remote_port,
            protocol,
            direction,
            process_name,
            process_id,
            process_path,
            auth_status,
            signature_status,
            request_id,
            destination,
            bytes_sent: 0,
            bytes_received: 0,
            duration_secs: 0.0,
            first_seen: chrono::Local::now().format("%H:%M:%S").to_string(),
            is_active: true,
        }
    }

    /// Update bandwidth stats from TLM poll
    pub fn update_bandwidth(&mut self, bytes_sent: u64, bytes_received: u64, duration_secs: f64) {
        self.bytes_sent = bytes_sent;
        self.bytes_received = bytes_received;
        self.duration_secs = duration_secs;
        self.is_active = true;
    }
}

/// Key for unified connection lookup
pub type UnifiedConnectionKey = (u16, IpAddr, u16); // (local_port, remote_ip, remote_port)

/// View mode for connections tab
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ViewMode {
    /// Show individual connections (default)
    #[default]
    Detailed,
    /// Show connections grouped by destination
    Grouped,
}

impl ViewMode {
    pub fn toggle(self) -> Self {
        match self {
            ViewMode::Detailed => ViewMode::Grouped,
            ViewMode::Grouped => ViewMode::Detailed,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ViewMode::Detailed => "Detailed",
            ViewMode::Grouped => "Grouped",
        }
    }
}

/// A grouped connection aggregating multiple connections by process and destination
/// Like Little Snitch: shows what each app is talking to
#[derive(Debug, Clone)]
pub struct GroupedConnection {
    /// Process name (aggregates all PIDs)
    pub process_name: String,
    /// Destination (domain or IP)
    pub destination: String,
    /// Ports used (may have multiple - e.g., 443, 80)
    pub ports: Vec<u16>,
    /// Protocols used (TCP, UDP, or both)
    pub protocols: Vec<sereno_core::types::Protocol>,
    /// Number of individual connections
    pub connection_count: usize,
    /// Number of unique PIDs
    pub pid_count: usize,
    /// Total bytes sent across all connections
    pub total_bytes_sent: u64,
    /// Total bytes received across all connections
    pub total_bytes_received: u64,
    /// First seen timestamp
    pub first_seen: String,
    /// Are any connections still active?
    pub is_any_active: bool,
    /// Most restrictive auth status (DENY > PENDING > SA > AUTO > ALLOW)
    pub auth_status: AuthStatus,
}

/// Active tab in the TUI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Connections,
    Rules,
    Logs,
    Settings,
}

impl Tab {
    pub fn next(self) -> Self {
        match self {
            Tab::Connections => Tab::Rules,
            Tab::Rules => Tab::Logs,
            Tab::Logs => Tab::Settings,
            Tab::Settings => Tab::Connections,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Tab::Connections => Tab::Settings,
            Tab::Rules => Tab::Connections,
            Tab::Logs => Tab::Rules,
            Tab::Settings => Tab::Logs,
        }
    }

    pub fn all() -> [Tab; 4] {
        [Tab::Connections, Tab::Rules, Tab::Logs, Tab::Settings]
    }

    pub fn label(self) -> &'static str {
        match self {
            Tab::Connections => "Connections",
            Tab::Rules => "Rules",
            Tab::Logs => "Logs",
            Tab::Settings => "Settings",
        }
    }

    pub fn key(self) -> char {
        match self {
            Tab::Connections => '1',
            Tab::Rules => '2',
            Tab::Logs => '3',
            Tab::Settings => '4',
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

/// Sorting options for unified connections
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionSort {
    #[default]
    Time,        // Most recent first
    BytesTotal,  // Highest bandwidth first
    Process,     // Alphabetical by process name
    Destination, // Alphabetical by destination
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
    /// Silent Allow - auto-allow all connections while logging
    SilentAllow,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Mode::MonitorOnly => "Monitor Only",
            Mode::UserModeWfp => "User-Mode WFP",
            Mode::KernelDriver => "Kernel Driver",
            Mode::SilentAllow => "Silent Allow",
        }
    }

    /// Cycle to next mode (for UI toggle)
    pub fn next(self) -> Self {
        match self {
            Mode::KernelDriver => Mode::SilentAllow,
            Mode::SilentAllow => Mode::KernelDriver,
            // MonitorOnly and UserModeWfp can't toggle
            other => other,
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
    /// Full path to the executable
    pub process_path: String,
    pub destination: String,
    /// Raw remote IP address (for matching SNI updates)
    pub remote_address: String,
    pub port: u16,
    /// Local (source) port - useful for correlating with TLM flows
    pub local_port: u16,
    pub protocol: String,
    /// Connection direction (Inbound/Outbound)
    pub direction: sereno_core::types::Direction,
    pub rule_name: Option<String>,
    pub is_pending: bool,
    /// Driver request ID for pending ASK (needed to send verdict)
    pub request_id: Option<u64>,
    /// Code signature status (None = not yet checked)
    pub signature_status: Option<crate::signature::SignatureStatus>,
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

    /// Duration selection prompt (when creating a rule)
    pub duration_prompt: Option<DurationPrompt>,

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

    /// Signature verification cache
    pub signature_cache: crate::signature::SignatureCache,

    // ===== UNIFIED CONNECTIONS VIEW =====

    /// Unified connections: ALE auth + TLM bandwidth merged
    /// Key: (local_port, remote_ip, remote_port)
    pub unified_connections: IndexMap<UnifiedConnectionKey, UnifiedConnection>,

    /// Currently selected unified connection index
    pub selected_unified: usize,

    /// Scroll offset for unified connections table
    pub unified_scroll_offset: usize,

    /// Sort mode for unified connections
    pub unified_sort: ConnectionSort,

    // ===== CONNECTION GROUPING =====

    /// View mode for connections tab (Detailed vs Grouped)
    pub view_mode: ViewMode,

    /// Grouped connections (computed on demand when switching to Grouped view)
    pub grouped_connections: Vec<GroupedConnection>,

    /// Currently selected grouped connection index
    pub selected_grouped: usize,

    /// Scroll offset for grouped connections table
    pub grouped_scroll_offset: usize,

    // ===== INFO POPUP =====

    /// Show info popup for selected connection
    pub show_info_popup: bool,
}

impl Default for App {
    fn default() -> Self {
        Self {
            should_quit: false,
            active_tab: Tab::Connections,
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
            duration_prompt: None,
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
            signature_cache: crate::signature::SignatureCache::new(),
            // Unified connections view
            unified_connections: IndexMap::new(),
            selected_unified: 0,
            unified_scroll_offset: 0,
            unified_sort: ConnectionSort::default(),
            // Connection grouping
            view_mode: ViewMode::default(),
            grouped_connections: Vec::new(),
            selected_grouped: 0,
            grouped_scroll_offset: 0,
            // Info popup
            show_info_popup: false,
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
            Tab::Connections => {
                if self.selected_unified > 0 {
                    self.selected_unified -= 1;
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
            Tab::Connections => {
                if self.selected_unified < self.unified_connections.len().saturating_sub(1) {
                    self.selected_unified += 1;
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

    // ===== UNIFIED CONNECTIONS METHODS =====

    /// Add or update a unified connection from an ALE authorization event
    pub fn add_unified_from_ale(
        &mut self,
        local_port: u16,
        remote_address: IpAddr,
        remote_port: u16,
        protocol: sereno_core::types::Protocol,
        direction: sereno_core::types::Direction,
        process_name: String,
        process_id: u32,
        process_path: String,
        auth_status: AuthStatus,
        destination: String,
        signature_status: Option<crate::signature::SignatureStatus>,
        request_id: Option<u64>,
    ) {
        let key: UnifiedConnectionKey = (local_port, remote_address, remote_port);

        // Track stats
        self.total_connections += 1;
        if auth_status == AuthStatus::Deny {
            self.blocked_connections += 1;
        }

        // Update or insert
        if let Some(conn) = self.unified_connections.get_mut(&key) {
            // Update existing connection
            conn.auth_status = auth_status;
            conn.signature_status = signature_status;
            conn.request_id = request_id;
            if !destination.is_empty() && destination != conn.destination {
                // Update destination if better info available (e.g., SNI)
                conn.destination = destination;
            }
        } else {
            // Insert new connection
            let conn = UnifiedConnection::from_ale_event(
                local_port,
                remote_address,
                remote_port,
                protocol,
                direction,
                process_name,
                process_id,
                process_path,
                auth_status,
                destination,
                signature_status,
                request_id,
            );
            self.unified_connections.insert(key, conn);
        }

        // Limit size (remove oldest entries if needed)
        while self.unified_connections.len() > self.max_connections {
            self.unified_connections.shift_remove_index(0);
        }
    }

    /// Update unified connections from TLM bandwidth poll
    /// This updates bandwidth stats and marks inactive connections
    pub fn update_unified_from_tlm(&mut self, entries: &[crate::driver::BandwidthEntry]) {
        use std::collections::HashSet;

        // Build set of active keys from TLM
        let active_keys: HashSet<UnifiedConnectionKey> = entries
            .iter()
            .map(|e| (e.local_port, e.remote_address, e.remote_port))
            .collect();

        // Mark all connections as inactive first
        for conn in self.unified_connections.values_mut() {
            conn.is_active = active_keys.contains(&(conn.local_port, conn.remote_address, conn.remote_port));
        }

        // Update bandwidth for each TLM entry
        for entry in entries {
            let key: UnifiedConnectionKey = (entry.local_port, entry.remote_address, entry.remote_port);

            if let Some(conn) = self.unified_connections.get_mut(&key) {
                // Update existing connection's bandwidth
                conn.update_bandwidth(entry.bytes_sent, entry.bytes_received, entry.duration_secs);
            } else {
                // TLM-only connection (UDP, or ALE event missed)
                // Create with AUTO status (UDP flows that didn't need authorization)
                let process_name = self.port_process_cache
                    .get(&entry.local_port)
                    .map(|(name, _, _)| name.clone())
                    .or_else(|| {
                        if entry.process_id != 0 {
                            self.process_names.get(&entry.process_id).cloned()
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| identify_system_traffic(entry));

                let destination = self.port_process_cache
                    .get(&entry.local_port)
                    .map(|(_, _, dest)| dest.clone())
                    .unwrap_or_else(|| entry.remote_address.to_string());

                let mut conn = UnifiedConnection::from_ale_event(
                    entry.local_port,
                    entry.remote_address,
                    entry.remote_port,
                    sereno_core::types::Protocol::Udp, // Assume UDP for TLM-only
                    sereno_core::types::Direction::Outbound, // Assume outbound for TLM-only
                    process_name,
                    entry.process_id,
                    String::new(), // No path for TLM-only
                    AuthStatus::Auto, // Auto-permitted
                    destination,
                    None,
                    None,
                );
                conn.update_bandwidth(entry.bytes_sent, entry.bytes_received, entry.duration_secs);
                self.unified_connections.insert(key, conn);
            }
        }

        // Update totals from all connections
        self.total_bytes_sent = self.unified_connections.values().map(|c| c.bytes_sent).sum();
        self.total_bytes_received = self.unified_connections.values().map(|c| c.bytes_received).sum();
        self.active_flows = self.unified_connections.values().filter(|c| c.is_active).count();

        // Clamp selected_unified to valid range
        if self.selected_unified >= self.unified_connections.len() && !self.unified_connections.is_empty() {
            self.selected_unified = self.unified_connections.len() - 1;
        }
    }

    /// Get the selected unified connection
    pub fn selected_unified_connection(&self) -> Option<&UnifiedConnection> {
        self.unified_connections.get_index(self.selected_unified).map(|(_, v)| v)
    }

    /// Get the selected unified connection (mutable)
    pub fn selected_unified_connection_mut(&mut self) -> Option<&mut UnifiedConnection> {
        self.unified_connections.get_index_mut(self.selected_unified).map(|(_, v)| v)
    }

    /// Adjust unified scroll offset to keep selection visible
    pub fn adjust_unified_scroll(&mut self, visible_rows: usize) {
        if visible_rows == 0 {
            return;
        }
        if self.selected_unified < self.unified_scroll_offset {
            self.unified_scroll_offset = self.selected_unified;
        }
        if self.selected_unified >= self.unified_scroll_offset + visible_rows {
            self.unified_scroll_offset = self.selected_unified.saturating_sub(visible_rows - 1);
        }
    }

    /// Cycle to next unified connection sort mode
    pub fn next_unified_sort(&mut self) {
        self.unified_sort = match self.unified_sort {
            ConnectionSort::Time => ConnectionSort::BytesTotal,
            ConnectionSort::BytesTotal => ConnectionSort::Process,
            ConnectionSort::Process => ConnectionSort::Destination,
            ConnectionSort::Destination => ConnectionSort::Time,
        };
        // Note: IndexMap maintains insertion order by default
        // For sorting, we'd need to rebuild the map - keeping simple for now
        // by relying on insertion order (most recent at end, reversed for display)
    }

    /// Get unified connections as a sorted vector for display (most recent first by default)
    pub fn get_unified_connections_sorted(&self) -> Vec<(&UnifiedConnectionKey, &UnifiedConnection)> {
        let mut connections: Vec<_> = self.unified_connections.iter().collect();

        match self.unified_sort {
            ConnectionSort::Time => {
                // Reverse for most recent first (IndexMap preserves insertion order)
                connections.reverse();
            }
            ConnectionSort::BytesTotal => {
                connections.sort_by(|(_, a), (_, b)| {
                    (b.bytes_sent + b.bytes_received).cmp(&(a.bytes_sent + a.bytes_received))
                });
            }
            ConnectionSort::Process => {
                connections.sort_by(|(_, a), (_, b)| a.process_name.cmp(&b.process_name));
            }
            ConnectionSort::Destination => {
                connections.sort_by(|(_, a), (_, b)| a.destination.cmp(&b.destination));
            }
        }

        connections
    }

    // ===== CONNECTION GROUPING METHODS =====

    /// Compute grouped connections by aggregating by (process_name, destination)
    /// Like Little Snitch: shows what each app is talking to, merging TCP+UDP
    pub fn compute_grouped_connections(&mut self) {
        use std::collections::{HashMap, HashSet};

        // Group by (process_name, destination) - ignoring port and protocol for grouping
        // This merges TCP+UDP connections and different ports to same destination
        let mut groups: HashMap<(String, String), GroupedConnection> = HashMap::new();
        let mut pids_seen: HashMap<(String, String), HashSet<u32>> = HashMap::new();

        for conn in self.unified_connections.values() {
            // Normalize process name (strip numeric suffixes, lowercase for matching)
            let process_key = conn.process_name.clone();
            let dest_key = conn.destination.clone();
            let key = (process_key.clone(), dest_key.clone());

            // Track PIDs for this group
            pids_seen.entry(key.clone())
                .or_insert_with(HashSet::new)
                .insert(conn.process_id);

            if let Some(group) = groups.get_mut(&key) {
                // Aggregate into existing group
                group.connection_count += 1;
                group.total_bytes_sent += conn.bytes_sent;
                group.total_bytes_received += conn.bytes_received;
                group.is_any_active = group.is_any_active || conn.is_active;

                // Add port if not already present
                if !group.ports.contains(&conn.remote_port) {
                    group.ports.push(conn.remote_port);
                }

                // Add protocol if not already present
                if !group.protocols.contains(&conn.protocol) {
                    group.protocols.push(conn.protocol);
                }

                // Update auth status to most restrictive
                group.auth_status = Self::most_restrictive_auth(group.auth_status, conn.auth_status);

                // Keep earliest first_seen
                if conn.first_seen < group.first_seen {
                    group.first_seen = conn.first_seen.clone();
                }
            } else {
                // Create new group
                groups.insert(key, GroupedConnection {
                    process_name: conn.process_name.clone(),
                    destination: conn.destination.clone(),
                    ports: vec![conn.remote_port],
                    protocols: vec![conn.protocol],
                    connection_count: 1,
                    pid_count: 1, // Will be updated after
                    total_bytes_sent: conn.bytes_sent,
                    total_bytes_received: conn.bytes_received,
                    first_seen: conn.first_seen.clone(),
                    is_any_active: conn.is_active,
                    auth_status: conn.auth_status,
                });
            }
        }

        // Update PID counts
        for (key, group) in groups.iter_mut() {
            if let Some(pids) = pids_seen.get(key) {
                group.pid_count = pids.len();
            }
        }

        // Convert to sorted vec
        // Primary sort: by process name (alphabetical)
        // Secondary sort: by total bytes (descending)
        let mut grouped: Vec<GroupedConnection> = groups.into_values().collect();
        grouped.sort_by(|a, b| {
            // First by process name
            match a.process_name.to_lowercase().cmp(&b.process_name.to_lowercase()) {
                std::cmp::Ordering::Equal => {
                    // Then by bytes (descending)
                    (b.total_bytes_sent + b.total_bytes_received)
                        .cmp(&(a.total_bytes_sent + a.total_bytes_received))
                }
                other => other,
            }
        });

        self.grouped_connections = grouped;

        // Reset selection if out of bounds
        if self.selected_grouped >= self.grouped_connections.len() && !self.grouped_connections.is_empty() {
            self.selected_grouped = self.grouped_connections.len() - 1;
        }
    }

    /// Helper to determine most restrictive auth status
    fn most_restrictive_auth(a: AuthStatus, b: AuthStatus) -> AuthStatus {
        // DENY > PENDING > SILENT_ALLOW > AUTO > ALLOW
        let priority = |status: AuthStatus| -> u8 {
            match status {
                AuthStatus::Deny => 5,
                AuthStatus::Pending => 4,
                AuthStatus::SilentAllow => 3,
                AuthStatus::Auto => 2,
                AuthStatus::Allow => 1,
            }
        };

        if priority(a) >= priority(b) { a } else { b }
    }

    /// Toggle view mode and recompute if switching to grouped
    pub fn toggle_view_mode(&mut self) {
        self.view_mode = self.view_mode.toggle();
        if self.view_mode == ViewMode::Grouped {
            self.compute_grouped_connections();
        }
    }

    /// Adjust grouped scroll offset to keep selection visible
    pub fn adjust_grouped_scroll(&mut self, visible_rows: usize) {
        if visible_rows == 0 {
            return;
        }
        if self.selected_grouped < self.grouped_scroll_offset {
            self.grouped_scroll_offset = self.selected_grouped;
        }
        if self.selected_grouped >= self.grouped_scroll_offset + visible_rows {
            self.grouped_scroll_offset = self.selected_grouped.saturating_sub(visible_rows - 1);
        }
    }

    /// Toggle info popup visibility
    pub fn toggle_info_popup(&mut self) {
        self.show_info_popup = !self.show_info_popup;
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

    // IPv4 address patterns
    if remote_str.starts_with("224.") || remote_str.starts_with("239.") {
        return "System (multicast)".to_string();
    }
    if remote_str.starts_with("169.254.") {
        return "System (link-local)".to_string();
    }
    if remote_str == "255.255.255.255" {
        return "System (broadcast)".to_string();
    }
    if remote_str.starts_with("127.") {
        return "localhost".to_string();
    }

    // IPv6 address patterns
    if entry.is_ipv6 {
        // IPv6 loopback ::1
        if remote_str == "::1" {
            return "localhost (IPv6)".to_string();
        }
        // IPv6 link-local fe80::/10
        if remote_str.starts_with("fe80:") || remote_str.starts_with("fe8") ||
           remote_str.starts_with("fe9") || remote_str.starts_with("fea") ||
           remote_str.starts_with("feb") {
            return "System (IPv6 link-local)".to_string();
        }
        // IPv6 multicast ff00::/8
        if remote_str.starts_with("ff") {
            return "System (IPv6 multicast)".to_string();
        }
        // IPv6 unique local (fc00::/7 = fc or fd prefix)
        if remote_str.starts_with("fc") || remote_str.starts_with("fd") {
            return "System (IPv6 ULA)".to_string();
        }
        // IPv4-mapped IPv6 ::ffff:x.x.x.x
        if remote_str.starts_with("::ffff:") {
            return "System (IPv4-mapped)".to_string();
        }
        // Generic IPv6
        return "System (IPv6)".to_string();
    }

    // Generic fallback
    "System".to_string()
}
