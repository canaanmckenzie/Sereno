//! TUI Application State

use sereno_core::types::Rule;
use std::collections::{HashSet, VecDeque};

/// Active tab in the TUI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Monitor,
    Rules,
    Logs,
    Settings,
}

impl Tab {
    pub fn next(self) -> Self {
        match self {
            Tab::Monitor => Tab::Rules,
            Tab::Rules => Tab::Logs,
            Tab::Logs => Tab::Settings,
            Tab::Settings => Tab::Monitor,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Tab::Monitor => Tab::Settings,
            Tab::Rules => Tab::Monitor,
            Tab::Logs => Tab::Rules,
            Tab::Settings => Tab::Logs,
        }
    }

    pub fn all() -> [Tab; 4] {
        [Tab::Monitor, Tab::Rules, Tab::Logs, Tab::Settings]
    }

    pub fn label(self) -> &'static str {
        match self {
            Tab::Monitor => "Monitor",
            Tab::Rules => "Rules",
            Tab::Logs => "Logs",
            Tab::Settings => "Settings",
        }
    }

    pub fn key(self) -> char {
        match self {
            Tab::Monitor => '1',
            Tab::Rules => '2',
            Tab::Logs => '3',
            Tab::Settings => '4',
        }
    }
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
            Tab::Rules => {
                if self.selected_rule < self.rules.len().saturating_sub(1) {
                    self.selected_rule += 1;
                }
            }
            _ => {}
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
}
