use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

/// Network protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Icmp => write!(f, "icmp"),
            Protocol::Any => write!(f, "any"),
        }
    }
}

/// Connection direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Inbound,
    Outbound,
    Any,
}

/// Action to take on a connection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
    Ask,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Allow => write!(f, "allow"),
            Action::Deny => write!(f, "deny"),
            Action::Ask => write!(f, "ask"),
        }
    }
}

/// Rule validity period
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Validity {
    Permanent,
    UntilQuit { process_id: u32 },
    Once,
    Timed { expires_at: DateTime<Utc> },
}

/// Domain matching pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DomainPattern {
    Exact { value: String },
    Wildcard { pattern: String },
    Regex { pattern: String },
}

/// Port matching
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PortMatcher {
    Single { port: u16 },
    Range { start: u16, end: u16 },
    List { ports: Vec<u16> },
    Any,
}

/// IP address matching
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpMatcher {
    Single { address: String },
    Cidr { network: String },
    List { addresses: Vec<String> },
    Any,
}

/// Rule condition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Condition {
    ProcessPath { pattern: String },
    ProcessName { pattern: String },
    RemoteAddress { matcher: IpMatcher },
    RemotePort { matcher: PortMatcher },
    LocalPort { matcher: PortMatcher },
    Protocol { protocol: Protocol },
    Domain { patterns: Vec<DomainPattern> },
    Direction { direction: Direction },
    And { conditions: Vec<Condition> },
    Or { conditions: Vec<Condition> },
    Not { condition: Box<Condition> },
}

/// A firewall rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub priority: i32,
    pub action: Action,
    pub conditions: Vec<Condition>,
    pub validity: Validity,
    pub hit_count: u64,
    pub created_at: DateTime<Utc>,
    pub profile_id: Option<String>,
}

impl Rule {
    pub fn new(name: impl Into<String>, action: Action, conditions: Vec<Condition>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.into(),
            enabled: true,
            priority: 0,
            action,
            conditions,
            validity: Validity::Permanent,
            hit_count: 0,
            created_at: Utc::now(),
            profile_id: None,
        }
    }
}

/// A network profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub is_active: bool,
    pub silent_mode: Option<SilentMode>,
    pub created_at: DateTime<Utc>,
}

/// Silent mode settings
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SilentMode {
    AllowAll,
    DenyAll,
}

/// A network connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub id: String,
    pub process_path: String,
    pub process_name: String,
    pub process_id: u32,
    pub remote_address: IpAddr,
    pub remote_port: u16,
    pub local_port: u16,
    pub protocol: Protocol,
    pub direction: Direction,
    pub domain: Option<String>,
    pub country: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub allowed: bool,
    pub rule_id: Option<String>,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
}

/// Context for evaluating rules against a connection
#[derive(Debug, Clone)]
pub struct ConnectionContext {
    pub process_path: String,
    pub process_name: String,
    pub process_id: u32,
    pub remote_address: IpAddr,
    pub remote_port: u16,
    pub local_port: u16,
    pub protocol: Protocol,
    pub direction: Direction,
    pub domain: Option<String>,
}

/// Result of rule evaluation
#[derive(Debug, Clone)]
pub enum EvalResult {
    Allow { rule_id: String },
    Deny { rule_id: String },
    Ask,
}
