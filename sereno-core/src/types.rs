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
    /// ICMPv6 (protocol 58)
    Icmpv6,
    /// GRE tunnel (protocol 47)
    Gre,
    /// IPSec ESP (protocol 50)
    Esp,
    /// IPSec AH (protocol 51)
    Ah,
    /// IGMP (protocol 2)
    Igmp,
    /// Other/unknown protocol with raw protocol number
    Other(u8),
    Any,
}

impl Protocol {
    /// Convert from raw IP protocol number
    pub fn from_protocol_number(proto: u8) -> Self {
        match proto {
            1 => Protocol::Icmp,
            2 => Protocol::Igmp,
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            47 => Protocol::Gre,
            50 => Protocol::Esp,
            51 => Protocol::Ah,
            58 => Protocol::Icmpv6,
            _ => Protocol::Other(proto),
        }
    }

    /// Get the raw IP protocol number
    pub fn protocol_number(&self) -> Option<u8> {
        match self {
            Protocol::Tcp => Some(6),
            Protocol::Udp => Some(17),
            Protocol::Icmp => Some(1),
            Protocol::Icmpv6 => Some(58),
            Protocol::Gre => Some(47),
            Protocol::Esp => Some(50),
            Protocol::Ah => Some(51),
            Protocol::Igmp => Some(2),
            Protocol::Other(n) => Some(*n),
            Protocol::Any => None,
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Icmp => write!(f, "icmp"),
            Protocol::Icmpv6 => write!(f, "icmpv6"),
            Protocol::Gre => write!(f, "gre"),
            Protocol::Esp => write!(f, "esp"),
            Protocol::Ah => write!(f, "ah"),
            Protocol::Igmp => write!(f, "igmp"),
            Protocol::Other(n) => write!(f, "proto:{}", n),
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
