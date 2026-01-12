//! DNS resolution and caching for domain-based blocking
//!
//! Provides both reverse lookups (IP → domain) and forward caching (domain → IPs)
//! to support domain-based firewall rules.

use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Type alias for our resolver
type TokioResolver = Resolver<TokioConnectionProvider>;

/// DNS resolver instance
static RESOLVER: Lazy<TokioResolver> = Lazy::new(|| {
    Resolver::builder_with_config(
        ResolverConfig::default(),
        TokioConnectionProvider::default(),
    )
    .build()
});

/// Cache for reverse DNS lookups (IP → hostname)
static REVERSE_CACHE: Lazy<Mutex<HashMap<IpAddr, ReverseCacheEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Cache for forward DNS lookups (domain → IPs)
/// This is critical for domain-based blocking rules
static FORWARD_CACHE: Lazy<Mutex<ForwardDnsCache>> =
    Lazy::new(|| Mutex::new(ForwardDnsCache::new()));

struct ReverseCacheEntry {
    hostname: Option<String>,
    timestamp: Instant,
}

/// Forward DNS cache supporting domain → IPs and IP → domains lookups
struct ForwardDnsCache {
    /// domain → set of IPs that resolve to it
    domain_to_ips: HashMap<String, ForwardCacheEntry>,
    /// IP → set of domains that resolve to it (reverse index)
    ip_to_domains: HashMap<IpAddr, HashSet<String>>,
}

struct ForwardCacheEntry {
    ips: HashSet<IpAddr>,
    timestamp: Instant,
}

impl ForwardDnsCache {
    fn new() -> Self {
        Self {
            domain_to_ips: HashMap::new(),
            ip_to_domains: HashMap::new(),
        }
    }

    /// Add a domain → IP mapping
    fn insert(&mut self, domain: &str, ips: Vec<IpAddr>) {
        let domain_lower = domain.to_lowercase();
        let ip_set: HashSet<IpAddr> = ips.into_iter().collect();

        // Update domain → IPs
        self.domain_to_ips.insert(
            domain_lower.clone(),
            ForwardCacheEntry {
                ips: ip_set.clone(),
                timestamp: Instant::now(),
            },
        );

        // Update reverse index (IP → domains)
        for ip in &ip_set {
            self.ip_to_domains
                .entry(*ip)
                .or_insert_with(HashSet::new)
                .insert(domain_lower.clone());
        }

        // Limit cache size
        if self.domain_to_ips.len() > 10000 {
            self.cleanup();
        }
    }

    /// Get domains that resolve to an IP
    fn get_domains_for_ip(&self, ip: &IpAddr) -> Vec<String> {
        self.ip_to_domains
            .get(ip)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get IPs for a domain
    fn get_ips_for_domain(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let domain_lower = domain.to_lowercase();
        self.domain_to_ips.get(&domain_lower).and_then(|entry| {
            if entry.timestamp.elapsed() < CACHE_TTL {
                Some(entry.ips.iter().copied().collect())
            } else {
                None
            }
        })
    }

    fn cleanup(&mut self) {
        let now = Instant::now();

        // Remove expired domain entries
        let expired: Vec<String> = self.domain_to_ips
            .iter()
            .filter(|(_, v)| now.duration_since(v.timestamp) >= CACHE_TTL)
            .map(|(k, _)| k.clone())
            .collect();

        for domain in expired {
            if let Some(entry) = self.domain_to_ips.remove(&domain) {
                // Also clean up reverse index
                for ip in entry.ips {
                    if let Some(domains) = self.ip_to_domains.get_mut(&ip) {
                        domains.remove(&domain);
                        if domains.is_empty() {
                            self.ip_to_domains.remove(&ip);
                        }
                    }
                }
            }
        }
    }
}

const CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes

/// Get cached reverse DNS result only - NO network lookup (for real-time performance)
pub fn get_cached_reverse(addr: IpAddr) -> Option<String> {
    let cache = REVERSE_CACHE.lock().unwrap();
    if let Some(entry) = cache.get(&addr) {
        if entry.timestamp.elapsed() < CACHE_TTL {
            return entry.hostname.clone();
        }
    }
    None
}

/// Get domains that resolve to this IP from forward cache (for domain-based rules)
pub fn get_domains_for_ip(addr: IpAddr) -> Vec<String> {
    let cache = FORWARD_CACHE.lock().unwrap();
    cache.get_domains_for_ip(&addr)
}

/// Get IPs for a domain from forward cache
pub fn get_ips_for_domain(domain: &str) -> Option<Vec<IpAddr>> {
    let cache = FORWARD_CACHE.lock().unwrap();
    cache.get_ips_for_domain(domain)
}

/// Perform reverse DNS lookup with caching
pub async fn reverse_lookup(addr: IpAddr) -> Option<String> {
    // Check cache
    {
        let cache = REVERSE_CACHE.lock().unwrap();
        if let Some(entry) = cache.get(&addr) {
            if entry.timestamp.elapsed() < CACHE_TTL {
                return entry.hostname.clone();
            }
        }
    }

    // Perform lookup
    let hostname = do_reverse_lookup(addr).await;

    // Cache result
    {
        let mut cache = REVERSE_CACHE.lock().unwrap();
        cache.insert(
            addr,
            ReverseCacheEntry {
                hostname: hostname.clone(),
                timestamp: Instant::now(),
            },
        );

        // Limit cache size
        if cache.len() > 5000 {
            // Remove old entries
            let now = Instant::now();
            cache.retain(|_, v| now.duration_since(v.timestamp) < CACHE_TTL);
        }
    }

    hostname
}

async fn do_reverse_lookup(addr: IpAddr) -> Option<String> {
    match tokio::time::timeout(Duration::from_millis(500), RESOLVER.reverse_lookup(addr)).await {
        Ok(Ok(lookup)) => lookup.iter().next().map(|name| {
            let s = name.to_string();
            // Remove trailing dot
            s.trim_end_matches('.').to_string()
        }),
        _ => None,
    }
}

/// Resolve a domain and cache the IPs (for domain-based rule matching)
pub async fn resolve_domain(domain: &str) -> Vec<IpAddr> {
    // Check cache first
    if let Some(ips) = get_ips_for_domain(domain) {
        return ips;
    }

    // Perform lookup
    let ips = do_forward_lookup(domain).await;

    // Cache result (even if empty, to avoid repeated lookups)
    if !ips.is_empty() {
        let mut cache = FORWARD_CACHE.lock().unwrap();
        cache.insert(domain, ips.clone());
    }

    ips
}

async fn do_forward_lookup(domain: &str) -> Vec<IpAddr> {
    let mut ips = Vec::new();

    // Try IPv4 lookup
    if let Ok(Ok(lookup)) = tokio::time::timeout(
        Duration::from_millis(500),
        RESOLVER.ipv4_lookup(domain),
    )
    .await
    {
        ips.extend(lookup.iter().map(|a| IpAddr::V4(a.0)));
    }

    // Try IPv6 lookup
    if let Ok(Ok(lookup)) = tokio::time::timeout(
        Duration::from_millis(500),
        RESOLVER.ipv6_lookup(domain),
    )
    .await
    {
        ips.extend(lookup.iter().map(|a| IpAddr::V6(a.0)));
    }

    ips
}

/// Manually cache a domain → IP mapping (e.g., from DNS interception)
pub fn cache_domain_mapping(domain: &str, ips: Vec<IpAddr>) {
    if ips.is_empty() {
        return;
    }
    let mut cache = FORWARD_CACHE.lock().unwrap();
    cache.insert(domain, ips);
}

/// Check if an IP matches any cached domain (for rule evaluation)
/// Returns true if the IP resolves to any of the given domains
pub fn ip_matches_domain(addr: IpAddr, domain_pattern: &str) -> bool {
    let domains = get_domains_for_ip(addr);
    let pattern_lower = domain_pattern.to_lowercase();

    for domain in domains {
        // Exact match
        if domain == pattern_lower {
            return true;
        }
        // Wildcard match: *.example.com matches sub.example.com
        if pattern_lower.starts_with("*.") {
            let suffix = &pattern_lower[1..]; // ".example.com"
            if domain.ends_with(suffix) {
                return true;
            }
        }
    }
    false
}

/// Try to find a domain for an IP using multiple strategies
/// 1. Check forward cache (fastest - IP→domain from pre-resolved domains)
/// 2. Check if IP is in any monitored domain's IP set
/// 3. Fall back to cached reverse DNS
pub fn find_domain_for_ip(addr: IpAddr) -> Option<String> {
    // Strategy 1: Direct lookup from forward cache reverse index
    let forward_domains = get_domains_for_ip(addr);
    if !forward_domains.is_empty() {
        return Some(forward_domains[0].clone());
    }

    // Strategy 2: Check if this IP is in any domain's IP set
    // This handles cases where the exact IP wasn't in the reverse index
    // but we have the domain→IPs mapping
    {
        let cache = FORWARD_CACHE.lock().unwrap();
        for (domain, entry) in cache.domain_to_ips.iter() {
            if entry.ips.contains(&addr) {
                return Some(domain.clone());
            }
        }
    }

    // Strategy 3: Fall back to reverse DNS cache
    get_cached_reverse(addr)
}

/// Check if an IP belongs to any monitored domain by checking all cached domain→IP mappings
pub fn ip_belongs_to_monitored_domain(addr: IpAddr) -> Option<String> {
    let cache = FORWARD_CACHE.lock().unwrap();
    for (domain, entry) in cache.domain_to_ips.iter() {
        if entry.ips.contains(&addr) {
            return Some(domain.clone());
        }
    }
    None
}

/// Get all monitored domains and their IPs (for debugging)
pub fn get_all_cached_domains() -> Vec<(String, Vec<IpAddr>)> {
    let cache = FORWARD_CACHE.lock().unwrap();
    cache.domain_to_ips
        .iter()
        .map(|(domain, entry)| (domain.clone(), entry.ips.iter().copied().collect()))
        .collect()
}

/// Get a friendly name for well-known IP ranges
pub fn get_ip_context(addr: IpAddr) -> Option<&'static str> {
    match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();

            // Google
            if octets[0] == 142 && octets[1] == 250 {
                return Some("Google");
            }
            if octets[0] == 172 && octets[1] == 217 {
                return Some("Google");
            }

            // Microsoft/Azure
            if octets[0] == 13 || octets[0] == 20 || octets[0] == 40 || octets[0] == 52 {
                return Some("Microsoft Azure");
            }
            if octets[0] == 104 && octets[1] >= 40 && octets[1] <= 47 {
                return Some("Microsoft");
            }

            // Amazon AWS
            if octets[0] == 54 || octets[0] == 52 || octets[0] == 18 || octets[0] == 3 {
                return Some("Amazon AWS");
            }

            // Cloudflare
            if octets[0] == 104 && (octets[1] >= 16 && octets[1] <= 31) {
                return Some("Cloudflare");
            }
            if octets[0] == 1 && octets[1] == 1 && octets[2] == 1 {
                return Some("Cloudflare DNS");
            }

            // Akamai
            if octets[0] == 23 || octets[0] == 184 {
                return Some("Akamai CDN");
            }

            // Private ranges
            if octets[0] == 10 {
                return Some("Private Network");
            }
            if octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31 {
                return Some("Private Network");
            }
            if octets[0] == 192 && octets[1] == 168 {
                return Some("Local Network");
            }
            if octets[0] == 127 {
                return Some("Localhost");
            }

            None
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return Some("Localhost");
            }
            None
        }
    }
}

/// Get port service name
pub fn get_service_name(port: u16) -> Option<&'static str> {
    match port {
        20 => Some("FTP Data"),
        21 => Some("FTP"),
        22 => Some("SSH"),
        23 => Some("Telnet"),
        25 => Some("SMTP"),
        53 => Some("DNS"),
        80 => Some("HTTP"),
        110 => Some("POP3"),
        143 => Some("IMAP"),
        443 => Some("HTTPS"),
        445 => Some("SMB"),
        465 => Some("SMTPS"),
        587 => Some("SMTP Submission"),
        993 => Some("IMAPS"),
        995 => Some("POP3S"),
        1433 => Some("MSSQL"),
        1521 => Some("Oracle"),
        3306 => Some("MySQL"),
        3389 => Some("RDP"),
        5432 => Some("PostgreSQL"),
        5900 => Some("VNC"),
        6379 => Some("Redis"),
        8080 => Some("HTTP Proxy"),
        8443 => Some("HTTPS Alt"),
        27017 => Some("MongoDB"),
        _ => None,
    }
}
