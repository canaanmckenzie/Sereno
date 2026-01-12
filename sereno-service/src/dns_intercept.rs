//! DNS interception for domain-based blocking
//!
//! Two approaches:
//! 1. Rule-based pre-resolution: Resolve domains mentioned in rules upfront
//! 2. ETW-based interception: Capture DNS queries in real-time (future)

use crate::dns;
use sereno_core::types::{Condition, DomainPattern, Rule};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Domains we're actively monitoring for DNS resolution
static MONITORED_DOMAINS: once_cell::sync::Lazy<Arc<RwLock<HashSet<String>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(HashSet::new())));

/// Add a domain to monitor for DNS resolution
pub async fn monitor_domain(domain: &str) {
    let domain_lower = domain.to_lowercase();

    // Add to monitored set
    {
        let mut monitored = MONITORED_DOMAINS.write().await;
        if monitored.contains(&domain_lower) {
            return; // Already monitoring
        }
        monitored.insert(domain_lower.clone());
    }

    // Resolve immediately and cache
    let ips = dns::resolve_domain(&domain_lower).await;
    if !ips.is_empty() {
        info!("Pre-resolved {} -> {:?}", domain_lower, ips);
    } else {
        warn!("Failed to resolve domain: {}", domain_lower);
    }
}

/// Remove a domain from monitoring
pub async fn unmonitor_domain(domain: &str) {
    let domain_lower = domain.to_lowercase();
    let mut monitored = MONITORED_DOMAINS.write().await;
    monitored.remove(&domain_lower);
}

/// Refresh DNS resolution for all monitored domains
pub async fn refresh_all() {
    let domains: Vec<String> = {
        let monitored = MONITORED_DOMAINS.read().await;
        monitored.iter().cloned().collect()
    };

    for domain in domains {
        let ips = dns::resolve_domain(&domain).await;
        if !ips.is_empty() {
            debug!("Refreshed {} -> {:?}", domain, ips);
        }
    }
}

/// Check if an IP matches any monitored domain by doing a fresh DNS lookup
/// This is used when the IP isn't in our cache - we re-resolve all domains
/// and check if any of them now resolve to this IP
pub async fn resolve_and_check_ip(addr: std::net::IpAddr) -> Option<String> {
    let domains: Vec<String> = {
        let monitored = MONITORED_DOMAINS.read().await;
        monitored.iter().cloned().collect()
    };

    for domain in domains {
        // Get fresh IPs for this domain
        let ips = dns::resolve_domain(&domain).await;
        if ips.contains(&addr) {
            info!("Re-resolved {} -> {:?} (matched {})", domain, ips, addr);
            return Some(domain);
        }
    }
    None
}

/// Get number of monitored domains
pub async fn monitored_count() -> usize {
    let monitored = MONITORED_DOMAINS.read().await;
    monitored.len()
}

/// Get list of currently monitored domains
pub async fn list_monitored() -> Vec<String> {
    let monitored = MONITORED_DOMAINS.read().await;
    monitored.iter().cloned().collect()
}

/// Parse a rule target to extract domain if present
/// Returns Some(domain) if the target is a domain pattern
pub fn extract_domain_from_rule(target: &str) -> Option<String> {
    let target = target.trim();

    // Skip if it looks like an IP address
    if target.parse::<IpAddr>().is_ok() {
        return None;
    }

    // Skip if it looks like a CIDR range
    if target.contains('/') && target.split('/').next().map(|s| s.parse::<IpAddr>().is_ok()).unwrap_or(false) {
        return None;
    }

    // Strip wildcard prefix for resolution
    let domain = if target.starts_with("*.") {
        &target[2..]
    } else {
        target
    };

    // Basic domain validation
    if domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.') {
        Some(domain.to_lowercase())
    } else {
        None
    }
}

/// Extract all domain patterns from a condition (recursive)
fn extract_domains_from_condition(condition: &Condition, domains: &mut HashSet<String>) {
    match condition {
        Condition::Domain { patterns } => {
            for pattern in patterns {
                match pattern {
                    DomainPattern::Exact { value } => {
                        domains.insert(value.to_lowercase());
                    }
                    DomainPattern::Wildcard { pattern } => {
                        // For wildcard *.example.com, resolve example.com
                        let base = if pattern.starts_with("*.") {
                            &pattern[2..]
                        } else {
                            pattern.as_str()
                        };
                        domains.insert(base.to_lowercase());
                    }
                    DomainPattern::Regex { .. } => {
                        // Can't pre-resolve regex patterns
                    }
                }
            }
        }
        Condition::And { conditions } | Condition::Or { conditions } => {
            for cond in conditions {
                extract_domains_from_condition(cond, domains);
            }
        }
        Condition::Not { condition } => {
            extract_domains_from_condition(condition, domains);
        }
        _ => {}
    }
}

/// Extract all domains from a list of rules
pub fn extract_domains_from_rules(rules: &[Rule]) -> HashSet<String> {
    let mut domains = HashSet::new();
    for rule in rules {
        if !rule.enabled {
            continue;
        }
        for condition in &rule.conditions {
            extract_domains_from_condition(condition, &mut domains);
        }
    }
    domains
}

/// Pre-resolve all domains found in rules
pub async fn preload_domains_from_rules(rules: &[Rule]) {
    let domains = extract_domains_from_rules(rules);

    if domains.is_empty() {
        debug!("No domain patterns found in rules");
        return;
    }

    info!("Pre-resolving {} domain(s) from rules", domains.len());

    for domain in domains {
        monitor_domain(&domain).await;
    }
}

/// Check if an IP matches any domain pattern in our cache
/// This is used during rule evaluation when we only have an IP
pub fn check_ip_for_domain_match(addr: IpAddr, pattern: &DomainPattern) -> bool {
    match pattern {
        DomainPattern::Exact { value } => {
            dns::ip_matches_domain(addr, value)
        }
        DomainPattern::Wildcard { pattern } => {
            dns::ip_matches_domain(addr, pattern)
        }
        DomainPattern::Regex { pattern: _ } => {
            // For regex, we need the actual domain string
            // Check if any cached domain for this IP matches the regex
            let domains = dns::get_domains_for_ip(addr);
            if domains.is_empty() {
                return false;
            }
            // Regex matching would need to be done by caller
            // For now, return false (requires domain string)
            false
        }
    }
}

// ============================================================================
// ETW-based DNS interception (skeleton for future implementation)
// ============================================================================
//
// The Microsoft-Windows-DNS-Client ETW provider (GUID: {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D})
// can be used to intercept DNS queries in real-time.
//
// Events of interest:
// - Event ID 3006: DNS query sent
// - Event ID 3008: DNS response received (contains resolved IPs)
// - Event ID 3020: DNS query completed
//
// Implementation would require:
// 1. StartTrace() to create a trace session
// 2. EnableTraceEx2() to enable the DNS provider
// 3. ProcessTrace() in a dedicated thread to receive events
// 4. Parse TDH (Trace Data Helper) formatted events
//
// This requires admin privileges and is more complex than rule-based pre-resolution.
// For now, the simpler approach works well for static domain rules.

#[cfg(windows)]
pub mod etw {
    use tracing::info;

    /// Placeholder for future ETW-based DNS interception
    /// Currently not implemented - using rule-based pre-resolution instead
    pub fn start_dns_trace() -> Result<(), String> {
        info!("ETW DNS tracing not yet implemented - using rule-based pre-resolution");
        Ok(())
    }

    pub fn stop_dns_trace() {
        // No-op for now
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain() {
        assert_eq!(extract_domain_from_rule("google.com"), Some("google.com".into()));
        assert_eq!(extract_domain_from_rule("*.google.com"), Some("google.com".into()));
        assert_eq!(extract_domain_from_rule("sub.domain.com"), Some("sub.domain.com".into()));
        assert_eq!(extract_domain_from_rule("192.168.1.1"), None);
        assert_eq!(extract_domain_from_rule("10.0.0.0/8"), None);
        assert_eq!(extract_domain_from_rule("localhost"), None); // no dot
    }
}
