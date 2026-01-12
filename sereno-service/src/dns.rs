//! DNS resolution and reverse lookups

use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;
use once_cell::sync::Lazy;
use std::collections::HashMap;
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

/// Cache for reverse DNS lookups
static DNS_CACHE: Lazy<Mutex<HashMap<IpAddr, CacheEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

struct CacheEntry {
    hostname: Option<String>,
    timestamp: Instant,
}

const CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes

/// Get cached DNS result only - NO network lookup (for real-time performance)
pub fn get_cached(addr: IpAddr) -> Option<String> {
    let cache = DNS_CACHE.lock().unwrap();
    if let Some(entry) = cache.get(&addr) {
        if entry.timestamp.elapsed() < CACHE_TTL {
            return entry.hostname.clone();
        }
    }
    None
}

/// Perform reverse DNS lookup with caching
pub async fn reverse_lookup(addr: IpAddr) -> Option<String> {
    // Check cache
    {
        let cache = DNS_CACHE.lock().unwrap();
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
        let mut cache = DNS_CACHE.lock().unwrap();
        cache.insert(
            addr,
            CacheEntry {
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
