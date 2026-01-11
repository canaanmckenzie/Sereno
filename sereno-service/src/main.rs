//! Sereno Service - Production-grade network firewall service
//!
//! Features from SERENO_BUILD_GUIDE.md:
//! - Real-time connection monitoring
//! - Per-application rules
//! - Domain/IP/Port filtering
//! - WFP integration for blocking
//! - Kernel driver for synchronous pre-connection filtering
//! - Process identification with publisher info
//! - DNS reverse lookup
//! - Connection logging

mod dns;
mod driver;
mod process;
mod wfp;

use anyhow::Result;
use colored::*;
use sereno_core::{
    database::Database,
    rule_engine::RuleEngine,
    types::{Connection, ConnectionContext, Direction, EvalResult, Protocol},
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Connection event from the network monitor
#[derive(Debug, Clone)]
pub struct ConnectionEvent {
    pub id: u64,
    pub process_path: String,
    pub process_name: String,
    pub process_id: u32,
    pub publisher: Option<String>,
    pub remote_address: std::net::IpAddr,
    pub remote_port: u16,
    pub local_port: u16,
    pub protocol: Protocol,
    pub direction: Direction,
    pub domain: Option<String>,
}

/// Verdict to send back to driver
#[derive(Debug, Clone, Copy)]
pub enum Verdict {
    Allow,
    Block,
}

fn print_banner() {
    println!();
    println!("{}", "╔═══════════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║                     SERENO NETWORK MONITOR                     ║".cyan());
    println!("{}", "║              Production-Grade Application Firewall             ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════════╝".cyan());
    println!();
}

fn format_connection(
    action: &str,
    action_color: colored::Color,
    process_name: &str,
    publisher: Option<&str>,
    remote: &str,
    port: u16,
    service: Option<&str>,
    domain: Option<&str>,
    ip_context: Option<&str>,
    rule_name: Option<&str>,
    blocked_by: Option<&str>,
) {
    let action_str = format!(" {:^7} ", action).color(action_color).bold();
    let process_str = process_name.white().bold();
    let publisher_str = publisher
        .map(|p| format!(" ({})", p).dimmed().to_string())
        .unwrap_or_default();

    let dest = if let Some(d) = domain {
        format!("{}", d.yellow())
    } else if let Some(ctx) = ip_context {
        format!("{} ({})", remote.yellow(), ctx.dimmed())
    } else {
        format!("{}", remote.yellow())
    };

    let port_str = if let Some(svc) = service {
        format!(":{} ({})", port.to_string().cyan(), svc.dimmed())
    } else {
        format!(":{}", port.to_string().cyan())
    };

    let rule_str = rule_name
        .map(|r| format!(" [{}]", r).dimmed().to_string())
        .unwrap_or_default();

    let block_indicator = match blocked_by {
        Some("KERNEL") => " [BLOCKED]".red().bold().to_string(),
        Some("WFP") => " [WFP]".red().to_string(),
        _ => String::new(),
    };

    println!(
        "{}│ {}{} → {}{}{}{}",
        action_str, process_str, publisher_str, dest, port_str, rule_str, block_indicator
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("sereno_service=info,sereno_core=info")
        .with_target(false)
        .without_time()
        .init();

    print_banner();

    // Determine database path
    let db_path = std::env::var("SERENO_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("sereno")
                .join("sereno.db")
        });

    // Ensure directory exists
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    println!("{} {}", "Database:".dimmed(), db_path.display());

    let db = Database::open(&db_path)?;
    let engine = Arc::new(RuleEngine::new(db.clone())?);

    // Show rule stats
    let rules = engine.rules();
    let enabled_count = rules.iter().filter(|r| r.enabled).count();
    println!(
        "{} {} total, {} enabled",
        "Rules:".dimmed(),
        rules.len(),
        enabled_count
    );

    // Initialize WFP
    let mut wfp_engine: Option<Arc<wfp::WfpEngine>> = None;
    let mut blocking_manager: Option<wfp::BlockingManager> = None;

    #[cfg(windows)]
    {
        match wfp::WfpEngine::open() {
            Ok(engine) => {
                println!("{} {}", "WFP Engine:".dimmed(), "Active".green());
                if let Err(e) = engine.register_provider() {
                    println!(
                        "{} {} ({})",
                        "WFP Provider:".dimmed(),
                        "Failed".yellow(),
                        e
                    );
                } else {
                    println!("{} {}", "WFP Provider:".dimmed(), "Registered".green());
                    let arc_engine = Arc::new(engine);
                    blocking_manager = Some(wfp::BlockingManager::new(arc_engine.clone()));
                    wfp_engine = Some(arc_engine);
                }
            }
            Err(e) => {
                println!(
                    "{} {} - {}",
                    "WFP Engine:".dimmed(),
                    "Unavailable".yellow(),
                    "Run as Administrator for blocking".dimmed()
                );
                if std::env::var("SERENO_DEBUG").is_ok() {
                    println!("  {}: {}", "Error".dimmed(), e);
                }
            }
        }
    }

    // Check for kernel driver
    let driver_available = driver::DriverHandle::is_available();
    if driver_available {
        println!("{} {}", "Kernel Driver:".dimmed(), "Available".green());
    } else {
        println!(
            "{} {} - {}",
            "Kernel Driver:".dimmed(),
            "Not loaded".yellow(),
            "Install SerenoFilter.sys for pre-connection blocking".dimmed()
        );
    }

    let wfp_enabled = wfp_engine.is_some();
    let mode_str = if driver_available {
        "Full Kernel (Synchronous Pre-Connection Blocking)".green()
    } else if wfp_enabled {
        "User-Mode WFP (Monitor + Post-Connection Block)".cyan()
    } else {
        "Monitor Only".yellow()
    };
    println!("{} {}", "Mode:".dimmed(), mode_str);

    // Show WFP filter stats
    if let Some(ref engine) = wfp_engine {
        println!(
            "{} {} active",
            "WFP Filters:".dimmed(),
            engine.filter_count()
        );
    }

    println!();
    println!("{}", "─".repeat(67).dimmed());
    println!(
        "{}",
        " ACTION │ PROCESS → DESTINATION:PORT".dimmed()
    );
    println!("{}", "─".repeat(67).dimmed());

    // Channel for connection events
    let (event_tx, mut event_rx) = mpsc::channel::<ConnectionEvent>(1000);
    let (verdict_tx, mut verdict_rx) = mpsc::channel::<(u64, Verdict)>(1000);

    // Driver service for sending verdicts (if available)
    let driver_service: Option<Arc<std::sync::Mutex<driver::DriverService>>> = if driver_available {
        let mut ds = driver::DriverService::new();
        if ds.connect().is_ok() {
            Some(Arc::new(std::sync::Mutex::new(ds)))
        } else {
            None
        }
    } else {
        None
    };

    // Start kernel driver loop or fall back to user-mode monitor
    if let Some(ref ds) = driver_service {
        let ds_clone = ds.clone();
        let event_tx_clone = event_tx.clone();

        // Driver polling task
        tokio::spawn(async move {
            loop {
                let request = {
                    let guard = ds_clone.lock().unwrap();
                    guard.get_pending()
                };

                match request {
                    Ok(Some(req)) => {
                        let process_info = process::get_process_info(req.process_id);
                        let event = ConnectionEvent {
                            id: req.request_id,
                            process_path: req.application_path.to_string_lossy().to_string(),
                            process_name: req
                                .application_path
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_else(|| "Unknown".to_string()),
                            process_id: req.process_id,
                            publisher: process_info.as_ref().and_then(|p| p.publisher.clone()),
                            remote_address: req.remote_address,
                            remote_port: req.remote_port,
                            local_port: req.local_port,
                            protocol: req.protocol,
                            direction: req.direction,
                            domain: req.domain_name,
                        };

                        if event_tx_clone.send(event).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    }
                    Err(e) => {
                        error!("Driver error: {}", e);
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                }
            }
        });

        // Verdict handler for driver
        let ds_verdict = ds.clone();
        tokio::spawn(async move {
            while let Some((request_id, verdict)) = verdict_rx.recv().await {
                let allow = matches!(verdict, Verdict::Allow);
                if let Ok(guard) = ds_verdict.lock() {
                    if let Err(e) = guard.set_verdict(request_id, allow) {
                        error!("Failed to send verdict to driver: {}", e);
                    }
                }
            }
        });
    } else {
        // Fall back to user-mode connection monitor
        let monitor = wfp::ConnectionMonitor::new();
        tokio::spawn(async move {
            let _ = monitor.run(event_tx, verdict_rx).await;
        });
    }

    let using_kernel_driver = driver_service.is_some();

    // Build rule name lookup
    let rule_names: std::collections::HashMap<String, String> = rules
        .iter()
        .map(|r| (r.id.clone(), r.name.clone()))
        .collect();

    // Track blocked IPs for this session (avoid duplicate blocks)
    let mut session_blocked_ips: std::collections::HashSet<std::net::IpAddr> =
        std::collections::HashSet::new();

    // Main event loop
    while let Some(event) = event_rx.recv().await {
        // Perform async DNS lookup
        let domain = if event.domain.is_some() {
            event.domain.clone()
        } else {
            dns::reverse_lookup(event.remote_address).await
        };

        let ctx = ConnectionContext {
            process_path: event.process_path.clone(),
            process_name: event.process_name.clone(),
            process_id: event.process_id,
            remote_address: event.remote_address,
            remote_port: event.remote_port,
            local_port: event.local_port,
            protocol: event.protocol,
            direction: event.direction,
            domain: domain.clone(),
        };

        let result = engine.evaluate(&ctx);

        let (verdict, allowed, action_str, action_color, rule_id) = match &result {
            EvalResult::Allow { rule_id } => (
                Verdict::Allow,
                true,
                "ALLOW",
                colored::Color::Green,
                Some(rule_id.clone()),
            ),
            EvalResult::Deny { rule_id } => (
                Verdict::Block,
                false,
                "DENY",
                colored::Color::Red,
                Some(rule_id.clone()),
            ),
            EvalResult::Ask => {
                // In production, this would trigger an alert
                // For now, allow and mark as "ASK"
                (Verdict::Allow, true, "ASK", colored::Color::Yellow, None)
            }
        };

        // Apply blocking for DENY verdicts
        let mut blocked_by = None;
        if matches!(verdict, Verdict::Block) {
            if using_kernel_driver {
                // Kernel driver handles blocking synchronously before connection
                blocked_by = Some("KERNEL");
            } else if wfp_enabled {
                // Fall back to user-mode WFP blocking (post-connection)
                if let Some(ref bm) = blocking_manager {
                    if !session_blocked_ips.contains(&event.remote_address) {
                        match bm.block_ip(event.remote_address) {
                            Ok(_) => {
                                session_blocked_ips.insert(event.remote_address);
                                blocked_by = Some("WFP");
                                info!("WFP: Blocked IP {}", event.remote_address);
                            }
                            Err(e) => {
                                warn!("WFP: Failed to block {}: {}", event.remote_address, e);
                            }
                        }
                    } else {
                        blocked_by = Some("WFP");
                    }
                }
            }
        }

        // Get rule name
        let rule_name = rule_id
            .as_ref()
            .and_then(|id| {
                if id.is_empty() {
                    None
                } else {
                    rule_names.get(id).map(|s| s.as_str())
                }
            });

        // Get service name and IP context
        let service = dns::get_service_name(event.remote_port);
        let ip_context = dns::get_ip_context(event.remote_address);

        // Print formatted output
        format_connection(
            action_str,
            action_color,
            &event.process_name,
            event.publisher.as_deref(),
            &event.remote_address.to_string(),
            event.remote_port,
            service,
            domain.as_deref(),
            ip_context,
            rule_name,
            blocked_by,
        );

        // Send verdict
        if verdict_tx.send((event.id, verdict)).await.is_err() {
            error!("Failed to send verdict");
        }

        // Log connection to database
        let conn = Connection {
            id: Uuid::new_v4().to_string(),
            process_path: event.process_path,
            process_name: event.process_name,
            process_id: event.process_id,
            remote_address: event.remote_address,
            remote_port: event.remote_port,
            local_port: event.local_port,
            protocol: event.protocol,
            direction: event.direction,
            domain,
            country: None,
            bytes_sent: 0,
            bytes_received: 0,
            allowed,
            rule_id: match result {
                EvalResult::Allow { rule_id } | EvalResult::Deny { rule_id } => {
                    if rule_id.is_empty() {
                        None
                    } else {
                        Some(rule_id)
                    }
                }
                EvalResult::Ask => None,
            },
            started_at: chrono::Utc::now(),
            ended_at: None,
        };

        if let Err(e) = db.log_connection(&conn) {
            error!("Failed to log connection: {}", e);
        }
    }

    // Cleanup on shutdown
    if let Some(ref bm) = blocking_manager {
        info!("Cleaning up {} blocked IPs", session_blocked_ips.len());
        bm.clear_all();
    }

    info!("Service shutting down");
    Ok(())
}
