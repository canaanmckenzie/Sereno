//! Terminal User Interface for Sereno Firewall
//!
//! Provides an interactive TUI for monitoring connections, managing rules,
//! and handling interactive prompts.

pub mod app;
pub mod events;
pub mod ui;

use crate::driver::{DriverHandle, DriverVerdict};
use anyhow::Result;
use app::{App, ConnectionEvent, DriverStatus, Mode};
use crossterm::{
    event::Event,
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use events::{handle_key_event, poll_event, EventResult};
use ratatui::{backend::CrosstermBackend, Terminal};
use sereno_core::{
    database::Database,
    rule_engine::RuleEngine,
    types::{ConnectionContext, EvalResult},
};
use std::{
    io::{self, stdout},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::sync::mpsc;

/// Run the TUI application (blocking wrapper for async)
pub fn run(db_path: &Path) -> Result<()> {
    // Build a runtime for async operations
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async(db_path))
}

/// Run the TUI application (async)
async fn run_async(db_path: &Path) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    // Initialize app state
    let mut app = App::new();

    // Load database and rules
    let db = Database::open(db_path)?;
    let engine = Arc::new(RuleEngine::new(db.clone())?);
    app.rules = engine.rules();
    app.log(format!("Loaded {} rules", app.rules.len()));

    // Check driver status and try to connect
    app.driver_status = check_driver_status();
    app.mode = if app.driver_status == DriverStatus::Running {
        Mode::KernelDriver
    } else {
        Mode::MonitorOnly
    };
    app.is_admin = is_running_as_admin();

    app.log(format!("Driver: {}", app.driver_status.label()));
    app.log(format!("Mode: {}", app.mode.label()));

    // Create channel for driver events
    let (conn_tx, mut conn_rx) = mpsc::channel::<DriverConnectionEvent>(100);

    // Start driver polling task if driver is available
    let driver_handle = if app.driver_status == DriverStatus::Running {
        match DriverHandle::open() {
            Ok(handle) => {
                app.log("Connected to driver".to_string());
                // Enable filtering
                if let Err(e) = handle.enable_filtering() {
                    app.log(format!("Warning: Could not enable filtering: {}", e));
                } else {
                    app.log("Driver filtering enabled".to_string());
                }
                Some(Arc::new(handle))
            }
            Err(e) => {
                app.log(format!("Could not connect to driver: {}", e));
                None
            }
        }
    } else {
        None
    };

    // Spawn driver polling task
    if let Some(ref handle) = driver_handle {
        let handle_clone = handle.clone();
        let engine_clone = engine.clone();
        let tx = conn_tx.clone();

        tokio::spawn(async move {
            driver_poll_loop(handle_clone, engine_clone, tx).await;
        });
    }

    // Main event loop
    let result = run_event_loop(&mut terminal, &mut app, &mut conn_rx, driver_handle).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

/// Event from driver polling
struct DriverConnectionEvent {
    request_id: u64,
    event: ConnectionEvent,
    verdict: EvalResult,
}

/// Driver polling loop - runs in background task
async fn driver_poll_loop(
    handle: Arc<DriverHandle>,
    engine: Arc<RuleEngine>,
    tx: mpsc::Sender<DriverConnectionEvent>,
) {
    loop {
        // Poll for pending connection
        match handle.get_pending() {
            Ok(Some(req)) => {
                // Build context for rule evaluation
                let ctx = ConnectionContext {
                    process_path: req.process_path.to_string_lossy().to_string(),
                    process_name: req.process_name.clone(),
                    process_id: req.process_id,
                    remote_address: req.remote_address,
                    remote_port: req.remote_port,
                    local_port: req.local_port,
                    protocol: req.protocol,
                    direction: req.direction,
                    domain: req.domain.clone(),
                };

                // Evaluate rules
                let verdict = engine.evaluate(&ctx);

                // Determine action string and send verdict to driver
                let (action_str, allow) = match &verdict {
                    EvalResult::Allow { .. } => ("ALLOW", true),
                    EvalResult::Deny { .. } => ("DENY", false),
                    EvalResult::Ask => ("ASK", true), // Default allow for ASK for now
                };

                // Send verdict to driver immediately
                let driver_verdict = if allow {
                    DriverVerdict::Allow
                } else {
                    DriverVerdict::Block
                };

                if let Err(e) = handle.set_verdict(req.request_id, driver_verdict) {
                    eprintln!("Failed to send verdict: {}", e);
                }

                // Create UI event
                let event = ConnectionEvent {
                    time: chrono::Local::now().format("%H:%M:%S").to_string(),
                    action: action_str.to_string(),
                    process_name: req.process_name,
                    process_id: req.process_id,
                    destination: req.domain.unwrap_or_else(|| req.remote_address.to_string()),
                    port: req.remote_port,
                    protocol: format!("{:?}", req.protocol),
                    rule_name: match &verdict {
                        EvalResult::Allow { rule_id } | EvalResult::Deny { rule_id } => {
                            if rule_id.is_empty() {
                                None
                            } else {
                                Some(rule_id[..8.min(rule_id.len())].to_string())
                            }
                        }
                        EvalResult::Ask => None,
                    },
                    is_pending: matches!(verdict, EvalResult::Ask),
                };

                // Send to UI
                let _ = tx.send(DriverConnectionEvent {
                    request_id: req.request_id,
                    event,
                    verdict,
                }).await;
            }
            Ok(None) => {
                // No pending requests, sleep briefly
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            Err(e) => {
                // Error polling, sleep and retry
                eprintln!("Driver poll error: {}", e);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

/// Main event loop
async fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    conn_rx: &mut mpsc::Receiver<DriverConnectionEvent>,
    _driver_handle: Option<Arc<DriverHandle>>,
) -> Result<()> {
    loop {
        // Draw UI
        terminal.draw(|frame| ui::draw(frame, app))?;

        // Use tokio::select to handle multiple event sources
        tokio::select! {
            // Check for keyboard events (non-blocking poll)
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                // Poll keyboard
                if let Some(event) = poll_event(Duration::from_millis(0))? {
                    match event {
                        Event::Key(key) => {
                            if matches!(handle_key_event(app, key), EventResult::Quit) {
                                break;
                            }
                        }
                        Event::Resize(_, _) => {
                            // Terminal resized - just redraw
                        }
                        _ => {}
                    }
                }
            }

            // Check for driver connection events
            Some(driver_event) = conn_rx.recv() => {
                app.add_connection(driver_event.event);
            }
        }

        // Check if should quit
        if app.should_quit {
            break;
        }
    }

    Ok(())
}

/// Check if the kernel driver is running
fn check_driver_status() -> DriverStatus {
    #[cfg(windows)]
    {
        use std::process::Command;

        let output = Command::new("sc.exe")
            .args(["query", "SerenoFilter"])
            .output();

        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains("RUNNING") {
                    DriverStatus::Running
                } else if stdout.contains("STOPPED") {
                    DriverStatus::Stopped
                } else if stdout.contains("does not exist") || !output.status.success() {
                    DriverStatus::NotInstalled
                } else {
                    DriverStatus::Stopped
                }
            }
            Err(_) => DriverStatus::Unknown,
        }
    }

    #[cfg(not(windows))]
    {
        DriverStatus::NotInstalled
    }
}

/// Check if running with admin privileges
fn is_running_as_admin() -> bool {
    #[cfg(windows)]
    {
        use std::process::Command;

        // Try to query a service - will fail without admin
        let output = Command::new("sc.exe")
            .args(["query", "SerenoFilter"])
            .output();

        match output {
            Ok(output) => output.status.success() || !String::from_utf8_lossy(&output.stderr).contains("Access is denied"),
            Err(_) => false,
        }
    }

    #[cfg(not(windows))]
    {
        false
    }
}

/// Add demo connections for testing the UI
fn add_demo_connections(app: &mut App) {
    let demo_events = vec![
        ConnectionEvent {
            time: "19:45:17".to_string(),
            action: "ALLOW".to_string(),
            process_name: "curl.exe".to_string(),
            process_id: 7892,
            destination: "google.com".to_string(),
            port: 443,
            protocol: "TCP".to_string(),
            rule_name: None,
            is_pending: false,
        },
        ConnectionEvent {
            time: "19:45:14".to_string(),
            action: "ASK".to_string(),
            process_name: "Code.exe".to_string(),
            process_id: 10860,
            destination: "github.com".to_string(),
            port: 443,
            protocol: "TCP".to_string(),
            rule_name: None,
            is_pending: true,
        },
        ConnectionEvent {
            time: "19:44:57".to_string(),
            action: "DENY".to_string(),
            process_name: "telemetry.exe".to_string(),
            process_id: 4024,
            destination: "telemetry.microsoft.com".to_string(),
            port: 443,
            protocol: "TCP".to_string(),
            rule_name: Some("Block Telemetry".to_string()),
            is_pending: false,
        },
        ConnectionEvent {
            time: "19:44:57".to_string(),
            action: "ALLOW".to_string(),
            process_name: "node.exe".to_string(),
            process_id: 12816,
            destination: "localhost".to_string(),
            port: 50073,
            protocol: "TCP".to_string(),
            rule_name: Some("Allow Local".to_string()),
            is_pending: false,
        },
        ConnectionEvent {
            time: "19:44:52".to_string(),
            action: "ALLOW".to_string(),
            process_name: "svchost.exe".to_string(),
            process_id: 1234,
            destination: "windowsupdate.com".to_string(),
            port: 443,
            protocol: "TCP".to_string(),
            rule_name: Some("Allow WU".to_string()),
            is_pending: false,
        },
    ];

    for event in demo_events {
        app.add_connection(event);
    }
}
