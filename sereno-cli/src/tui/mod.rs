//! Terminal User Interface for Sereno Firewall
//!
//! Provides an interactive TUI for monitoring connections, managing rules,
//! and handling interactive prompts.

pub mod app;
pub mod events;
pub mod ui;

use anyhow::Result;
use app::{App, ConnectionEvent, DriverStatus, Mode};
use crossterm::{
    event::Event,
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use events::{handle_key_event, poll_event, EventResult};
use ratatui::{backend::CrosstermBackend, Terminal};
use sereno_core::{database::Database, rule_engine::RuleEngine};
use std::{
    io::{self, stdout},
    path::Path,
    time::Duration,
};

/// Run the TUI application
pub fn run(db_path: &Path) -> Result<()> {
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
    let engine = RuleEngine::new(db.clone())?;
    app.rules = engine.rules();
    app.log(format!("Loaded {} rules", app.rules.len()));

    // Check driver status
    app.driver_status = check_driver_status();
    app.mode = if app.driver_status == DriverStatus::Running {
        Mode::KernelDriver
    } else {
        Mode::MonitorOnly
    };
    app.is_admin = is_running_as_admin();

    app.log(format!("Driver: {}", app.driver_status.label()));
    app.log(format!("Mode: {}", app.mode.label()));
    app.log(format!("Admin: {}", if app.is_admin { "Yes" } else { "No" }));

    // Add some demo connections for now
    add_demo_connections(&mut app);

    // Main event loop
    let result = run_event_loop(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

/// Main event loop
fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    loop {
        // Draw UI
        terminal.draw(|frame| ui::draw(frame, app))?;

        // Poll for events (with 100ms timeout for responsive UI)
        if let Some(event) = poll_event(Duration::from_millis(100))? {
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

        // Check if should quit
        if app.should_quit {
            break;
        }

        // TODO: Poll for new connections from the service
        // This would integrate with the driver/service communication
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
