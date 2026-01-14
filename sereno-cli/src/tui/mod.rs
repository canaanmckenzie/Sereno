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
    types::{Condition, ConnectionContext, DomainPattern, EvalResult, Rule},
};
use std::{
    collections::{HashMap, HashSet},
    io::{self, stdout},
    net::{IpAddr, ToSocketAddrs},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, RwLock};

/// Debounce state for kernel sync operations
/// Prevents spamming the kernel with repeated clear/add operations
struct SyncDebounce {
    /// Timestamp when sync was first requested (None if no sync pending)
    pending_since: Option<Instant>,
    /// Delay before actually syncing (ms)
    delay_ms: u64,
}

impl SyncDebounce {
    fn new(delay_ms: u64) -> Self {
        Self {
            pending_since: None,
            delay_ms,
        }
    }

    /// Mark that a sync is needed (starts the debounce timer)
    fn request_sync(&mut self) {
        if self.pending_since.is_none() {
            self.pending_since = Some(Instant::now());
        }
    }

    /// Check if we should sync now (enough time has passed)
    fn should_sync(&self) -> bool {
        if let Some(since) = self.pending_since {
            since.elapsed().as_millis() >= self.delay_ms as u128
        } else {
            false
        }
    }

    /// Mark sync as completed
    fn sync_completed(&mut self) {
        self.pending_since = None;
    }
}

/// Domain cache for IP → domain lookups (enables domain-based rules)
struct DomainCache {
    ip_to_domains: HashMap<IpAddr, HashSet<String>>,
}

impl DomainCache {
    fn new() -> Self {
        Self {
            ip_to_domains: HashMap::new(),
        }
    }

    /// Add a domain → IP mapping (bidirectional)
    fn add(&mut self, domain: &str, ip: IpAddr) {
        self.ip_to_domains
            .entry(ip)
            .or_insert_with(HashSet::new)
            .insert(domain.to_lowercase());
    }

    /// Get domains for an IP
    fn get_domains(&self, ip: &IpAddr) -> Option<String> {
        self.ip_to_domains
            .get(ip)
            .and_then(|set| set.iter().next().cloned())
    }
}

/// Extract domains that should be blocked from rules (for kernel blocklist sync)
fn extract_blocked_domains(rules: &[Rule]) -> Vec<String> {
    let mut blocked = Vec::new();

    for rule in rules {
        // Only consider enabled DENY rules
        if !rule.enabled || rule.action != sereno_core::types::Action::Deny {
            continue;
        }

        for condition in &rule.conditions {
            if let Condition::Domain { patterns } = condition {
                for pattern in patterns {
                    match pattern {
                        DomainPattern::Exact { value } => {
                            // Strip " (SNI)" suffix if present (added by TUI for display)
                            let domain = value.trim_end_matches(" (SNI)");
                            if !domain.is_empty() {
                                blocked.push(domain.to_string());
                            }
                        }
                        DomainPattern::Wildcard { pattern } => {
                            // For *.facebook.com, extract facebook.com for suffix matching
                            let domain = pattern.trim_start_matches("*.");
                            let domain = domain.trim_end_matches(" (SNI)");
                            if !domain.is_empty() {
                                blocked.push(domain.to_string());
                            }
                        }
                        DomainPattern::Regex { .. } => {
                            // Can't sync regex patterns to kernel - handled in usermode only
                        }
                    }
                }
            }
        }
    }

    // Deduplicate
    blocked.sort();
    blocked.dedup();
    blocked
}

/// Sync blocked domains from rules to kernel blocklist
fn sync_blocked_domains_to_kernel(handle: &DriverHandle, rules: &[Rule]) -> usize {
    // Extract domains first
    let blocked_domains = extract_blocked_domains(rules);

    // Only clear and sync if we have domains
    if blocked_domains.is_empty() {
        return 0;
    }

    // Clear existing blocklist
    if handle.clear_blocked_domains().is_err() {
        return 0;
    }

    let mut synced = 0;
    for domain in &blocked_domains {
        if handle.add_blocked_domain(domain).is_ok() {
            synced += 1;
        }
    }

    synced
}

/// Result of checking for existing rules that match a new rule's target
enum ExistingRuleMatch {
    /// No matching rule found
    None,
    /// Found a rule with the same action (duplicate)
    SameAction { rule_id: String, rule_name: String },
    /// Found a rule with opposite action (conflict)
    ConflictingAction { rule_id: String, rule_name: String },
}

/// Check if an existing rule matches the destination and port
/// Returns the first matching rule info if found
fn find_matching_rule(rules: &[Rule], destination: &str, port: u16, new_action: sereno_core::types::Action) -> ExistingRuleMatch {
    use sereno_core::types::PortMatcher;

    // Normalize destination for matching (strip " (SNI)" suffix)
    let normalized_dest = destination.trim_end_matches(" (SNI)").to_lowercase();

    for rule in rules {
        let mut has_matching_domain = false;
        let mut has_matching_port = false;

        for condition in &rule.conditions {
            match condition {
                Condition::Domain { patterns } => {
                    for pattern in patterns {
                        match pattern {
                            DomainPattern::Exact { value } => {
                                let rule_domain = value.trim_end_matches(" (SNI)").to_lowercase();
                                if rule_domain == normalized_dest {
                                    has_matching_domain = true;
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Condition::RemotePort { matcher } => {
                    match matcher {
                        PortMatcher::Single { port: rule_port } if *rule_port == port => {
                            has_matching_port = true;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        // Check if this rule matches both destination and port
        if has_matching_domain && has_matching_port {
            if rule.action == new_action {
                return ExistingRuleMatch::SameAction {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                };
            } else {
                return ExistingRuleMatch::ConflictingAction {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                };
            }
        }
    }

    ExistingRuleMatch::None
}

/// Extract domains from rules and resolve them to IPs
fn preload_domains_from_rules(rules: &[Rule]) -> DomainCache {
    let mut cache = DomainCache::new();

    for rule in rules {
        for condition in &rule.conditions {
            if let Condition::Domain { patterns } = condition {
                for pattern in patterns {
                    let domain = match pattern {
                        DomainPattern::Exact { value } => value.clone(),
                        DomainPattern::Wildcard { pattern } => {
                            // For wildcards like *.google.com, try resolving google.com
                            pattern.trim_start_matches("*.").to_string()
                        }
                        DomainPattern::Regex { .. } => continue, // Can't resolve regex
                    };

                    // Try to resolve domain to IPs
                    if let Ok(addrs) = format!("{}:80", domain).to_socket_addrs() {
                        for addr in addrs {
                            cache.add(&domain, addr.ip());
                        }
                    }
                }
            }
        }
    }

    cache
}

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

    // Preload domains from rules for IP → domain lookup
    let preloaded_cache = preload_domains_from_rules(&app.rules);
    let ip_count = preloaded_cache.ip_to_domains.len();
    let domain_cache = Arc::new(RwLock::new(preloaded_cache));
    app.log(format!("Resolved {} IPs from domain rules", ip_count));

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
    let (conn_tx, mut conn_rx) = mpsc::channel::<DriverEvent>(100);

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

                    // Sync blocked domains from rules to kernel blocklist (Phase 2: SNI-based blocking)
                    let synced = sync_blocked_domains_to_kernel(&handle, &app.rules);
                    if synced > 0 {
                        app.log(format!("Synced {} blocked domains to kernel", synced));
                    }
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

    // Flag to signal verdict cache clear (set when rules change)
    let clear_cache_flag = Arc::new(AtomicBool::new(false));

    // Debounce state for kernel sync (500ms delay to batch rapid changes)
    let sync_debounce = Arc::new(Mutex::new(SyncDebounce::new(500)));

    // Spawn driver polling task
    if let Some(ref handle) = driver_handle {
        let handle_clone = handle.clone();
        let engine_clone = engine.clone();
        let domain_cache_clone = domain_cache.clone();
        let tx = conn_tx.clone();
        let clear_flag = clear_cache_flag.clone();

        tokio::spawn(async move {
            driver_poll_loop(handle_clone, engine_clone, domain_cache_clone, tx, clear_flag).await;
        });
    }

    // Main event loop
    let result = run_event_loop(&mut terminal, &mut app, &mut conn_rx, driver_handle, engine, clear_cache_flag, sync_debounce).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

/// Event from driver polling
enum DriverEvent {
    /// New connection with verdict
    Connection {
        request_id: u64,
        event: ConnectionEvent,
        verdict: EvalResult,
    },
    /// SNI update for existing connection (domain extracted from TLS ClientHello)
    SniUpdate {
        remote_address: String,
        port: u16,
        domain: String,
    },
}

/// Driver polling loop - runs in background task
async fn driver_poll_loop(
    handle: Arc<DriverHandle>,
    engine: Arc<RuleEngine>,
    domain_cache: Arc<RwLock<DomainCache>>,
    tx: mpsc::Sender<DriverEvent>,
    clear_cache_flag: Arc<AtomicBool>,
) {
    use std::collections::HashMap;
    use std::time::Instant;

    // Cache to deduplicate repeated connections
    // Key: (process_name, remote_ip, remote_port)
    // Value: (verdict, timestamp, show_in_ui)
    let mut verdict_cache: HashMap<(String, String, u16), (EvalResult, Instant)> = HashMap::new();
    const CACHE_TTL_SECS: u64 = 30;

    loop {
        // Check if rules changed - clear cache if so
        if clear_cache_flag.swap(false, Ordering::Relaxed) {
            verdict_cache.clear();
        }

        // Clean old cache entries periodically
        verdict_cache.retain(|_, (_, ts)| ts.elapsed().as_secs() < CACHE_TTL_SECS * 2);

        // Poll for pending connection
        match handle.get_pending() {
            Ok(Some(req)) => {
                // Connection received - log to debug file
                let _ = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("sereno-debug.log")
                    .and_then(|mut f| {
                        use std::io::Write;
                        writeln!(f, "[{}] Got request {} from {} ({}:{}) pid={}",
                            chrono::Local::now().format("%H:%M:%S"),
                            req.request_id, req.process_name, req.remote_address, req.remote_port, req.process_id)
                    });
                // Try to resolve domain from IP using cache
                let domain = if req.domain.is_some() {
                    req.domain.clone()
                } else {
                    // Look up in domain cache
                    domain_cache.read().await.get_domains(&req.remote_address)
                };

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
                    domain: domain.clone(),
                };

                // Check cache for recent identical connection
                let cache_key = (
                    req.process_name.clone(),
                    req.remote_address.to_string(),
                    req.remote_port,
                );

                // Evaluate the connection against rules
                let verdict = engine.evaluate(&ctx);

                // Check if we should show in UI
                // Show ALL connections (ALLOW, DENY, ASK) but deduplicate rapid-fire duplicates
                // Use a short TTL (2 seconds) to prevent flooding while still showing most connections
                const UI_DEDUP_TTL_SECS: u64 = 2;
                let show_in_ui = if let Some((cached_verdict, ts)) = verdict_cache.get(&cache_key) {
                    if ts.elapsed().as_secs() < UI_DEDUP_TTL_SECS {
                        // Very recent duplicate - check if verdict changed
                        let verdict_changed = match (&verdict, cached_verdict) {
                            (EvalResult::Allow { .. }, EvalResult::Allow { .. }) => false,
                            (EvalResult::Deny { .. }, EvalResult::Deny { .. }) => false,
                            (EvalResult::Ask, EvalResult::Ask) => false,
                            _ => true,
                        };
                        verdict_changed // Show if verdict changed, otherwise suppress rapid duplicates
                    } else {
                        true // Dedup window expired, show
                    }
                } else {
                    true // Not in cache, show
                };

                // Update cache with current verdict
                verdict_cache.insert(cache_key.clone(), (verdict.clone(), Instant::now()));

                // Determine action string
                let action_str = match &verdict {
                    EvalResult::Allow { .. } => "ALLOW",
                    EvalResult::Deny { .. } => "DENY",
                    EvalResult::Ask => "ASK",
                };

                // Send verdict to driver immediately for ALL cases
                // ASK = allow now, prompt user to create rule for future
                let driver_verdict = match &verdict {
                    EvalResult::Allow { .. } => DriverVerdict::Allow,
                    EvalResult::Deny { .. } => DriverVerdict::Block,
                    EvalResult::Ask => DriverVerdict::Allow, // Allow now, ask about rule later
                };

                // Send verdict to driver - log to file (can't print to TUI)
                let verdict_result = handle.set_verdict(req.request_id, driver_verdict);
                let _ = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("sereno-debug.log")
                    .and_then(|mut f| {
                        use std::io::Write;
                        match &verdict_result {
                            Ok(()) => writeln!(f, "[{}] Sent {:?} for request {} ({})",
                                chrono::Local::now().format("%H:%M:%S"),
                                driver_verdict, req.request_id, action_str),
                            Err(e) => writeln!(f, "[{}] FAILED set_verdict for request {}: {} (verdict: {:?})",
                                chrono::Local::now().format("%H:%M:%S"),
                                req.request_id, e, driver_verdict),
                        }
                    });

                // Only send to UI if not a duplicate (dedup)
                if show_in_ui {
                    let event = ConnectionEvent {
                        time: chrono::Local::now().format("%H:%M:%S").to_string(),
                        action: action_str.to_string(),
                        process_name: req.process_name,
                        process_id: req.process_id,
                        destination: domain.clone().unwrap_or_else(|| req.remote_address.to_string()),
                        remote_address: req.remote_address.to_string(),
                        port: req.remote_port,
                        local_port: req.local_port,
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
                        is_pending: false, // Not blocking anymore, just highlighting ASK
                        request_id: None,
                    };

                    // Send to UI
                    let _ = tx.send(DriverEvent::Connection {
                        request_id: req.request_id,
                        event,
                        verdict,
                    }).await;
                }

                // CRITICAL: Sleep after processing each request to prevent tight loop
                // Without this, the loop runs at full CPU speed when requests exist
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok(None) => {
                // No pending connection requests - check for SNI updates
                // Poll all available SNI notifications (drain the queue)
                loop {
                    match handle.get_sni() {
                        Ok(Some(sni)) => {
                            // Send SNI update to UI
                            let _ = tx.send(DriverEvent::SniUpdate {
                                remote_address: sni.remote_address.to_string(),
                                port: sni.remote_port,
                                domain: sni.domain,
                            }).await;
                        }
                        Ok(None) => break, // No more SNI notifications
                        Err(_) => break,   // Error, stop polling
                    }
                }
                // Sleep before next poll cycle
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(_) => {
                // Error polling, sleep and retry (don't spam stderr)
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

/// Main event loop
async fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    conn_rx: &mut mpsc::Receiver<DriverEvent>,
    driver_handle: Option<Arc<DriverHandle>>,
    engine: Arc<RuleEngine>,
    clear_cache_flag: Arc<AtomicBool>,
    sync_debounce: Arc<Mutex<SyncDebounce>>,
) -> Result<()> {
    // Timer for bandwidth polling (every 1 second)
    let mut last_bandwidth_poll = Instant::now();
    const BANDWIDTH_POLL_INTERVAL_MS: u64 = 1000;

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
                            match handle_key_event(app, key) {
                                EventResult::Quit => break,
                                EventResult::AllowPending(request_id) => {
                                    // Send ALLOW verdict to driver
                                    if let Some(ref handle) = driver_handle {
                                        if let Err(e) = handle.set_verdict(request_id, DriverVerdict::Allow) {
                                            app.log(format!("Failed to send ALLOW: {}", e));
                                        }
                                    }
                                }
                                EventResult::BlockPending(request_id) => {
                                    // Send BLOCK verdict to driver
                                    if let Some(ref handle) = driver_handle {
                                        if let Err(e) = handle.set_verdict(request_id, DriverVerdict::Block) {
                                            app.log(format!("Failed to send BLOCK: {}", e));
                                        }
                                    }
                                }
                                EventResult::Continue => {}
                                EventResult::ToggleRule(rule_id) => {
                                    // Find current state of rule
                                    let current_enabled = app.rules.iter()
                                        .find(|r| r.id == rule_id)
                                        .map(|r| r.enabled)
                                        .unwrap_or(true);

                                    // Toggle in database
                                    match engine.set_rule_enabled(&rule_id, !current_enabled) {
                                        Ok(()) => {
                                            // Refresh rules list
                                            app.rules = engine.rules();
                                            // Signal poll loop to clear its verdict cache
                                            clear_cache_flag.store(true, Ordering::Relaxed);
                                            let status = if !current_enabled { "enabled" } else { "disabled" };
                                            app.log(format!("Rule {} {}", &rule_id[..8.min(rule_id.len())], status));

                                            // Request debounced sync to kernel
                                            if driver_handle.is_some() {
                                                sync_debounce.lock().unwrap().request_sync();
                                            }
                                        }
                                        Err(e) => {
                                            app.log(format!("Failed to toggle rule: {}", e));
                                        }
                                    }
                                }
                                EventResult::DeleteRule(rule_id) => {
                                    // Delete rule from database
                                    match engine.remove_rule(&rule_id) {
                                        Ok(()) => {
                                            // Refresh rules list
                                            app.rules = engine.rules();
                                            // Signal poll loop to clear its verdict cache
                                            clear_cache_flag.store(true, Ordering::Relaxed);
                                            app.log(format!("Deleted rule {}", &rule_id[..8.min(rule_id.len())]));

                                            // Request debounced sync to kernel
                                            if driver_handle.is_some() {
                                                sync_debounce.lock().unwrap().request_sync();
                                            }
                                        }
                                        Err(e) => {
                                            app.log(format!("Failed to delete rule: {}", e));
                                        }
                                    }
                                }
                                EventResult::ToggleConnection { process_name, destination, port, current_action } => {
                                    // Create a rule with the opposite action
                                    use sereno_core::types::{Action, Condition, DomainPattern, PortMatcher};

                                    let new_action = if current_action == "DENY" {
                                        Action::Allow
                                    } else {
                                        Action::Deny
                                    };

                                    let action_str = if current_action == "DENY" { "ALLOW" } else { "DENY" };

                                    // Check for existing matching rules (deduplication + conflict detection)
                                    match find_matching_rule(&app.rules, &destination, port, new_action) {
                                        ExistingRuleMatch::SameAction { rule_id, rule_name } => {
                                            // Rule with same action already exists
                                            // Check if it's disabled - if so, enable it
                                            let is_disabled = app.rules.iter()
                                                .find(|r| r.id == rule_id)
                                                .map(|r| !r.enabled)
                                                .unwrap_or(false);

                                            if is_disabled {
                                                // Enable the existing rule instead of creating duplicate
                                                match engine.set_rule_enabled(&rule_id, true) {
                                                    Ok(()) => {
                                                        app.rules = engine.rules();
                                                        clear_cache_flag.store(true, Ordering::Relaxed);
                                                        app.log(format!("Enabled existing rule: {}", rule_name));

                                                        if let Some(conn) = app.connections.get_mut(app.selected_connection) {
                                                            conn.action = action_str.to_string();
                                                            conn.rule_name = Some(rule_name[..20.min(rule_name.len())].to_string());
                                                        }

                                                        if new_action == Action::Deny && driver_handle.is_some() {
                                                            sync_debounce.lock().unwrap().request_sync();
                                                        }
                                                    }
                                                    Err(e) => {
                                                        app.log(format!("Failed to enable rule: {}", e));
                                                    }
                                                }
                                            } else {
                                                // Already exists and enabled - just log
                                                app.log(format!("Rule already exists: {}", rule_name));

                                                if let Some(conn) = app.connections.get_mut(app.selected_connection) {
                                                    conn.action = action_str.to_string();
                                                    conn.rule_name = Some(rule_name[..20.min(rule_name.len())].to_string());
                                                }
                                            }
                                        }
                                        ExistingRuleMatch::ConflictingAction { rule_id, rule_name } => {
                                            // Conflicting rule exists - disable it first, then create new
                                            app.log(format!("Disabling conflicting rule: {}", rule_name));

                                            if let Err(e) = engine.set_rule_enabled(&rule_id, false) {
                                                app.log(format!("Warning: Failed to disable conflicting rule: {}", e));
                                            }

                                            // Now create the new rule
                                            let mut conditions = Vec::new();
                                            let is_domain = destination.chars().any(|c| c.is_alphabetic());
                                            if is_domain {
                                                conditions.push(Condition::Domain {
                                                    patterns: vec![DomainPattern::Exact { value: destination.clone() }],
                                                });
                                            }
                                            conditions.push(Condition::RemotePort {
                                                matcher: PortMatcher::Single { port },
                                            });

                                            let new_rule_name = format!("{} {} ({}:{})", action_str, process_name, destination, port);
                                            let mut rule = Rule::new(new_rule_name.clone(), new_action, conditions);
                                            rule.priority = 50;

                                            match engine.add_rule(rule) {
                                                Ok(()) => {
                                                    app.rules = engine.rules();
                                                    clear_cache_flag.store(true, Ordering::Relaxed);
                                                    app.log(format!("Created rule: {}", new_rule_name));

                                                    if let Some(conn) = app.connections.get_mut(app.selected_connection) {
                                                        conn.action = action_str.to_string();
                                                        conn.rule_name = Some(new_rule_name[..20.min(new_rule_name.len())].to_string());
                                                    }

                                                    if new_action == Action::Deny && driver_handle.is_some() {
                                                        sync_debounce.lock().unwrap().request_sync();
                                                    }
                                                }
                                                Err(e) => {
                                                    app.log(format!("Failed to create rule: {}", e));
                                                }
                                            }
                                        }
                                        ExistingRuleMatch::None => {
                                            // No existing rule - create new one
                                            let mut conditions = Vec::new();
                                            let is_domain = destination.chars().any(|c| c.is_alphabetic());
                                            if is_domain {
                                                conditions.push(Condition::Domain {
                                                    patterns: vec![DomainPattern::Exact { value: destination.clone() }],
                                                });
                                            }
                                            conditions.push(Condition::RemotePort {
                                                matcher: PortMatcher::Single { port },
                                            });

                                            let rule_name = format!("{} {} ({}:{})", action_str, process_name, destination, port);
                                            let mut rule = Rule::new(rule_name.clone(), new_action, conditions);
                                            rule.priority = 50;

                                            match engine.add_rule(rule) {
                                                Ok(()) => {
                                                    app.rules = engine.rules();
                                                    clear_cache_flag.store(true, Ordering::Relaxed);
                                                    app.log(format!("Created rule: {}", rule_name));

                                                    if let Some(conn) = app.connections.get_mut(app.selected_connection) {
                                                        conn.action = action_str.to_string();
                                                        conn.rule_name = Some(rule_name[..20.min(rule_name.len())].to_string());
                                                    }

                                                    if new_action == Action::Deny && driver_handle.is_some() {
                                                        sync_debounce.lock().unwrap().request_sync();
                                                    }
                                                }
                                                Err(e) => {
                                                    app.log(format!("Failed to create rule: {}", e));
                                                }
                                            }
                                        }
                                    }
                                }
                                EventResult::ToggleRuleSelection(rule_id) => {
                                    // Toggle selection state for the rule
                                    if app.selected_rules.contains(&rule_id) {
                                        app.selected_rules.remove(&rule_id);
                                    } else {
                                        app.selected_rules.insert(rule_id);
                                    }
                                }
                                EventResult::SelectAllRules => {
                                    // Select all rules
                                    app.selected_rules = app.rules.iter().map(|r| r.id.clone()).collect();
                                    app.log(format!("Selected {} rules", app.selected_rules.len()));
                                }
                                EventResult::ClearRuleSelection => {
                                    // Clear all selection
                                    let count = app.selected_rules.len();
                                    app.selected_rules.clear();
                                    app.log(format!("Cleared {} selections", count));
                                }
                                EventResult::DeleteSelectedRules(rule_ids) => {
                                    // Bulk delete all selected rules
                                    let count = rule_ids.len();
                                    let mut deleted = 0;
                                    for rule_id in &rule_ids {
                                        if engine.remove_rule(rule_id).is_ok() {
                                            deleted += 1;
                                        }
                                    }
                                    // Clear selection and refresh
                                    app.selected_rules.clear();
                                    app.rules = engine.rules();
                                    clear_cache_flag.store(true, Ordering::Relaxed);
                                    app.log(format!("Deleted {} of {} rules", deleted, count));

                                    // Request debounced sync to kernel
                                    if driver_handle.is_some() {
                                        sync_debounce.lock().unwrap().request_sync();
                                    }
                                }
                            }
                        }
                        Event::Resize(_, _) => {
                            // Terminal resized - just redraw
                        }
                        _ => {}
                    }
                }
            }

            // Check for driver events (connections and SNI updates)
            Some(driver_event) = conn_rx.recv() => {
                match driver_event {
                    DriverEvent::Connection { event, .. } => {
                        // Cache process name for TLM flow lookup (by PID)
                        app.cache_process_name(event.process_id, &event.process_name);
                        // Cache by local port for TLM correlation (local port is unique per connection)
                        app.cache_port_process(
                            event.local_port,
                            &event.process_name,
                            &event.remote_address,
                            &event.destination,
                        );
                        // ASK connections are auto-allowed now (no blocking)
                        app.add_connection(event);
                    }
                    DriverEvent::SniUpdate { remote_address, port, domain } => {
                        // Update existing connection(s) with SNI domain
                        // Match by remote IP and port
                        // Collect port cache updates first to avoid borrow checker issues
                        let mut port_updates: Vec<(u16, String, String, String)> = Vec::new();
                        for conn in app.connections.iter_mut() {
                            if conn.remote_address == remote_address && conn.port == port {
                                // Only update if destination is still showing IP (no domain yet)
                                if conn.destination == remote_address {
                                    conn.destination = format!("{} (SNI)", domain);
                                }
                                // Collect update for port process cache
                                port_updates.push((
                                    conn.local_port,
                                    conn.process_name.clone(),
                                    remote_address.clone(),
                                    format!("{} (SNI)", domain),
                                ));
                            }
                        }
                        // Apply port cache updates after the mutable borrow ends
                        for (local_port, proc_name, remote_ip, dest) in port_updates {
                            app.cache_port_process(local_port, &proc_name, &remote_ip, &dest);
                        }
                    }
                }
            }
        }

        // Check debounced sync - perform sync if enough time has passed
        {
            let mut debounce = sync_debounce.lock().unwrap();
            if debounce.should_sync() {
                if let Some(ref handle) = driver_handle {
                    let synced = sync_blocked_domains_to_kernel(handle, &app.rules);
                    if synced > 0 {
                        app.log(format!("Synced {} blocked domains to kernel", synced));
                    }
                }
                debounce.sync_completed();
            }
        }

        // Poll bandwidth stats from TLM layer periodically
        if last_bandwidth_poll.elapsed().as_millis() >= BANDWIDTH_POLL_INTERVAL_MS as u128 {
            if let Some(ref handle) = driver_handle {
                match handle.get_bandwidth_stats() {
                    Ok(entries) => {
                        // Update app with flow data (handles aggregation, history, etc.)
                        app.update_flows(entries);

                        // Debug: log bandwidth poll results
                        let _ = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open("sereno-debug.log")
                            .and_then(|mut f| {
                                use std::io::Write;
                                writeln!(f, "[{}] TLM: {} flows, sent={}, recv={}",
                                    chrono::Local::now().format("%H:%M:%S"),
                                    app.active_flows, app.total_bytes_sent, app.total_bytes_received)
                            });
                    }
                    Err(e) => {
                        // TLM not available or error - log it
                        let _ = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open("sereno-debug.log")
                            .and_then(|mut f| {
                                use std::io::Write;
                                writeln!(f, "[{}] TLM ERROR: {}",
                                    chrono::Local::now().format("%H:%M:%S"), e)
                            });
                    }
                }
            }
            last_bandwidth_poll = Instant::now();
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
#[allow(dead_code)]
fn add_demo_connections(app: &mut App) {
    let demo_events = vec![
        ConnectionEvent {
            time: "19:45:17".to_string(),
            action: "ALLOW".to_string(),
            process_name: "curl.exe".to_string(),
            process_id: 7892,
            destination: "google.com".to_string(),
            remote_address: "142.250.80.46".to_string(),
            port: 443,
            local_port: 50001,
            protocol: "Tcp".to_string(),
            rule_name: None,
            is_pending: false,
            request_id: None,
        },
        ConnectionEvent {
            time: "19:45:14".to_string(),
            action: "ASK".to_string(),
            process_name: "Code.exe".to_string(),
            process_id: 10860,
            destination: "github.com".to_string(),
            remote_address: "140.82.114.4".to_string(),
            port: 443,
            local_port: 50002,
            protocol: "Tcp".to_string(),
            rule_name: None,
            is_pending: true,
            request_id: Some(999), // Demo request ID
        },
        ConnectionEvent {
            time: "19:44:57".to_string(),
            action: "DENY".to_string(),
            process_name: "telemetry.exe".to_string(),
            process_id: 4024,
            destination: "telemetry.microsoft.com".to_string(),
            remote_address: "13.107.4.52".to_string(),
            port: 443,
            local_port: 50003,
            protocol: "Tcp".to_string(),
            rule_name: Some("Block Telemetry".to_string()),
            is_pending: false,
            request_id: None,
        },
        ConnectionEvent {
            time: "19:44:57".to_string(),
            action: "ALLOW".to_string(),
            process_name: "node.exe".to_string(),
            process_id: 12816,
            destination: "localhost".to_string(),
            remote_address: "127.0.0.1".to_string(),
            port: 50073,
            local_port: 50004,
            protocol: "Tcp".to_string(),
            rule_name: Some("Allow Local".to_string()),
            is_pending: false,
            request_id: None,
        },
        ConnectionEvent {
            time: "19:44:52".to_string(),
            action: "ALLOW".to_string(),
            process_name: "svchost.exe".to_string(),
            process_id: 1234,
            destination: "windowsupdate.com".to_string(),
            remote_address: "13.107.4.50".to_string(),
            port: 443,
            local_port: 50005,
            protocol: "Tcp".to_string(),
            rule_name: Some("Allow WU".to_string()),
            is_pending: false,
            request_id: None,
        },
    ];

    for event in demo_events {
        app.add_connection(event);
    }
}
