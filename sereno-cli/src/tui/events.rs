//! TUI Event Handling

use crate::tui::app::{App, Tab};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use std::time::Duration;

/// Result of handling an event
pub enum EventResult {
    /// Continue running
    Continue,
    /// Exit the application
    Quit,
    /// User decided to allow a pending connection
    AllowPending(u64),
    /// User decided to block a pending connection
    BlockPending(u64),
    /// Toggle a rule's enabled state
    ToggleRule(String),
    /// Delete a rule
    DeleteRule(String),
    /// Delete multiple selected rules (bulk delete)
    DeleteSelectedRules(Vec<String>),
    /// Toggle selection on current rule
    ToggleRuleSelection(String),
    /// Select all rules
    SelectAllRules,
    /// Clear rule selection
    ClearRuleSelection,
    /// Toggle a connection's verdict (create rule with opposite action)
    /// Contains: (process_name, destination/domain, port, current_action)
    ToggleConnection {
        process_name: String,
        destination: String,
        port: u16,
        current_action: String,
    },
    /// Create a deny rule with specific duration
    CreateDenyRule {
        process_name: String,
        destination: String,
        port: u16,
        duration: crate::tui::app::RuleDuration,
    },
    /// Cancel duration selection
    CancelDurationPrompt,
}

/// Poll for and handle events
pub fn poll_event(timeout: Duration) -> std::io::Result<Option<Event>> {
    if event::poll(timeout)? {
        Ok(Some(event::read()?))
    } else {
        Ok(None)
    }
}

/// Handle a key event
pub fn handle_key_event(app: &mut App, key: KeyEvent) -> EventResult {
    // Only handle key press events, ignore release and repeat
    if key.kind != KeyEventKind::Press {
        return EventResult::Continue;
    }

    // Handle Ctrl+C globally
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return EventResult::Quit;
    }

    // Handle pending ASK prompt first
    if app.pending_ask.is_some() {
        return handle_pending_ask(app, key);
    }

    // Handle duration selection prompt
    if app.duration_prompt.is_some() {
        return handle_duration_prompt(app, key);
    }

    // Global keys
    match key.code {
        KeyCode::Char('q') | KeyCode::Char('Q') => {
            return EventResult::Quit;
        }
        KeyCode::Char('1') => {
            app.switch_tab(Tab::Connections);
        }
        KeyCode::Char('2') => {
            app.switch_tab(Tab::Rules);
        }
        KeyCode::Char('3') => {
            app.switch_tab(Tab::Logs);
        }
        KeyCode::Char('4') => {
            app.switch_tab(Tab::Settings);
        }
        KeyCode::Tab => {
            app.next_tab();
        }
        KeyCode::BackTab => {
            app.prev_tab();
        }
        _ => {
            // Tab-specific handling
            return handle_tab_key(app, key);
        }
    }

    EventResult::Continue
}

/// Handle keys specific to the current tab
fn handle_tab_key(app: &mut App, key: KeyEvent) -> EventResult {
    match app.active_tab {
        Tab::Connections => handle_connections_key(app, key),
        Tab::Rules => handle_rules_key(app, key),
        Tab::Logs => handle_logs_key(app, key),
        Tab::Settings => handle_settings_key(app, key),
    }
}

/// Handle keys in the unified Connections tab
fn handle_connections_key(app: &mut App, key: KeyEvent) -> EventResult {
    const VISIBLE_ROWS: usize = 20; // Approximate visible rows for scroll adjustment

    // Handle info popup dismissal first
    if app.show_info_popup {
        match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('i') | KeyCode::Char('I') | KeyCode::Char('q') => {
                app.show_info_popup = false;
            }
            _ => {
                // Any other key also dismisses the popup
                app.show_info_popup = false;
            }
        }
        return EventResult::Continue;
    }

    // Handle view mode toggle first (works in any view mode)
    if key.code == KeyCode::Char('g') || key.code == KeyCode::Char('G') {
        app.toggle_view_mode();
        app.log(format!("View mode: {}", app.view_mode.label()));
        return EventResult::Continue;
    }

    // Handle navigation differently based on view mode
    if app.view_mode == crate::tui::app::ViewMode::Grouped {
        return handle_grouped_key(app, key, VISIBLE_ROWS);
    }

    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            app.select_up();
            app.adjust_unified_scroll(VISIBLE_ROWS);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.select_down();
            app.adjust_unified_scroll(VISIBLE_ROWS);
        }
        KeyCode::Home => {
            app.selected_unified = 0;
            app.unified_scroll_offset = 0;
        }
        KeyCode::End => {
            app.selected_unified = app.unified_connections.len().saturating_sub(1);
            app.adjust_unified_scroll(VISIBLE_ROWS);
        }
        KeyCode::PageUp => {
            app.selected_unified = app.selected_unified.saturating_sub(VISIBLE_ROWS);
            app.adjust_unified_scroll(VISIBLE_ROWS);
        }
        KeyCode::PageDown => {
            let max = app.unified_connections.len().saturating_sub(1);
            app.selected_unified = (app.selected_unified + VISIBLE_ROWS).min(max);
            app.adjust_unified_scroll(VISIBLE_ROWS);
        }
        KeyCode::Enter | KeyCode::Char('i') | KeyCode::Char('I') => {
            // Toggle info popup for selected connection
            if app.selected_unified_connection().is_some() {
                app.toggle_info_popup();
            }
        }
        KeyCode::Char('s') | KeyCode::Char('S') => {
            // Cycle sort mode
            app.next_unified_sort();
            let sort_name = match app.unified_sort {
                crate::tui::app::ConnectionSort::Time => "Time",
                crate::tui::app::ConnectionSort::BytesTotal => "Bytes Total",
                crate::tui::app::ConnectionSort::Process => "Process",
                crate::tui::app::ConnectionSort::Destination => "Destination",
            };
            app.log(format!("Sorted by: {}", sort_name));
        }
        KeyCode::Char('c') | KeyCode::Char('C') => {
            // Clear connections
            app.unified_connections.clear();
            app.selected_unified = 0;
            app.unified_scroll_offset = 0;
            app.log("Cleared connection list".to_string());
        }
        KeyCode::Char('t') | KeyCode::Char('T') => {
            // Toggle connection - create/remove rule for selected connection
            if let Some(conn) = app.selected_unified_connection() {
                let action_str = conn.auth_status.label();
                if action_str == "DENY" {
                    // DENY → ALLOW: Remove deny rule
                    return EventResult::ToggleConnection {
                        process_name: conn.process_name.clone(),
                        destination: conn.destination.clone(),
                        port: conn.remote_port,
                        current_action: action_str.to_string(),
                    };
                } else {
                    // ALLOW/AUTO/ASK → DENY: Show duration selection prompt
                    app.duration_prompt = Some(crate::tui::app::DurationPrompt {
                        process_name: conn.process_name.clone(),
                        destination: conn.destination.clone(),
                        port: conn.remote_port,
                        selected_index: 4, // Default to "Permanent"
                    });
                }
            }
        }
        _ => {}
    }
    EventResult::Continue
}

/// Handle keys in grouped view mode
fn handle_grouped_key(app: &mut App, key: KeyEvent, visible_rows: usize) -> EventResult {
    // Handle info popup dismissal first
    if app.show_info_popup {
        app.show_info_popup = false;
        return EventResult::Continue;
    }

    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            if app.selected_grouped > 0 {
                app.selected_grouped -= 1;
            }
            app.adjust_grouped_scroll(visible_rows);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if app.selected_grouped < app.grouped_connections.len().saturating_sub(1) {
                app.selected_grouped += 1;
            }
            app.adjust_grouped_scroll(visible_rows);
        }
        KeyCode::Home => {
            app.selected_grouped = 0;
            app.grouped_scroll_offset = 0;
        }
        KeyCode::End => {
            app.selected_grouped = app.grouped_connections.len().saturating_sub(1);
            app.adjust_grouped_scroll(visible_rows);
        }
        KeyCode::PageUp => {
            app.selected_grouped = app.selected_grouped.saturating_sub(visible_rows);
            app.adjust_grouped_scroll(visible_rows);
        }
        KeyCode::PageDown => {
            let max = app.grouped_connections.len().saturating_sub(1);
            app.selected_grouped = (app.selected_grouped + visible_rows).min(max);
            app.adjust_grouped_scroll(visible_rows);
        }
        KeyCode::Enter | KeyCode::Char('i') | KeyCode::Char('I') => {
            // Toggle info popup for selected group
            if !app.grouped_connections.is_empty() {
                app.toggle_info_popup();
            }
        }
        KeyCode::Char('s') | KeyCode::Char('S') => {
            // Refresh/re-sort grouped connections
            app.compute_grouped_connections();
            app.log("Refreshed grouped view".to_string());
        }
        KeyCode::Char('c') | KeyCode::Char('C') => {
            // Clear all connections (goes back to detailed view)
            app.unified_connections.clear();
            app.grouped_connections.clear();
            app.selected_unified = 0;
            app.selected_grouped = 0;
            app.unified_scroll_offset = 0;
            app.grouped_scroll_offset = 0;
            app.view_mode = crate::tui::app::ViewMode::Detailed;
            app.log("Cleared connection list".to_string());
        }
        _ => {}
    }
    EventResult::Continue
}

/// Handle keys in the Monitor tab (legacy, kept for reference)
#[allow(dead_code)]
fn handle_monitor_key(app: &mut App, key: KeyEvent) -> EventResult {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            app.select_up();
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.select_down();
        }
        KeyCode::Home => {
            app.selected_connection = 0;
        }
        KeyCode::End => {
            app.selected_connection = app.connections.len().saturating_sub(1);
        }
        KeyCode::PageUp => {
            app.selected_connection = app.selected_connection.saturating_sub(10);
        }
        KeyCode::PageDown => {
            let max = app.connections.len().saturating_sub(1);
            app.selected_connection = (app.selected_connection + 10).min(max);
        }
        KeyCode::Enter => {
            // TODO: Show connection details popup
            if let Some(conn) = app.selected_connection_event() {
                app.log(format!("Selected: {} → {}", conn.process_name, conn.destination));
            }
        }
        KeyCode::Char('c') | KeyCode::Char('C') => {
            // Clear connections
            app.connections.clear();
            app.selected_connection = 0;
            app.log("Cleared connection list".to_string());
        }
        KeyCode::Char('t') | KeyCode::Char('T') => {
            // Toggle connection - create rule with opposite action
            if let Some(conn) = app.selected_connection_event() {
                if conn.action == "DENY" {
                    // DENY → ALLOW: Just remove the rule (no prompt needed)
                    return EventResult::ToggleConnection {
                        process_name: conn.process_name.clone(),
                        destination: conn.destination.clone(),
                        port: conn.port,
                        current_action: conn.action.clone(),
                    };
                } else {
                    // ALLOW → DENY: Show duration selection prompt
                    app.duration_prompt = Some(crate::tui::app::DurationPrompt {
                        process_name: conn.process_name.clone(),
                        destination: conn.destination.clone(),
                        port: conn.port,
                        selected_index: 4, // Default to "Permanent"
                    });
                }
            }
        }
        _ => {}
    }
    EventResult::Continue
}

/// Handle keys in the Flows tab (legacy, kept for reference)
#[allow(dead_code)]
fn handle_flows_key(app: &mut App, key: KeyEvent) -> EventResult {
    // Assume ~20 visible rows for scroll adjustment (will be refined by actual rendering)
    const VISIBLE_ROWS: usize = 20;

    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            app.select_up();
            app.adjust_flow_scroll(VISIBLE_ROWS);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.select_down();
            app.adjust_flow_scroll(VISIBLE_ROWS);
        }
        KeyCode::Home => {
            app.selected_flow = 0;
            app.flow_scroll_offset = 0;
        }
        KeyCode::End => {
            app.selected_flow = app.flows.len().saturating_sub(1);
            app.adjust_flow_scroll(VISIBLE_ROWS);
        }
        KeyCode::PageUp => {
            app.selected_flow = app.selected_flow.saturating_sub(VISIBLE_ROWS);
            app.adjust_flow_scroll(VISIBLE_ROWS);
        }
        KeyCode::PageDown => {
            let max = app.flows.len().saturating_sub(1);
            app.selected_flow = (app.selected_flow + VISIBLE_ROWS).min(max);
            app.adjust_flow_scroll(VISIBLE_ROWS);
        }
        KeyCode::Char('s') | KeyCode::Char('S') => {
            // Cycle sort mode
            app.next_flow_sort();
            let sort_name = match app.flow_sort {
                crate::tui::app::FlowSort::BytesTotal => "Total Bytes",
                crate::tui::app::FlowSort::BytesSent => "Bytes Sent",
                crate::tui::app::FlowSort::BytesReceived => "Bytes Received",
                crate::tui::app::FlowSort::Duration => "Duration",
                crate::tui::app::FlowSort::Process => "Process Name",
            };
            app.log(format!("Flows sorted by: {}", sort_name));
        }
        KeyCode::Enter => {
            // Show flow details
            if let Some(flow) = app.selected_flow_item() {
                app.log(format!(
                    "Flow: {}:{} → {}:{} | ↑{} ↓{} | {:.1}s",
                    flow.local_address, flow.local_port,
                    flow.remote_address, flow.remote_port,
                    crate::tui::ui::format_bytes_pub(flow.bytes_sent),
                    crate::tui::ui::format_bytes_pub(flow.bytes_received),
                    flow.duration_secs
                ));
            }
        }
        _ => {}
    }
    EventResult::Continue
}

/// Handle keys in the Rules tab
fn handle_rules_key(app: &mut App, key: KeyEvent) -> EventResult {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            app.select_up();
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.select_down();
        }
        KeyCode::Home => {
            app.selected_rule = 0;
        }
        KeyCode::End => {
            app.selected_rule = app.rules.len().saturating_sub(1);
        }
        KeyCode::Enter | KeyCode::Char('e') => {
            // TODO: Edit rule
            if let Some(rule) = app.selected_rule_item() {
                app.log(format!("Edit rule: {}", rule.name));
            }
        }
        KeyCode::Char('t') | KeyCode::Char('T') => {
            // Toggle enabled
            if let Some(rule) = app.selected_rule_item() {
                let rule_id = rule.id.clone();
                return EventResult::ToggleRule(rule_id);
            }
        }
        KeyCode::Char('D') => {
            // Bulk delete - delete all selected rules (Shift+D)
            if !app.selected_rules.is_empty() {
                let selected: Vec<String> = app.selected_rules.iter().cloned().collect();
                return EventResult::DeleteSelectedRules(selected);
            } else if let Some(rule) = app.selected_rule_item() {
                // No selection, delete current rule
                let rule_id = rule.id.clone();
                return EventResult::DeleteRule(rule_id);
            }
        }
        KeyCode::Char('d') | KeyCode::Delete => {
            // Delete single selected rule
            if let Some(rule) = app.selected_rule_item() {
                let rule_id = rule.id.clone();
                return EventResult::DeleteRule(rule_id);
            }
        }
        KeyCode::Char(' ') => {
            // Toggle selection on current rule
            if let Some(rule) = app.selected_rule_item() {
                let rule_id = rule.id.clone();
                return EventResult::ToggleRuleSelection(rule_id);
            }
        }
        KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            // Select all rules (Ctrl+A)
            return EventResult::SelectAllRules;
        }
        KeyCode::Esc => {
            // Clear selection
            if !app.selected_rules.is_empty() {
                return EventResult::ClearRuleSelection;
            }
        }
        _ => {}
    }
    EventResult::Continue
}

/// Handle keys in the Logs tab
fn handle_logs_key(app: &mut App, key: KeyEvent) -> EventResult {
    match key.code {
        KeyCode::Char('c') | KeyCode::Char('C') => {
            app.logs.clear();
            app.log("Cleared logs".to_string());
        }
        _ => {}
    }
    EventResult::Continue
}

/// Handle keys in the Settings tab
fn handle_settings_key(app: &mut App, key: KeyEvent) -> EventResult {
    match key.code {
        KeyCode::Char('d') | KeyCode::Char('D') => {
            // Toggle driver
            app.log("Toggle driver...".to_string());
            // TODO: Actually start/stop driver
        }
        KeyCode::Char('r') | KeyCode::Char('R') => {
            // Reload rules
            app.log("Reloading rules...".to_string());
            // TODO: Actually reload rules from database
        }
        KeyCode::Char('m') | KeyCode::Char('M') => {
            // Toggle mode between KernelDriver and SilentAllow
            use crate::tui::app::Mode;
            if app.mode == Mode::KernelDriver || app.mode == Mode::SilentAllow {
                app.mode = app.mode.next();
                app.log(format!("Mode changed to: {}", app.mode.label()));
            } else {
                app.log("Mode toggle only available with Kernel Driver".to_string());
            }
        }
        _ => {}
    }
    EventResult::Continue
}

/// Handle keys when there's a pending ASK prompt
fn handle_pending_ask(app: &mut App, key: KeyEvent) -> EventResult {
    match key.code {
        KeyCode::Char('a') | KeyCode::Char('A') => {
            // Allow
            if let Some(pending) = app.pending_ask.take() {
                app.log(format!(
                    "ALLOWED: {} → {}",
                    pending.process_name, pending.destination
                ));
                // Update the connection in the list to show ALLOW
                update_pending_connection(app, &pending, "ALLOW");
                // Return verdict to send to driver
                if let Some(request_id) = pending.request_id {
                    return EventResult::AllowPending(request_id);
                }
            }
        }
        KeyCode::Char('b') | KeyCode::Char('B') => {
            // Block
            if let Some(pending) = app.pending_ask.take() {
                app.log(format!(
                    "BLOCKED: {} → {}",
                    pending.process_name, pending.destination
                ));
                // Update the connection in the list to show DENY
                update_pending_connection(app, &pending, "DENY");
                app.blocked_connections += 1;
                // Return verdict to send to driver
                if let Some(request_id) = pending.request_id {
                    return EventResult::BlockPending(request_id);
                }
            }
        }
        KeyCode::Char('r') | KeyCode::Char('R') => {
            // Create rule - for now, allow and log
            if let Some(pending) = app.pending_ask.take() {
                app.log(format!(
                    "TODO: Rule creation for {} → {}",
                    pending.process_name, pending.destination
                ));
                // Allow for now while rule creation is implemented
                update_pending_connection(app, &pending, "ALLOW");
                if let Some(request_id) = pending.request_id {
                    return EventResult::AllowPending(request_id);
                }
            }
        }
        KeyCode::Char('i') | KeyCode::Char('I') | KeyCode::Esc => {
            // Ignore (allow this time but don't remember)
            if let Some(pending) = app.pending_ask.take() {
                app.log(format!(
                    "IGNORED: {} → {}",
                    pending.process_name, pending.destination
                ));
                update_pending_connection(app, &pending, "ALLOW");
                if let Some(request_id) = pending.request_id {
                    return EventResult::AllowPending(request_id);
                }
            }
        }
        KeyCode::Char('q') | KeyCode::Char('Q') => {
            return EventResult::Quit;
        }
        _ => {}
    }
    EventResult::Continue
}

/// Update a pending connection in the list after user decision
fn update_pending_connection(app: &mut App, pending: &crate::tui::app::ConnectionEvent, new_action: &str) {
    // Find the connection by request_id and update it
    if let Some(request_id) = pending.request_id {
        for conn in app.connections.iter_mut() {
            if conn.request_id == Some(request_id) {
                conn.action = new_action.to_string();
                conn.is_pending = false;
                conn.request_id = None;
                break;
            }
        }
    }
}

/// Handle keys when duration selection prompt is shown
fn handle_duration_prompt(app: &mut App, key: KeyEvent) -> EventResult {
    use crate::tui::app::RuleDuration;

    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            if let Some(prompt) = &mut app.duration_prompt {
                if prompt.selected_index > 0 {
                    prompt.selected_index -= 1;
                }
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if let Some(prompt) = &mut app.duration_prompt {
                if prompt.selected_index < 4 {
                    prompt.selected_index += 1;
                }
            }
        }
        KeyCode::Enter => {
            // Confirm selection and create rule
            if let Some(prompt) = app.duration_prompt.take() {
                let durations = RuleDuration::all();
                let duration = durations[prompt.selected_index];
                app.log(format!(
                    "Creating DENY rule for {}:{} ({})",
                    prompt.destination, prompt.port, duration.label()
                ));
                return EventResult::CreateDenyRule {
                    process_name: prompt.process_name,
                    destination: prompt.destination,
                    port: prompt.port,
                    duration,
                };
            }
        }
        KeyCode::Esc | KeyCode::Char('q') => {
            // Cancel
            app.duration_prompt = None;
            app.log("Cancelled rule creation".to_string());
            return EventResult::CancelDurationPrompt;
        }
        // Quick keys for duration selection
        KeyCode::Char('1') => {
            if let Some(prompt) = app.duration_prompt.take() {
                return EventResult::CreateDenyRule {
                    process_name: prompt.process_name,
                    destination: prompt.destination,
                    port: prompt.port,
                    duration: RuleDuration::Once,
                };
            }
        }
        KeyCode::Char('2') => {
            if let Some(prompt) = app.duration_prompt.take() {
                return EventResult::CreateDenyRule {
                    process_name: prompt.process_name,
                    destination: prompt.destination,
                    port: prompt.port,
                    duration: RuleDuration::OneHour,
                };
            }
        }
        KeyCode::Char('3') => {
            if let Some(prompt) = app.duration_prompt.take() {
                return EventResult::CreateDenyRule {
                    process_name: prompt.process_name,
                    destination: prompt.destination,
                    port: prompt.port,
                    duration: RuleDuration::OneDay,
                };
            }
        }
        KeyCode::Char('4') => {
            if let Some(prompt) = app.duration_prompt.take() {
                return EventResult::CreateDenyRule {
                    process_name: prompt.process_name,
                    destination: prompt.destination,
                    port: prompt.port,
                    duration: RuleDuration::OneWeek,
                };
            }
        }
        KeyCode::Char('5') => {
            if let Some(prompt) = app.duration_prompt.take() {
                return EventResult::CreateDenyRule {
                    process_name: prompt.process_name,
                    destination: prompt.destination,
                    port: prompt.port,
                    duration: RuleDuration::Permanent,
                };
            }
        }
        _ => {}
    }
    EventResult::Continue
}
