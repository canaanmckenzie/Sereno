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

    // Global keys
    match key.code {
        KeyCode::Char('q') | KeyCode::Char('Q') => {
            return EventResult::Quit;
        }
        KeyCode::Char('1') => {
            app.switch_tab(Tab::Monitor);
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
        Tab::Monitor => handle_monitor_key(app, key),
        Tab::Rules => handle_rules_key(app, key),
        Tab::Logs => handle_logs_key(app, key),
        Tab::Settings => handle_settings_key(app, key),
    }
}

/// Handle keys in the Monitor tab
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
                return EventResult::ToggleConnection {
                    process_name: conn.process_name.clone(),
                    destination: conn.destination.clone(),
                    port: conn.port,
                    current_action: conn.action.clone(),
                };
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
