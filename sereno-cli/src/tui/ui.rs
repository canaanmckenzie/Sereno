//! TUI UI Rendering

use crate::tui::app::{App, DriverStatus, FlowSort, Tab};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table, Tabs},
    Frame,
};

/// Main UI rendering function
pub fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Length(3), // Tabs
            Constraint::Min(10),   // Content
            Constraint::Length(3), // Footer/Status
        ])
        .split(frame.area());

    draw_header(frame, app, chunks[0]);
    draw_tabs(frame, app, chunks[1]);
    draw_content(frame, app, chunks[2]);
    draw_footer(frame, app, chunks[3]);
}

/// Format bytes into human-readable form (KB, MB, GB)
fn format_bytes(bytes: u64) -> String {
    format_bytes_pub(bytes)
}

/// Public version of format_bytes for use in other modules
pub fn format_bytes_pub(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1}GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1}MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{}B", bytes)
    }
}

/// Draw the header with title and status
fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let driver_indicator = match app.driver_status {
        DriverStatus::Running => Span::styled("● Running", Style::default().fg(Color::Green)),
        DriverStatus::Stopped => Span::styled("○ Stopped", Style::default().fg(Color::Yellow)),
        DriverStatus::NotInstalled => {
            Span::styled("✗ Not Installed", Style::default().fg(Color::Red))
        }
        DriverStatus::Unknown => Span::styled("? Unknown", Style::default().fg(Color::DarkGray)),
    };

    let mode_span = Span::styled(
        app.mode.label(),
        Style::default().fg(Color::Cyan),
    );

    // Format bandwidth stats
    let bandwidth_span = if app.driver_status == DriverStatus::Running {
        vec![
            Span::raw("  ↑"),
            Span::styled(format_bytes(app.total_bytes_sent), Style::default().fg(Color::Green)),
            Span::raw(" ↓"),
            Span::styled(format_bytes(app.total_bytes_received), Style::default().fg(Color::Cyan)),
            Span::raw(" ("),
            Span::styled(format!("{}", app.active_flows), Style::default().fg(Color::Yellow)),
            Span::raw(" flows)"),
        ]
    } else {
        vec![]
    };

    let mut title_parts = vec![
        Span::styled(
            " SERENO FIREWALL ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  Driver: "),
        driver_indicator,
        Span::raw("  Mode: "),
        mode_span,
    ];
    title_parts.extend(bandwidth_span);

    let title = Line::from(title_parts);

    let header = Paragraph::new(title)
        .block(Block::default().borders(Borders::BOTTOM).border_style(Style::default().fg(Color::DarkGray)));

    frame.render_widget(header, area);
}

/// Draw the tab bar
fn draw_tabs(frame: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = Tab::all()
        .iter()
        .map(|tab| {
            let style = if *tab == app.active_tab {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            Line::from(Span::styled(format!("[{}] {}", tab.key(), tab.label()), style))
        })
        .collect();

    let tabs = Tabs::new(titles)
        .select(app.active_tab as usize)
        .divider(Span::raw(" │ "))
        .highlight_style(Style::default().fg(Color::Yellow));

    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(Color::DarkGray));

    frame.render_widget(tabs.block(block), area);
}

/// Draw the main content area based on active tab
fn draw_content(frame: &mut Frame, app: &App, area: Rect) {
    match app.active_tab {
        Tab::Monitor => draw_monitor_tab(frame, app, area),
        Tab::Flows => draw_flows_tab(frame, app, area),
        Tab::Rules => draw_rules_tab(frame, app, area),
        Tab::Logs => draw_logs_tab(frame, app, area),
        Tab::Settings => draw_settings_tab(frame, app, area),
    }
}

/// Draw the Monitor tab - live connection list
fn draw_monitor_tab(frame: &mut Frame, app: &App, area: Rect) {
    let header_cells = ["Time", "Action", "Process", "Destination", "Port", "Rule"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));

    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = app.connections.iter().enumerate().map(|(i, conn)| {
        let action_style = match conn.action.as_str() {
            "ALLOW" => Style::default().fg(Color::Green),
            "DENY" => Style::default().fg(Color::Red),
            "ASK" => Style::default().fg(Color::Yellow),
            _ => Style::default(),
        };

        let selected = i == app.selected_connection;
        let row_style = if selected {
            Style::default().bg(Color::Blue).fg(Color::White)
        } else if conn.is_pending {
            Style::default().bg(Color::Rgb(50, 50, 0))
        } else {
            Style::default()
        };

        // For selected row, override action style too
        let final_action_style = if selected {
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
        } else {
            action_style
        };

        // Format process name - handle System process (PID 4)
        let process_display = if conn.process_id == 4 {
            "System[4]".to_string()
        } else if conn.process_name == "Unknown" || conn.process_name.is_empty() {
            format!("PID:{}", conn.process_id)
        } else {
            format!("{}[{}]", conn.process_name, conn.process_id)
        };

        // Format port - handle ICMP (no ports)
        let port_display = if conn.protocol == "Icmp" || conn.protocol == "ICMP" {
            "ICMP".to_string()
        } else {
            format!("{}:{}", conn.port, conn.protocol)
        };

        Row::new(vec![
            Cell::from(conn.time.clone()),
            Cell::from(conn.action.clone()).style(final_action_style),
            Cell::from(process_display),
            Cell::from(conn.destination.clone()),
            Cell::from(port_display),
            Cell::from(conn.rule_name.clone().unwrap_or_default()),
        ])
        .style(row_style)
        .height(1)
    }).collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),  // Time
            Constraint::Length(6),  // Action
            Constraint::Length(20), // Process
            Constraint::Min(20),    // Destination
            Constraint::Length(10), // Port
            Constraint::Length(15), // Rule
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(format!(
                " Live Connections ({} total, {} blocked) [sel:{}]",
                app.total_connections, app.blocked_connections, app.selected_connection
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue)),
    );

    frame.render_widget(table, area);
}

/// Format duration in human-readable form
fn format_duration(secs: f64) -> String {
    if secs >= 3600.0 {
        format!("{:.1}h", secs / 3600.0)
    } else if secs >= 60.0 {
        format!("{:.1}m", secs / 60.0)
    } else {
        format!("{:.0}s", secs)
    }
}

/// Draw the Flows tab - live TLM flow data with bandwidth
fn draw_flows_tab(frame: &mut Frame, app: &App, area: Rect) {
    // Split area: main table on left, smaller summary on right
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(80), Constraint::Percentage(20)])
        .split(area);

    // Left side: Flow table
    draw_flow_table(frame, app, chunks[0]);

    // Right side: Bandwidth sparkline only (process info not useful until we correlate with ALE)
    draw_bandwidth_summary(frame, app, chunks[1]);
}

/// Draw the flow table (left side of Flows tab)
fn draw_flow_table(frame: &mut Frame, app: &App, area: Rect) {
    let sort_indicator = match app.flow_sort {
        FlowSort::BytesTotal => "Total",
        FlowSort::BytesSent => "↑Sent",
        FlowSort::BytesReceived => "↓Recv",
        FlowSort::Duration => "Time",
        FlowSort::Process => "Proc",
    };

    let header_cells = ["Process", "Destination", "Port", "↑Sent", "↓Recv", "Time"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));

    let header = Row::new(header_cells).height(1);

    // Calculate visible rows (area height minus borders and header)
    let visible_rows = area.height.saturating_sub(3) as usize; // 2 for borders, 1 for header

    // Clamp scroll offset to valid range (handles terminal resize)
    let max_scroll = app.flows.len().saturating_sub(visible_rows.max(1));
    let scroll_offset = app.flow_scroll_offset.min(max_scroll);

    // Ensure selected item is visible
    let selected = app.selected_flow.min(app.flows.len().saturating_sub(1));
    let scroll_offset = if selected < scroll_offset {
        selected
    } else if selected >= scroll_offset + visible_rows && visible_rows > 0 {
        selected.saturating_sub(visible_rows - 1)
    } else {
        scroll_offset
    };

    // Slice flows based on scroll offset
    let start = scroll_offset;
    let end = (start + visible_rows).min(app.flows.len());

    let rows: Vec<Row> = app.flows.iter().enumerate()
        .skip(start)
        .take(end - start)
        .map(|(i, flow)| {
            let selected = i == app.selected_flow;
            let row_style = if selected {
                Style::default().bg(Color::Blue).fg(Color::White)
            } else {
                Style::default()
            };

            // USE the process_name already computed in update_flows() - don't re-lookup!
            let process_name = &flow.process_name;

            // Build destination display - check port cache for SNI/domain info first
            let flow_remote_str = flow.remote_address.to_string();
            let is_ipv6_or_unknown = flow.is_ipv6 || flow_remote_str == "0.0.0.0";

            // Try to get enhanced destination from port cache or connections
            let destination = if let Some((_, _, dest)) = app.get_process_by_port(flow.local_port) {
                dest.clone()
            } else if let Some(conn) = app.connections.iter().find(|c| {
                (c.local_port == flow.local_port && c.local_port > 0) ||
                (c.port == flow.remote_port && (c.destination.contains(&flow_remote_str) || c.remote_address == flow_remote_str))
            }) {
                conn.destination.clone()
            } else {
                // Build descriptive destination from traffic patterns
                match (is_ipv6_or_unknown, flow.remote_port, flow_remote_str.as_str()) {
                    (_, 5353, "224.0.0.251") => "mDNS (multicast)".to_string(),
                    (true, 5353, _) => "mDNS (IPv6)".to_string(),
                    (false, 5353, addr) => format!("mDNS ({})", addr),
                    (true, 53, _) => "DNS (IPv6)".to_string(),
                    (false, 53, addr) => format!("DNS ({})", addr),
                    (true, 443, _) => "HTTPS (IPv6)".to_string(),
                    (false, _, addr) if addr.starts_with("169.254.") => format!("{} (link-local)", addr),
                    (false, _, addr) if addr.starts_with("224.") || addr.starts_with("239.") => format!("{} (multicast)", addr),
                    (true, port, _) if port > 0 => format!("IPv6:{}", port),
                    (true, _, _) => "IPv6".to_string(),
                    _ => flow_remote_str.clone(),
                }
            };

            Row::new(vec![
                Cell::from(process_name.as_str()).style(Style::default().fg(if selected { Color::White } else { Color::Magenta })),
                Cell::from(destination),
                Cell::from(format!("{}", flow.remote_port)),
                Cell::from(format_bytes(flow.bytes_sent)).style(Style::default().fg(if selected { Color::White } else { Color::Green })),
                Cell::from(format_bytes(flow.bytes_received)).style(Style::default().fg(if selected { Color::White } else { Color::Cyan })),
                Cell::from(format_duration(flow.duration_secs)),
            ])
            .style(row_style)
            .height(1)
        }).collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(20), // Process (wider for longer names)
            Constraint::Min(20),    // Destination
            Constraint::Length(6),  // Port
            Constraint::Length(8),  // Sent
            Constraint::Length(8),  // Recv
            Constraint::Length(6),  // Duration
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(format!(
                " Flows ({}-{}/{}) [Sort: {}] ",
                if app.flows.is_empty() { 0 } else { start + 1 },
                end,
                app.flows.len(),
                sort_indicator
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue)),
    );

    frame.render_widget(table, area);
}

/// Draw bandwidth summary (right side of Flows tab)
fn draw_bandwidth_summary(frame: &mut Frame, app: &App, area: Rect) {
    // Split into stats and sparkline
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(9), Constraint::Min(5)])
        .split(area);

    // Get selected flow stats (per-flow, not totals)
    let selected_flow = app.flows.get(app.selected_flow);

    // Stats for selected flow
    let stats_text = if let Some(flow) = selected_flow {
        // Use the process_name already in the Flow struct - don't re-lookup!
        vec![
            Line::from(vec![
                Span::styled(flow.process_name.clone(), Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::raw(" ↑Sent: "),
                Span::styled(format_bytes(flow.bytes_sent), Style::default().fg(Color::Green)),
            ]),
            Line::from(vec![
                Span::raw(" ↓Recv: "),
                Span::styled(format_bytes(flow.bytes_received), Style::default().fg(Color::Cyan)),
            ]),
            Line::from(vec![
                Span::raw(" Total: "),
                Span::styled(format_bytes(flow.bytes_sent + flow.bytes_received), Style::default().fg(Color::Yellow)),
            ]),
            Line::from(vec![
                Span::raw(" Time:  "),
                Span::styled(format_duration(flow.duration_secs), Style::default().fg(Color::White)),
            ]),
        ]
    } else {
        vec![
            Line::from(""),
            Line::from(Span::styled(" No flow", Style::default().fg(Color::DarkGray))),
            Line::from(Span::styled(" selected", Style::default().fg(Color::DarkGray))),
        ]
    };

    let stats = Paragraph::new(stats_text).block(
        Block::default()
            .title(" Selected ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Magenta)),
    );
    frame.render_widget(stats, chunks[0]);

    // Draw bidirectional flow rate graph (sent up, recv down)
    draw_bidirectional_rate_graph(frame, app, chunks[1]);
}

/// Draw a simple flow rate display
fn draw_bidirectional_rate_graph(frame: &mut Frame, app: &App, area: Rect) {
    // Calculate rates from bandwidth history
    let (current_sent, current_recv, samples) = if app.bandwidth_history.len() >= 2 {
        let history: Vec<_> = app.bandwidth_history.iter().collect();
        let len = history.len();

        // Get rate from last two samples
        let sent_rate = history[len-1].bytes_sent.saturating_sub(history[len-2].bytes_sent);
        let recv_rate = history[len-1].bytes_received.saturating_sub(history[len-2].bytes_received);

        (sent_rate, recv_rate, len)
    } else {
        (0, 0, app.bandwidth_history.len())
    };

    // Simple text-based display that will definitely render
    let text = vec![
        Line::from(vec![
            Span::styled("↑ Sent:  ", Style::default().fg(Color::Green)),
            Span::styled(format!("{}/s", format_bytes_short(current_sent)), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("↓ Recv:  ", Style::default().fg(Color::Cyan)),
            Span::styled(format!("{}/s", format_bytes_short(current_recv)), Style::default().fg(Color::White)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Total:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("↑{} ↓{}",
                format_bytes_short(app.total_bytes_sent),
                format_bytes_short(app.total_bytes_received)
            ), Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::styled("Flows:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{}", app.active_flows), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("Samples: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{}", samples), Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let widget = Paragraph::new(text).block(
        Block::default()
            .title(" Flow Rate ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(widget, area);
}

/// Format bytes in short form (no decimal for small values)
fn format_bytes_short(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1}K", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1}M", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1}G", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Extract a human-readable target summary from rule conditions
fn format_rule_target(rule: &sereno_core::types::Rule) -> String {
    use sereno_core::types::{Condition, DomainPattern, IpMatcher, PortMatcher};

    let mut parts = Vec::new();

    for condition in &rule.conditions {
        match condition {
            Condition::Domain { patterns } => {
                for pattern in patterns {
                    let domain_str = match pattern {
                        DomainPattern::Exact { value } => value.clone(),
                        DomainPattern::Wildcard { pattern } => pattern.clone(),
                        DomainPattern::Regex { pattern } => format!("/{}/", pattern),
                    };
                    parts.push(domain_str);
                }
            }
            Condition::RemotePort { matcher } => {
                let port_str = match matcher {
                    PortMatcher::Single { port } => format!(":{}", port),
                    PortMatcher::Range { start, end } => format!(":{}-{}", start, end),
                    PortMatcher::List { ports } => {
                        let ps: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
                        format!(":{}", ps.join(","))
                    }
                    PortMatcher::Any => ":*".to_string(),
                };
                parts.push(port_str);
            }
            Condition::RemoteAddress { matcher } => {
                let ip_str = match matcher {
                    IpMatcher::Single { address } => format!("IP:{}", address),
                    IpMatcher::Cidr { network } => format!("IP:{}", network),
                    IpMatcher::List { addresses } => format!("IP:{{{}}}", addresses.len()),
                    IpMatcher::Any => "IP:*".to_string(),
                };
                parts.push(ip_str);
            }
            Condition::ProcessPath { pattern } => {
                parts.push(format!("path:{}", pattern));
            }
            Condition::ProcessName { pattern } => {
                parts.push(format!("proc:{}", pattern));
            }
            Condition::Protocol { protocol } => {
                parts.push(format!("{:?}", protocol));
            }
            _ => {}
        }
    }

    if parts.is_empty() {
        "Any".to_string()
    } else {
        parts.join(" ")
    }
}

/// Draw the Rules tab
fn draw_rules_tab(frame: &mut Frame, app: &App, area: Rect) {
    let header_cells = ["", "Action", "Target", "Name", "Pri", "Hits"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));

    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = app.rules.iter().enumerate().map(|(i, rule)| {
        let cursor_selected = i == app.selected_rule;
        let multi_selected = app.selected_rules.contains(&rule.id);

        // Base styles - highlight differently for cursor vs multi-select
        let row_style = if cursor_selected {
            Style::default().bg(Color::Blue).fg(Color::White)
        } else if multi_selected {
            Style::default().bg(Color::DarkGray).fg(Color::White)
        } else if !rule.enabled {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default()
        };

        let action_style = if cursor_selected || multi_selected {
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
        } else if !rule.enabled {
            Style::default().fg(Color::DarkGray)
        } else {
            match format!("{}", rule.action).as_str() {
                "Allow" => Style::default().fg(Color::Green),
                "Deny" => Style::default().fg(Color::Red),
                _ => Style::default().fg(Color::Yellow),
            }
        };

        // Selection indicator: [x] for selected, [ ] for not selected
        let select_indicator = if multi_selected { "[x]" } else { "[ ]" };

        // Format the target conditions
        let target = format_rule_target(rule);

        // Enabled indicator merged with action display
        let enabled_indicator = if rule.enabled { "" } else { "(off) " };
        let action_display = format!("{}{}", enabled_indicator, rule.action);

        Row::new(vec![
            Cell::from(select_indicator),
            Cell::from(action_display).style(action_style),
            Cell::from(target),
            Cell::from(rule.name.clone()),
            Cell::from(format!("{}", rule.priority)),
            Cell::from(format!("{}", rule.hit_count)),
        ])
        .style(row_style)
        .height(1)
    }).collect();

    // Title with selection count if any rules are selected
    let title = if app.selected_rules.is_empty() {
        format!(" Rules ({}) ", app.rules.len())
    } else {
        format!(" Rules ({}) [{} selected - Shift+D to delete] ", app.rules.len(), app.selected_rules.len())
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(3),  // Sel (checkbox)
            Constraint::Length(12), // Action (with disabled indicator)
            Constraint::Min(25),    // Target (domain, port, IP, etc.)
            Constraint::Length(20), // Name
            Constraint::Length(4),  // Priority
            Constraint::Length(5),  // Hits
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue)),
    );

    frame.render_widget(table, area);
}

/// Draw the Logs tab
fn draw_logs_tab(frame: &mut Frame, app: &App, area: Rect) {
    let log_items: Vec<ListItem> = app
        .logs
        .iter()
        .map(|log| {
            let style = if log.contains("ERROR") || log.contains("error") {
                Style::default().fg(Color::Red)
            } else if log.contains("WARN") || log.contains("warn") {
                Style::default().fg(Color::Yellow)
            } else if log.contains("INFO") || log.contains("info") {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(log.clone())).style(style)
        })
        .collect();

    let list = List::new(log_items).block(
        Block::default()
            .title(format!(" Logs ({}) ", app.logs.len()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue)),
    );

    frame.render_widget(list, area);
}

/// Draw the Settings tab
fn draw_settings_tab(frame: &mut Frame, app: &App, area: Rect) {
    let settings_text = vec![
        Line::from(""),
        Line::from(vec![
            Span::raw("  Database:     "),
            Span::styled(
                "C:\\Users\\Virgil\\AppData\\Local\\sereno\\sereno.db",
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("  Driver:       "),
            Span::styled(app.driver_status.label(),
                if app.driver_status.is_running() {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::Yellow)
                }
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("  Mode:         "),
            Span::styled(app.mode.label(), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("  Admin:        "),
            Span::styled(
                if app.is_admin { "Yes" } else { "No" },
                if app.is_admin {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::Yellow)
                },
            ),
        ]),
        Line::from(""),
        Line::from(""),
        Line::from(Span::styled(
            "  Press 'D' to toggle driver, 'R' to reload rules",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let paragraph = Paragraph::new(settings_text).block(
        Block::default()
            .title(" Settings ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue)),
    );

    frame.render_widget(paragraph, area);
}

/// Draw the footer with keyboard shortcuts and pending ASK prompt
fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let content = if let Some(ref pending) = app.pending_ask {
        // Show pending ASK prompt
        Line::from(vec![
            Span::styled(" PENDING: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw(&pending.process_name),
            Span::raw(" → "),
            Span::styled(&pending.destination, Style::default().fg(Color::Cyan)),
            Span::raw(format!(":{}", pending.port)),
            Span::raw("  "),
            Span::styled("[A]llow", Style::default().fg(Color::Green)),
            Span::raw(" "),
            Span::styled("[B]lock", Style::default().fg(Color::Red)),
            Span::raw(" "),
            Span::styled("[R]ule", Style::default().fg(Color::Yellow)),
            Span::raw(" "),
            Span::styled("[I]gnore", Style::default().fg(Color::DarkGray)),
        ])
    } else {
        // Show tab-specific keyboard shortcuts
        match app.active_tab {
            Tab::Monitor => Line::from(vec![
                Span::raw(" "),
                Span::styled("↑↓/jk", Style::default().fg(Color::Cyan)),
                Span::raw(" Navigate  "),
                Span::styled("T", Style::default().fg(Color::Green)),
                Span::raw(" Toggle  "),
                Span::styled("C", Style::default().fg(Color::Cyan)),
                Span::raw(" Clear  "),
                Span::styled("Tab", Style::default().fg(Color::Cyan)),
                Span::raw(" Switch tabs  "),
                Span::styled("Q", Style::default().fg(Color::Cyan)),
                Span::raw(" Quit"),
            ]),
            Tab::Flows => Line::from(vec![
                Span::raw(" "),
                Span::styled("↑↓", Style::default().fg(Color::Cyan)),
                Span::raw(" Navigate  "),
                Span::styled("S", Style::default().fg(Color::Green)),
                Span::raw(" Sort  "),
                Span::styled("Tab", Style::default().fg(Color::Cyan)),
                Span::raw(" Switch tabs  "),
                Span::styled("Q", Style::default().fg(Color::Cyan)),
                Span::raw(" Quit"),
            ]),
            Tab::Rules => Line::from(vec![
                Span::raw(" "),
                Span::styled("↑↓", Style::default().fg(Color::Cyan)),
                Span::raw(" Nav  "),
                Span::styled("Space", Style::default().fg(Color::Magenta)),
                Span::raw(" Select  "),
                Span::styled("T", Style::default().fg(Color::Green)),
                Span::raw(" Toggle  "),
                Span::styled("d", Style::default().fg(Color::Red)),
                Span::raw(" Del  "),
                Span::styled("D", Style::default().fg(Color::Red)),
                Span::raw(" BulkDel  "),
                Span::styled("Esc", Style::default().fg(Color::Yellow)),
                Span::raw(" Clear  "),
                Span::styled("Q", Style::default().fg(Color::Cyan)),
                Span::raw(" Quit"),
            ]),
            Tab::Logs => Line::from(vec![
                Span::raw(" "),
                Span::styled("C", Style::default().fg(Color::Cyan)),
                Span::raw(" Clear logs  "),
                Span::styled("Tab", Style::default().fg(Color::Cyan)),
                Span::raw(" Switch tabs  "),
                Span::styled("Q", Style::default().fg(Color::Cyan)),
                Span::raw(" Quit"),
            ]),
            Tab::Settings => Line::from(vec![
                Span::raw(" "),
                Span::styled("D", Style::default().fg(Color::Cyan)),
                Span::raw(" Toggle driver  "),
                Span::styled("R", Style::default().fg(Color::Cyan)),
                Span::raw(" Reload rules  "),
                Span::styled("Tab", Style::default().fg(Color::Cyan)),
                Span::raw(" Switch tabs  "),
                Span::styled("Q", Style::default().fg(Color::Cyan)),
                Span::raw(" Quit"),
            ]),
        }
    };

    let footer = Paragraph::new(content).block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(footer, area);
}
