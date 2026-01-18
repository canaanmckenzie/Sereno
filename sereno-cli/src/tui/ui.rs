//! TUI UI Rendering

use crate::tui::app::{App, AuthStatus, ConnectionSort, DriverStatus, FlowSort, Tab, ViewMode};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table, Tabs},
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

    // Draw info popup overlay if active
    if app.show_info_popup {
        draw_info_popup(frame, app);
    }

    // Draw help overlay if active (on top of everything)
    if app.show_help {
        draw_help_overlay(frame, app);
    }
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

    let mode_style = if app.mode == crate::tui::app::Mode::SilentAllow {
        Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Cyan)
    };
    let mode_span = Span::styled(app.mode.label(), mode_style);

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
        Tab::Connections => draw_connections_tab(frame, app, area),
        Tab::Rules => draw_rules_tab(frame, app, area),
        Tab::Logs => draw_logs_tab(frame, app, area),
        Tab::Settings => draw_settings_tab(frame, app, area),
    }
}

/// Draw the unified Connections tab - merged ALE auth + TLM bandwidth
fn draw_connections_tab(frame: &mut Frame, app: &App, area: Rect) {
    // Check if we need to show search bar
    let show_search_bar = app.search_active || !app.search_query.is_empty();

    if show_search_bar {
        // Split area: search bar at top, content below
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // Search bar
                Constraint::Min(5),    // Content
            ])
            .split(area);

        // Draw search bar
        let search_style = if app.search_active {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let cursor = if app.search_active { "▌" } else { "" };
        let search_text = format!(" / Search: {}{} ", app.search_query, cursor);
        let hint = if app.search_active {
            " [Enter=confirm, Esc=cancel] "
        } else {
            " [/=edit, Esc=clear] "
        };

        let search_line = Line::from(vec![
            Span::styled(search_text, search_style),
            Span::styled(hint, Style::default().fg(Color::DarkGray)),
        ]);
        let search_bar = Paragraph::new(search_line);
        frame.render_widget(search_bar, chunks[0]);

        // Draw content in remaining area
        match app.view_mode {
            ViewMode::Detailed => draw_connections_detailed(frame, app, chunks[1]),
            ViewMode::Grouped => draw_connections_grouped(frame, app, chunks[1]),
        }
    } else {
        // No search bar - use full area
        match app.view_mode {
            ViewMode::Detailed => draw_connections_detailed(frame, app, area),
            ViewMode::Grouped => draw_connections_grouped(frame, app, area),
        }
    }
}

/// Format direction indicator
fn direction_indicator(direction: sereno_core::types::Direction) -> &'static str {
    match direction {
        sereno_core::types::Direction::Outbound => "→",
        sereno_core::types::Direction::Inbound => "←",
        sereno_core::types::Direction::Any => "↔",
    }
}

/// Truncate long strings (especially IPv6 addresses) for display
fn truncate_for_display(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len > 3 {
        format!("{}...", &s[..max_len - 3])
    } else {
        s[..max_len].to_string()
    }
}

/// Draw detailed view of connections
fn draw_connections_detailed(frame: &mut Frame, app: &App, area: Rect) {
    use crate::signature::SignatureStatus;

    // Sort indicator for title
    let sort_indicator = match app.unified_sort {
        ConnectionSort::Time => "Time",
        ConnectionSort::BytesTotal => "Bytes",
        ConnectionSort::Process => "Proc",
        ConnectionSort::Destination => "Dest",
    };

    // Header row
    let header_cells = ["Time", "Auth", "Dir", "Sig", "Process", "Destination", "Port", "↑Sent", "↓Recv"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));

    let header = Row::new(header_cells).height(1);

    // Calculate visible rows (subtract 1 more if filters are active for filter bar)
    let filter_bar_height = if app.filters.any_active() { 1 } else { 0 };
    let visible_rows = area.height.saturating_sub(3 + filter_bar_height as u16) as usize;

    // Get filtered and sorted connections
    let sorted_connections = app.get_filtered_connections();

    // Clamp scroll offset and selection
    let max_scroll = sorted_connections.len().saturating_sub(visible_rows.max(1));
    let scroll_offset = app.unified_scroll_offset.min(max_scroll);

    // Ensure selected item is visible
    let selected = app.selected_unified.min(sorted_connections.len().saturating_sub(1));
    let scroll_offset = if selected < scroll_offset {
        selected
    } else if selected >= scroll_offset + visible_rows && visible_rows > 0 {
        selected.saturating_sub(visible_rows - 1)
    } else {
        scroll_offset
    };

    // Slice for display
    let start = scroll_offset;
    let end = (start + visible_rows).min(sorted_connections.len());

    let rows: Vec<Row> = sorted_connections.iter()
        .enumerate()
        .skip(start)
        .take(end - start)
        .map(|(i, (_, conn))| {
            let is_selected = i == app.selected_unified;

            // Auth status color
            let auth_style = if is_selected {
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                match conn.auth_status {
                    AuthStatus::Allow => Style::default().fg(Color::Green),
                    AuthStatus::Deny => Style::default().fg(Color::Red),
                    AuthStatus::Pending => Style::default().fg(Color::Yellow),
                    AuthStatus::Auto => Style::default().fg(Color::Cyan),
                    AuthStatus::SilentAllow => Style::default().fg(Color::Magenta),
                }
            };

            // Row background
            let row_style = if is_selected {
                Style::default().bg(Color::Blue).fg(Color::White)
            } else if conn.auth_status == AuthStatus::Pending {
                Style::default().bg(Color::Rgb(50, 50, 0))
            } else if !conn.is_active {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default()
            };

            // Signature status - show "SYS" for system processes where signing doesn't apply
            let is_system_process = conn.process_id == 0
                || conn.process_id == 4
                || conn.process_name.to_lowercase() == "system"
                || conn.process_name.to_lowercase().starts_with("system ");

            let (sig_label, sig_style) = if is_system_process {
                ("SYS", Style::default().fg(Color::Cyan))
            } else {
                match &conn.signature_status {
                    Some(SignatureStatus::Signed { .. }) => ("OK", Style::default().fg(Color::Green)),
                    Some(SignatureStatus::Unsigned) => ("!!", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                    Some(SignatureStatus::Invalid) => ("XX", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                    Some(SignatureStatus::Unknown) | None => ("?", Style::default().fg(Color::DarkGray)),
                }
            };

            // Process display
            let process_display = if conn.process_id == 4 {
                "System[4]".to_string()
            } else if conn.process_name == "Unknown" || conn.process_name.is_empty() {
                format!("PID:{}", conn.process_id)
            } else {
                format!("{}[{}]", conn.process_name, conn.process_id)
            };

            // Protocol for port display
            let protocol_str = match conn.protocol {
                sereno_core::types::Protocol::Tcp => "TCP",
                sereno_core::types::Protocol::Udp => "UDP",
                sereno_core::types::Protocol::Icmp => "ICMP",
                _ => "",
            };

            // Port display
            let port_display = if protocol_str == "ICMP" {
                "ICMP".to_string()
            } else {
                format!("{}:{}", conn.remote_port, protocol_str)
            };

            // Bandwidth display
            let sent_style = if is_selected { Style::default().fg(Color::White) } else { Style::default().fg(Color::Green) };
            let recv_style = if is_selected { Style::default().fg(Color::White) } else { Style::default().fg(Color::Cyan) };

            // Direction indicator with color
            let dir_str = direction_indicator(conn.direction);
            let dir_style = match conn.direction {
                sereno_core::types::Direction::Inbound => Style::default().fg(Color::Yellow),
                sereno_core::types::Direction::Outbound => Style::default().fg(Color::Cyan),
                _ => Style::default(),
            };

            // Truncate long destinations (especially IPv6) for display
            let dest_display = truncate_for_display(&conn.destination, 50);

            Row::new(vec![
                Cell::from(conn.first_seen.clone()),
                Cell::from(conn.auth_status.label()).style(auth_style),
                Cell::from(dir_str).style(dir_style),
                Cell::from(sig_label).style(sig_style),
                Cell::from(process_display),
                Cell::from(dest_display),
                Cell::from(port_display),
                Cell::from(format_bytes(conn.bytes_sent)).style(sent_style),
                Cell::from(format_bytes(conn.bytes_received)).style(recv_style),
            ])
            .style(row_style)
            .height(1)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),  // Time
            Constraint::Length(5),  // Auth
            Constraint::Length(3),  // Dir
            Constraint::Length(3),  // Sig
            Constraint::Length(28), // Process (wider for name + PID)
            Constraint::Min(40),    // Destination (expanded)
            Constraint::Length(9),  // Port
            Constraint::Length(8),  // Sent
            Constraint::Length(8),  // Recv
        ],
    );

    // Build filter indicator for title
    let filter_hint = if app.filters.any_active() {
        let active: Vec<&str> = crate::tui::app::ConnectionFilters::LABELS
            .iter()
            .enumerate()
            .filter(|(i, _)| app.filters.get(*i))
            .map(|(_, label)| *label)
            .collect();
        format!(" [hiding: {}]", active.join(","))
    } else {
        String::new()
    };

    let table = table.header(header)
    .block(
        Block::default()
            .title(format!(
                " Connections ({}-{}/{}) [{}] ↑{} ↓{}{} [f=filter] ",
                if sorted_connections.is_empty() { 0 } else { start + 1 },
                end,
                sorted_connections.len(),
                sort_indicator,
                format_bytes(app.total_bytes_sent),
                format_bytes(app.total_bytes_received),
                filter_hint,
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue)),
    );

    frame.render_widget(table, area);
}

/// Draw grouped view of connections - aggregated by process + destination (like Little Snitch)
fn draw_connections_grouped(frame: &mut Frame, app: &App, area: Rect) {
    let header_cells = ["Process", "Destination", "Proto", "#", "↑Sent", "↓Recv", "Status"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));

    let header = Row::new(header_cells).height(1);

    // Get filtered grouped connections
    let filtered_groups = app.get_filtered_grouped();

    // Calculate visible rows
    let visible_rows = (area.height.saturating_sub(3)) as usize; // -3 for borders and header
    let start = app.grouped_scroll_offset.min(filtered_groups.len().saturating_sub(1));
    let end = (start + visible_rows).min(filtered_groups.len());

    let rows: Vec<Row> = filtered_groups
        .iter()
        .enumerate()
        .skip(start)
        .take(end - start)
        .map(|(i, group)| {
            let is_selected = i == app.selected_grouped;

            // Auth status color
            let auth_style = if is_selected {
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                match group.auth_status {
                    AuthStatus::Allow => Style::default().fg(Color::Green),
                    AuthStatus::Deny => Style::default().fg(Color::Red),
                    AuthStatus::Pending => Style::default().fg(Color::Yellow),
                    AuthStatus::Auto => Style::default().fg(Color::Cyan),
                    AuthStatus::SilentAllow => Style::default().fg(Color::Magenta),
                }
            };

            let row_style = if is_selected {
                Style::default().bg(Color::Blue).fg(Color::White)
            } else if group.is_any_active {
                Style::default().bg(Color::Rgb(0, 30, 0))
            } else {
                Style::default()
            };

            // Process display with connection count if multiple PIDs
            let proc_display = if group.pid_count > 1 {
                format!("{} ({})", group.process_name, group.pid_count)
            } else {
                group.process_name.clone()
            };
            let proc_display = truncate_for_display(&proc_display, 18);

            // Truncate destination
            let dest_display = truncate_for_display(&group.destination, 55);

            // Protocol display: show both if TCP+UDP, otherwise just one
            let proto_display = if group.protocols.len() > 1 {
                "TCP+UDP".to_string()
            } else if let Some(proto) = group.protocols.first() {
                match proto {
                    sereno_core::types::Protocol::Tcp => "TCP".to_string(),
                    sereno_core::types::Protocol::Udp => "UDP".to_string(),
                    sereno_core::types::Protocol::Icmp => "ICMP".to_string(),
                    _ => "?".to_string(),
                }
            } else {
                "?".to_string()
            };

            // Connection count
            let count_display = format!("{}", group.connection_count);

            Row::new(vec![
                Cell::from(proc_display).style(if is_selected { Style::default() } else { Style::default().fg(Color::Magenta) }),
                Cell::from(dest_display),
                Cell::from(proto_display).style(Style::default().fg(Color::DarkGray)),
                Cell::from(count_display),
                Cell::from(format_bytes(group.total_bytes_sent)).style(if is_selected { Style::default() } else { Style::default().fg(Color::Green) }),
                Cell::from(format_bytes(group.total_bytes_received)).style(if is_selected { Style::default() } else { Style::default().fg(Color::Cyan) }),
                Cell::from(group.auth_status.label()).style(auth_style),
            ])
            .style(row_style)
            .height(1)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(20), // Process (with PID count)
            Constraint::Min(40),    // Destination (expanded)
            Constraint::Length(7),  // Proto
            Constraint::Length(3),  // # (count)
            Constraint::Length(8),  // Sent
            Constraint::Length(8),  // Recv
            Constraint::Length(6),  // Status
        ],
    );

    // Build filter indicator for title
    let filter_hint = if app.filters.any_active() {
        let active: Vec<&str> = crate::tui::app::ConnectionFilters::LABELS
            .iter()
            .enumerate()
            .filter(|(i, _)| app.filters.get(*i))
            .map(|(_, label)| *label)
            .collect();
        format!(" [hiding: {}]", active.join(","))
    } else {
        String::new()
    };

    let table = table.header(header)
    .block(
        Block::default()
            .title(format!(
                " {} ({} groups){} ↑{} ↓{} [f=filter] ",
                filtered_groups.get(app.selected_grouped)
                    .map(|g| g.process_name.as_str())
                    .unwrap_or("No selection"),
                filtered_groups.len(),
                filter_hint,
                format_bytes(app.total_bytes_sent),
                format_bytes(app.total_bytes_received),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Magenta)),
    );

    frame.render_widget(table, area);
}

/// Draw the Monitor tab - live connection list (legacy, kept for reference)
#[allow(dead_code)]
fn draw_monitor_tab(frame: &mut Frame, app: &App, area: Rect) {
    use crate::signature::SignatureStatus;

    let header_cells = ["Time", "Action", "Sig", "Process", "Destination", "Port"]
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

        // Format signature status - show "SYS" for system processes
        let is_system_process = conn.process_id == 0
            || conn.process_id == 4
            || conn.process_name.to_lowercase() == "system"
            || conn.process_name.to_lowercase().starts_with("system ");

        let (sig_label, sig_style) = if is_system_process {
            ("SYS", Style::default().fg(Color::Cyan))
        } else {
            match &conn.signature_status {
                Some(SignatureStatus::Signed { .. }) => ("OK", Style::default().fg(Color::Green)),
                Some(SignatureStatus::Unsigned) => ("!!", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                Some(SignatureStatus::Invalid) => ("XX", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                Some(SignatureStatus::Unknown) | None => ("?", Style::default().fg(Color::DarkGray)),
            }
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
            Cell::from(sig_label).style(sig_style),
            Cell::from(process_display),
            Cell::from(conn.destination.clone()),
            Cell::from(port_display),
        ])
        .style(row_style)
        .height(1)
    }).collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),  // Time
            Constraint::Length(6),  // Action
            Constraint::Length(3),  // Sig (signature status)
            Constraint::Length(22), // Process
            Constraint::Min(20),    // Destination
            Constraint::Length(10), // Port
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

/// Format rule validity as a short string (for display)
fn format_rule_validity(rule: &sereno_core::types::Rule) -> String {
    use chrono::Utc;
    use sereno_core::types::Validity;

    match &rule.validity {
        Validity::Permanent => "∞".to_string(),
        Validity::Once => "1×".to_string(),
        Validity::UntilQuit { .. } => "quit".to_string(),
        Validity::Timed { expires_at } => {
            let now = Utc::now();
            if *expires_at <= now {
                "expired".to_string()
            } else {
                let duration = *expires_at - now;
                let hours = duration.num_hours();
                let minutes = duration.num_minutes();
                let days = duration.num_days();

                if days > 0 {
                    format!("{}d", days)
                } else if hours > 0 {
                    format!("{}h", hours)
                } else if minutes > 0 {
                    format!("{}m", minutes)
                } else {
                    "<1m".to_string()
                }
            }
        }
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
    let header_cells = ["", "Action", "Target", "TTL", "Hits"]
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

        // Format validity/TTL
        let validity = format_rule_validity(rule);
        let validity_style = if validity == "expired" {
            Style::default().fg(Color::Red)
        } else if validity.ends_with('m') || validity.ends_with('h') {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        // Enabled indicator merged with action display
        let enabled_indicator = if rule.enabled { "" } else { "(off) " };
        let action_display = format!("{}{}", enabled_indicator, rule.action);

        Row::new(vec![
            Cell::from(select_indicator),
            Cell::from(action_display).style(action_style),
            Cell::from(target),
            Cell::from(validity).style(validity_style),
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
            Constraint::Min(30),    // Target (domain, port, IP, etc.)
            Constraint::Length(7),  // TTL (validity)
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
    use crate::tui::app::RuleDuration;

    let content = if let Some(ref prompt) = app.duration_prompt {
        // Show duration selection prompt
        let durations = RuleDuration::all();
        let mut spans = vec![
            Span::styled(" BLOCK ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::styled(&prompt.destination, Style::default().fg(Color::Cyan)),
            Span::raw(format!(":{} for: ", prompt.port)),
        ];

        for (i, duration) in durations.iter().enumerate() {
            let label = format!("[{}]{}", i + 1, duration.short_label());
            if i == prompt.selected_index {
                spans.push(Span::styled(label, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD).add_modifier(Modifier::UNDERLINED)));
            } else {
                spans.push(Span::styled(label, Style::default().fg(Color::DarkGray)));
            }
            spans.push(Span::raw(" "));
        }
        spans.push(Span::raw("  "));
        spans.push(Span::styled("Enter", Style::default().fg(Color::Green)));
        spans.push(Span::raw("=Confirm  "));
        spans.push(Span::styled("Esc", Style::default().fg(Color::Red)));
        spans.push(Span::raw("=Cancel"));

        Line::from(spans)
    } else if let Some(ref pending) = app.pending_ask {
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
            Tab::Connections => Line::from(vec![
                Span::raw(" "),
                Span::styled("↑↓/jk", Style::default().fg(Color::Cyan)),
                Span::raw(" Nav  "),
                Span::styled("G", Style::default().fg(Color::Magenta)),
                Span::raw(" Group  "),
                Span::styled("I", Style::default().fg(Color::Yellow)),
                Span::raw(" Info  "),
                Span::styled("T", Style::default().fg(Color::Green)),
                Span::raw(" Toggle  "),
                Span::styled("S", Style::default().fg(Color::Magenta)),
                Span::raw(" Sort  "),
                Span::styled("C", Style::default().fg(Color::Cyan)),
                Span::raw(" Clear  "),
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
                Span::styled("M", Style::default().fg(Color::Magenta)),
                Span::raw(" Mode  "),
                Span::styled("D", Style::default().fg(Color::Cyan)),
                Span::raw(" Driver  "),
                Span::styled("R", Style::default().fg(Color::Cyan)),
                Span::raw(" Reload  "),
                Span::styled("Tab", Style::default().fg(Color::Cyan)),
                Span::raw(" Switch  "),
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

/// Draw info popup overlay for selected connection
fn draw_info_popup(frame: &mut Frame, app: &App) {
    use crate::signature::SignatureStatus;

    // Get selected connection based on view mode
    let conn_info = if app.view_mode == ViewMode::Grouped {
        // For grouped view, show group info + individual connections
        let filtered_groups = app.get_filtered_grouped();
        filtered_groups.get(app.selected_grouped).map(|group| {
            // Format ports list
            let ports_str = if group.ports.len() > 5 {
                let first_five: Vec<String> = group.ports.iter().take(5).map(|p| p.to_string()).collect();
                format!("{} (+{})", first_five.join(", "), group.ports.len() - 5)
            } else {
                group.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
            };

            // Format protocols
            let protocols_str = group.protocols.iter()
                .map(|p| match p {
                    sereno_core::types::Protocol::Tcp => "TCP",
                    sereno_core::types::Protocol::Udp => "UDP",
                    sereno_core::types::Protocol::Icmp => "ICMP",
                    _ => "?",
                })
                .collect::<Vec<_>>()
                .join(", ");

            // Find individual connections that belong to this group
            // Also build a map of local_port -> PID for resolving TLM-only (PID 0) entries
            let mut port_to_pid: std::collections::HashMap<u16, u32> = std::collections::HashMap::new();
            for conn in app.unified_connections.values() {
                if conn.process_id != 0 {
                    port_to_pid.insert(conn.local_port, conn.process_id);
                }
            }

            let mut individual_conns: Vec<String> = Vec::new();
            for conn in app.unified_connections.values() {
                if conn.process_name == group.process_name && conn.destination == group.destination {
                    let proto = match conn.protocol {
                        sereno_core::types::Protocol::Tcp => "TCP",
                        sereno_core::types::Protocol::Udp => "UDP",
                        _ => "?",
                    };
                    let active = if conn.is_active { "●" } else { "○" };

                    // For PID 0 (TLM-only), try to resolve from port or show "TLM"
                    let pid_display = if conn.process_id == 0 {
                        // Try to find PID from a related connection with same local port
                        if let Some(&resolved_pid) = port_to_pid.get(&conn.local_port) {
                            format!("~{}", resolved_pid) // ~ indicates inferred PID
                        } else {
                            "TLM".to_string() // TLM-only, no process info
                        }
                    } else {
                        conn.process_id.to_string()
                    };

                    individual_conns.push(format!(
                        "{} PID:{} :{}→:{} {} ↑{} ↓{}",
                        active,
                        pid_display,
                        conn.local_port,
                        conn.remote_port,
                        proto,
                        format_bytes(conn.bytes_sent),
                        format_bytes(conn.bytes_received),
                    ));
                }
            }

            let mut info: Vec<(String, String)> = vec![
                ("Process".to_string(), group.process_name.clone()),
                ("PIDs".to_string(), format!("{} unique", group.pid_count)),
                ("".to_string(), "".to_string()), // Separator
                ("Destination".to_string(), group.destination.clone()),
                ("Ports".to_string(), ports_str),
                ("Protocols".to_string(), protocols_str),
                ("".to_string(), "".to_string()), // Separator
                ("Connections".to_string(), format!("{}", group.connection_count)),
                ("Total Sent".to_string(), format_bytes(group.total_bytes_sent)),
                ("Total Received".to_string(), format_bytes(group.total_bytes_received)),
                ("Status".to_string(), group.auth_status.label().to_string()),
                ("Active".to_string(), if group.is_any_active { "Yes" } else { "No" }.to_string()),
                ("First Seen".to_string(), group.first_seen.clone()),
            ];

            // Add individual connections section if there are multiple
            if !individual_conns.is_empty() {
                info.push(("".to_string(), "".to_string())); // Separator
                info.push(("─ Individual".to_string(), "Connections ─".to_string()));
                // Show up to 8 individual connections
                for (i, conn_str) in individual_conns.iter().take(8).enumerate() {
                    info.push((format!("  #{}", i + 1), conn_str.clone()));
                }
                if individual_conns.len() > 8 {
                    info.push(("  ...".to_string(), format!("(+{} more)", individual_conns.len() - 8)));
                }
            }

            info
        })
    } else {
        // For detailed view, show connection info
        app.selected_unified_connection().map(|conn| {
            // Check if system process where signing doesn't apply
            let is_system_process = conn.process_id == 0
                || conn.process_id == 4
                || conn.process_name.to_lowercase() == "system"
                || conn.process_name.to_lowercase().starts_with("system ");

            let sig_info = if is_system_process {
                "○ System Process (N/A)".to_string()
            } else {
                match &conn.signature_status {
                    Some(SignatureStatus::Signed { signer }) => format!("✓ Signed: {}", signer),
                    Some(SignatureStatus::Unsigned) => "⚠ UNSIGNED".to_string(),
                    Some(SignatureStatus::Invalid) => "✗ INVALID".to_string(),
                    Some(SignatureStatus::Unknown) | None => "? Unknown".to_string(),
                }
            };

            let direction = match conn.direction {
                sereno_core::types::Direction::Outbound => "Outbound →",
                sereno_core::types::Direction::Inbound => "Inbound ←",
                sereno_core::types::Direction::Any => "Any ↔",
            };

            let protocol = match conn.protocol {
                sereno_core::types::Protocol::Tcp => "TCP",
                sereno_core::types::Protocol::Udp => "UDP",
                sereno_core::types::Protocol::Icmp => "ICMP",
                _ => "Other",
            };

            vec![
                ("Process".to_string(), format!("{} [PID: {}]", conn.process_name, conn.process_id)),
                ("Path".to_string(), if conn.process_path.is_empty() { "(unknown)".to_string() } else { conn.process_path.clone() }),
                ("Signature".to_string(), sig_info),
                ("".to_string(), "".to_string()), // Separator
                ("Destination".to_string(), conn.destination.clone()),
                ("Remote IP".to_string(), conn.remote_address.to_string()),
                ("Port".to_string(), format!("{} ({})", conn.remote_port, protocol)),
                ("Local Port".to_string(), format!("{}", conn.local_port)),
                ("Direction".to_string(), direction.to_string()),
                ("".to_string(), "".to_string()), // Separator
                ("Status".to_string(), conn.auth_status.label().to_string()),
                ("Sent".to_string(), format_bytes(conn.bytes_sent)),
                ("Received".to_string(), format_bytes(conn.bytes_received)),
                ("First Seen".to_string(), conn.first_seen.clone()),
                ("Active".to_string(), if conn.is_active { "Yes" } else { "No" }.to_string()),
            ]
        })
    };

    let Some(info) = conn_info else {
        return;
    };

    // Calculate popup size and position (centered)
    // Wider popup for grouped view with individual connections
    let area = frame.area();
    let popup_width = 75.min(area.width.saturating_sub(4));
    let popup_height = (info.len() as u16 + 4).min(area.height.saturating_sub(4));

    let popup_x = (area.width.saturating_sub(popup_width)) / 2;
    let popup_y = (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    // Clear the area behind the popup
    frame.render_widget(Clear, popup_area);

    // Build content lines
    let mut lines: Vec<Line> = Vec::new();

    for (label, value) in info {
        if label.is_empty() {
            // Separator line
            lines.push(Line::from(Span::styled(
                "─".repeat((popup_width - 2) as usize),
                Style::default().fg(Color::DarkGray),
            )));
        } else {
            let label_style = if label.starts_with("  #") || label.starts_with("  ...") {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default().fg(Color::Yellow)
            };
            let value_style = if label.starts_with("  #") || label.starts_with("  ...") {
                // Individual connection rows: color by active status (● green, ○ gray)
                if value.starts_with('●') {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::DarkGray)
                }
            } else if label == "Signature" {
                if value.starts_with('✓') {
                    Style::default().fg(Color::Green)
                } else if value.starts_with('⚠') || value.starts_with('✗') {
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                } else if value.starts_with('○') {
                    Style::default().fg(Color::Cyan) // System process
                } else {
                    Style::default().fg(Color::DarkGray)
                }
            } else if label == "Status" {
                match value.as_str() {
                    "ALLOW" => Style::default().fg(Color::Green),
                    "DENY" => Style::default().fg(Color::Red),
                    "ASK" => Style::default().fg(Color::Yellow),
                    "AUTO" => Style::default().fg(Color::Cyan),
                    "SA" => Style::default().fg(Color::Magenta),
                    _ => Style::default(),
                }
            } else if label == "Active" {
                if value == "Yes" {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::DarkGray)
                }
            } else {
                Style::default().fg(Color::White)
            };

            lines.push(Line::from(vec![
                Span::styled(format!("{:>14}: ", label), label_style),
                Span::styled(truncate_for_display(&value, (popup_width - 18) as usize), value_style),
            ]));
        }
    }

    // Add footer hint
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Press any key to close",
        Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC),
    )));

    let popup = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Connection Info ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .style(Style::default().bg(Color::Black)),
        );

    frame.render_widget(popup, popup_area);
}

/// Draw the help overlay showing all keyboard shortcuts
fn draw_help_overlay(frame: &mut Frame, _app: &App) {
    let area = frame.area();

    // Help content organized by category
    let help_sections = vec![
        ("Global Keys", vec![
            ("?", "Toggle this help"),
            ("q", "Quit"),
            ("1-4", "Switch tabs"),
            ("Tab", "Next tab"),
        ]),
        ("Connections Tab", vec![
            ("/", "Search/filter connections"),
            ("f", "Cycle through filters"),
            ("F", "Toggle current filter only"),
            ("g", "Toggle grouped view"),
            ("s", "Cycle sort mode"),
            ("i", "Show connection info"),
            ("t", "Toggle allow/deny rule"),
            ("c", "Clear connection list"),
        ]),
        ("Navigation", vec![
            ("j/↓", "Move down"),
            ("k/↑", "Move up"),
            ("Home", "Go to first item"),
            ("End", "Go to last item"),
            ("PgUp/Dn", "Page up/down"),
        ]),
        ("Rules Tab", vec![
            ("Space", "Select rule"),
            ("d", "Delete rule"),
            ("D", "Delete selected rules"),
            ("t", "Toggle enabled"),
            ("Ctrl+A", "Select all"),
            ("Esc", "Clear selection"),
        ]),
        ("Search Mode", vec![
            ("Esc", "Cancel/clear search"),
            ("Enter", "Confirm search"),
            ("Backspace", "Delete character"),
        ]),
    ];

    // Calculate popup dimensions
    let popup_width = 60.min(area.width.saturating_sub(4));
    let popup_height = 30.min(area.height.saturating_sub(4));

    let popup_x = (area.width.saturating_sub(popup_width)) / 2;
    let popup_y = (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    // Clear the area behind the popup
    frame.render_widget(Clear, popup_area);

    // Build content
    let mut lines: Vec<Line> = Vec::new();

    for (section_title, keys) in help_sections {
        // Section header
        lines.push(Line::from(Span::styled(
            format!("  {} ", section_title),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )));

        // Key-value pairs
        for (key, desc) in keys {
            lines.push(Line::from(vec![
                Span::styled(format!("    {:12} ", key), Style::default().fg(Color::Yellow)),
                Span::styled(desc, Style::default().fg(Color::White)),
            ]));
        }

        // Add spacing between sections
        lines.push(Line::from(""));
    }

    // Footer
    lines.push(Line::from(Span::styled(
        "  Press any key to close",
        Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC),
    )));

    let popup = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Keyboard Shortcuts ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green))
                .style(Style::default().bg(Color::Black)),
        );

    frame.render_widget(popup, popup_area);
}
