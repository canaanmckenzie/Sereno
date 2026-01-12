//! TUI UI Rendering

use crate::tui::app::{App, DriverStatus, Tab};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
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

    let title = Line::from(vec![
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
    ]);

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

        Row::new(vec![
            Cell::from(conn.time.clone()),
            Cell::from(conn.action.clone()).style(final_action_style),
            Cell::from(format!("{}[{}]", conn.process_name, conn.process_id)),
            Cell::from(conn.destination.clone()),
            Cell::from(format!("{}:{}", conn.port, conn.protocol)),
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

/// Draw the Rules tab
fn draw_rules_tab(frame: &mut Frame, app: &App, area: Rect) {
    let header_cells = ["Name", "Action", "Enabled", "Priority", "Hits"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));

    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = app.rules.iter().enumerate().map(|(i, rule)| {
        let selected = i == app.selected_rule;

        // Base styles
        let row_style = if selected {
            Style::default().bg(Color::Blue).fg(Color::White)
        } else {
            Style::default()
        };

        let action_style = if selected {
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
        } else {
            match format!("{}", rule.action).as_str() {
                "Allow" => Style::default().fg(Color::Green),
                "Deny" => Style::default().fg(Color::Red),
                _ => Style::default().fg(Color::Yellow),
            }
        };

        let enabled_style = if selected {
            Style::default().fg(Color::White)
        } else if rule.enabled {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        Row::new(vec![
            Cell::from(rule.name.clone()),
            Cell::from(format!("{}", rule.action)).style(action_style),
            Cell::from(if rule.enabled { "Yes" } else { "No" }).style(enabled_style),
            Cell::from(format!("{}", rule.priority)),
            Cell::from(format!("{}", rule.hit_count)),
        ])
        .style(row_style)
        .height(1)
    }).collect();

    let table = Table::new(
        rows,
        [
            Constraint::Min(20),    // Name
            Constraint::Length(8),  // Action
            Constraint::Length(8),  // Enabled
            Constraint::Length(10), // Priority
            Constraint::Length(8),  // Hits
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(format!(" Rules ({}) [sel:{}] ", app.rules.len(), app.selected_rule))
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
        // Show keyboard shortcuts
        Line::from(vec![
            Span::raw(" "),
            Span::styled("↑↓", Style::default().fg(Color::Cyan)),
            Span::raw(" Navigate  "),
            Span::styled("Tab", Style::default().fg(Color::Cyan)),
            Span::raw(" Switch tabs  "),
            Span::styled("Enter", Style::default().fg(Color::Cyan)),
            Span::raw(" Select  "),
            Span::styled("Q", Style::default().fg(Color::Cyan)),
            Span::raw(" Quit"),
        ])
    };

    let footer = Paragraph::new(content).block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(footer, area);
}
