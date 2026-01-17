mod driver;
mod signature;
mod tui;

use anyhow::Result;
use clap::{Parser, Subcommand};
use sereno_core::{
    database::Database,
    rule_engine::RuleEngine,
    types::{Action, Condition, DomainPattern, IpMatcher, PortMatcher, Protocol, Rule},
};
use std::path::PathBuf;
use tabled::{Table, Tabled};

fn default_db_path() -> PathBuf {
    std::env::var_os("SERENO_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("sereno")
                .join("sereno.db")
        })
}

#[derive(Parser)]
#[command(name = "sereno")]
#[command(about = "Sereno Network Firewall - Interactive TUI & CLI", version)]
struct Cli {
    /// Database file path
    #[arg(short, long, default_value_os_t = default_db_path())]
    database: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Launch interactive TUI (default when no command given)
    #[command(name = "tui")]
    Tui,
    /// Manage firewall rules
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
    /// View connection history
    Connections {
        /// Number of connections to show
        #[arg(short, long, default_value = "20")]
        limit: usize,
    },
    /// Manage profiles
    Profiles {
        #[command(subcommand)]
        action: ProfilesAction,
    },
    /// Show service status
    Status,
    /// Simulate a connection (for testing)
    Simulate {
        /// Process path
        #[arg(long)]
        process: String,
        /// Remote IP address
        #[arg(long)]
        ip: String,
        /// Remote port (optional for ICMP)
        #[arg(long, default_value = "0")]
        port: u16,
        /// Protocol (tcp/udp/icmp)
        #[arg(long, default_value = "tcp")]
        protocol: String,
        /// Domain name (optional)
        #[arg(long)]
        domain: Option<String>,
    },
    /// Initialize with factory rules
    Init,
}

#[derive(Subcommand)]
enum RulesAction {
    /// List all rules
    List,
    /// Add a new rule
    Add {
        /// Rule name
        #[arg(short, long)]
        name: String,
        /// Action (allow/deny/ask)
        #[arg(short, long)]
        action: String,
        /// Process path pattern (optional)
        #[arg(long)]
        process: Option<String>,
        /// Remote port (optional)
        #[arg(long)]
        port: Option<u16>,
        /// Domain pattern (optional)
        #[arg(long)]
        domain: Option<String>,
        /// Remote IP/CIDR (optional)
        #[arg(long)]
        ip: Option<String>,
        /// Rule priority
        #[arg(long, default_value = "0")]
        priority: i32,
    },
    /// Remove a rule
    Remove {
        /// Rule ID
        id: String,
    },
    /// Enable a rule
    Enable {
        /// Rule ID
        id: String,
    },
    /// Disable a rule
    Disable {
        /// Rule ID
        id: String,
    },
    /// Export rules to JSON
    Export {
        /// Output file
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Import rules from JSON
    Import {
        /// Input file
        #[arg(short, long)]
        input: PathBuf,
    },
}

#[derive(Subcommand)]
enum ProfilesAction {
    /// List all profiles
    List,
    /// Switch to a profile
    Switch {
        /// Profile ID or name
        profile: String,
    },
}

#[derive(Tabled)]
struct RuleRow {
    #[tabled(rename = "ID")]
    id: String,
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Action")]
    action: String,
    #[tabled(rename = "Enabled")]
    enabled: String,
    #[tabled(rename = "Priority")]
    priority: i32,
    #[tabled(rename = "Hits")]
    hits: u64,
}

#[derive(Tabled)]
struct ConnectionRow {
    #[tabled(rename = "Process")]
    process: String,
    #[tabled(rename = "Remote")]
    remote: String,
    #[tabled(rename = "Domain")]
    domain: String,
    #[tabled(rename = "Action")]
    action: String,
    #[tabled(rename = "Time")]
    time: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Default to TUI if no command given
    let command = cli.command.unwrap_or(Commands::Tui);

    // Only initialize tracing for non-TUI commands (TUI uses its own display)
    let is_tui = matches!(command, Commands::Tui);
    if !is_tui {
        tracing_subscriber::fmt::init();
    }

    let db = Database::open(&cli.database)?;

    match command {
        Commands::Tui => {
            // Launch interactive TUI
            drop(db); // Close db before TUI takes over
            tui::run(&cli.database)?;
        }
        Commands::Rules { action } => handle_rules(db, action)?,
        Commands::Connections { limit } => handle_connections(db, limit)?,
        Commands::Profiles { action } => handle_profiles(db, action)?,
        Commands::Status => handle_status(db)?,
        Commands::Simulate {
            process,
            ip,
            port,
            protocol,
            domain,
        } => handle_simulate(db, process, ip, port, protocol, domain)?,
        Commands::Init => handle_init(db)?,
    }

    Ok(())
}

fn handle_rules(db: Database, action: RulesAction) -> Result<()> {
    let engine = RuleEngine::new(db.clone())?;

    match action {
        RulesAction::List => {
            let rules = engine.rules();
            if rules.is_empty() {
                println!("No rules defined. Run 'sereno init' to add factory rules.");
                return Ok(());
            }

            let rows: Vec<RuleRow> = rules
                .into_iter()
                .map(|r| RuleRow {
                    id: r.id[..8].to_string(),
                    name: r.name,
                    action: format!("{}", r.action),
                    enabled: if r.enabled { "Yes" } else { "No" }.to_string(),
                    priority: r.priority,
                    hits: r.hit_count,
                })
                .collect();

            let table = Table::new(rows).to_string();
            println!("{}", table);
        }

        RulesAction::Add {
            name,
            action,
            process,
            port,
            domain,
            ip,
            priority,
        } => {
            let action = match action.to_lowercase().as_str() {
                "allow" => Action::Allow,
                "deny" => Action::Deny,
                _ => Action::Ask,
            };

            let mut conditions = Vec::new();

            if let Some(proc) = process {
                conditions.push(Condition::ProcessPath { pattern: proc });
            }

            if let Some(p) = port {
                conditions.push(Condition::RemotePort {
                    matcher: PortMatcher::Single { port: p },
                });
            }

            if let Some(d) = domain {
                conditions.push(Condition::Domain {
                    patterns: vec![DomainPattern::Wildcard { pattern: d }],
                });
            }

            if let Some(addr) = ip {
                conditions.push(Condition::RemoteAddress {
                    matcher: if addr.contains('/') {
                        IpMatcher::Cidr { network: addr }
                    } else {
                        IpMatcher::Single { address: addr }
                    },
                });
            }

            let mut rule = Rule::new(name, action, conditions);
            rule.priority = priority;

            engine.add_rule(rule.clone())?;
            println!("Created rule: {} ({})", rule.name, &rule.id[..8]);
        }

        RulesAction::Remove { id } => {
            let rules = engine.rules();
            let rule = rules
                .iter()
                .find(|r| r.id.starts_with(&id))
                .ok_or_else(|| anyhow::anyhow!("Rule not found: {}", id))?;

            engine.remove_rule(&rule.id)?;
            println!("Removed rule: {}", rule.name);
        }

        RulesAction::Enable { id } => {
            let rules = engine.rules();
            let rule = rules
                .iter()
                .find(|r| r.id.starts_with(&id))
                .ok_or_else(|| anyhow::anyhow!("Rule not found: {}", id))?;

            engine.set_rule_enabled(&rule.id, true)?;
            println!("Enabled rule: {}", rule.name);
        }

        RulesAction::Disable { id } => {
            let rules = engine.rules();
            let rule = rules
                .iter()
                .find(|r| r.id.starts_with(&id))
                .ok_or_else(|| anyhow::anyhow!("Rule not found: {}", id))?;

            engine.set_rule_enabled(&rule.id, false)?;
            println!("Disabled rule: {}", rule.name);
        }

        RulesAction::Export { output } => {
            let rules = engine.rules();
            let json = serde_json::to_string_pretty(&rules)?;
            std::fs::write(&output, json)?;
            println!("Exported {} rules to {:?}", rules.len(), output);
        }

        RulesAction::Import { input } => {
            let json = std::fs::read_to_string(&input)?;
            let rules: Vec<Rule> = serde_json::from_str(&json)?;

            for rule in &rules {
                engine.add_rule(rule.clone())?;
            }
            println!("Imported {} rules from {:?}", rules.len(), input);
        }
    }

    Ok(())
}

fn handle_connections(db: Database, limit: usize) -> Result<()> {
    let connections = db.get_recent_connections(limit)?;

    if connections.is_empty() {
        println!("No connection history.");
        return Ok(());
    }

    let rows: Vec<ConnectionRow> = connections
        .into_iter()
        .map(|c| ConnectionRow {
            process: c.process_name,
            remote: format!("{}:{}", c.remote_address, c.remote_port),
            domain: c.domain.unwrap_or_else(|| "-".to_string()),
            action: if c.allowed { "Allow" } else { "Deny" }.to_string(),
            time: c.started_at.format("%H:%M:%S").to_string(),
        })
        .collect();

    let table = Table::new(rows).to_string();
    println!("{}", table);

    Ok(())
}

fn handle_profiles(db: Database, action: ProfilesAction) -> Result<()> {
    match action {
        ProfilesAction::List => {
            let profiles = db.get_profiles()?;
            if profiles.is_empty() {
                println!("No profiles defined.");
                return Ok(());
            }

            for p in profiles {
                let active = if p.is_active { " (active)" } else { "" };
                println!("{}: {}{}", &p.id[..8], p.name, active);
            }
        }

        ProfilesAction::Switch { profile } => {
            let profiles = db.get_profiles()?;
            let target = profiles
                .iter()
                .find(|p| p.id.starts_with(&profile) || p.name.to_lowercase() == profile.to_lowercase())
                .ok_or_else(|| anyhow::anyhow!("Profile not found: {}", profile))?;

            db.set_active_profile(&target.id)?;
            println!("Switched to profile: {}", target.name);
        }
    }

    Ok(())
}

fn handle_status(db: Database) -> Result<()> {
    let rules = db.get_rules()?;
    let enabled_rules = rules.iter().filter(|r| r.enabled).count();
    let profiles = db.get_profiles()?;
    let active_profile = profiles.iter().find(|p| p.is_active);

    println!("Sereno Firewall Status");
    println!("======================");
    println!("Rules:      {} total, {} enabled", rules.len(), enabled_rules);
    println!(
        "Profile:    {}",
        active_profile
            .map(|p| p.name.as_str())
            .unwrap_or("(none)")
    );
    println!("Service:    Not running (MVP mode)");

    Ok(())
}

fn handle_simulate(
    db: Database,
    process: String,
    ip: String,
    port: u16,
    protocol: String,
    domain: Option<String>,
) -> Result<()> {
    use sereno_core::types::{ConnectionContext, Direction, EvalResult};

    let engine = RuleEngine::new(db)?;

    let protocol = match protocol.to_lowercase().as_str() {
        "udp" => Protocol::Udp,
        "icmp" => Protocol::Icmp,
        _ => Protocol::Tcp,
    };

    let ctx = ConnectionContext {
        process_path: process.clone(),
        process_name: std::path::Path::new(&process)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string(),
        process_id: 0,
        remote_address: ip.parse()?,
        remote_port: port,
        local_port: 0,
        protocol,
        direction: Direction::Outbound,
        domain,
    };

    println!("Simulating connection:");
    println!("  Process: {}", ctx.process_path);
    println!("  Remote:  {}:{}", ctx.remote_address, ctx.remote_port);
    println!("  Domain:  {}", ctx.domain.as_deref().unwrap_or("-"));
    println!();

    let result = engine.evaluate(&ctx);

    match result {
        EvalResult::Allow { rule_id } => {
            if rule_id.is_empty() {
                println!("Result: ALLOW (default)");
            } else {
                println!("Result: ALLOW (rule: {})", &rule_id[..8]);
            }
        }
        EvalResult::Deny { rule_id } => {
            if rule_id.is_empty() {
                println!("Result: DENY (default)");
            } else {
                println!("Result: DENY (rule: {})", &rule_id[..8]);
            }
        }
        EvalResult::Ask => {
            println!("Result: ASK (no matching rule)");
        }
    }

    Ok(())
}

fn handle_init(db: Database) -> Result<()> {
    let engine = RuleEngine::new(db)?;

    let factory_rules = vec![
        // Allow Claude Code / Anthropic API (high priority for development)
        {
            let mut rule = Rule::new(
                "Allow Claude Code",
                Action::Allow,
                vec![Condition::Domain {
                    patterns: vec![
                        DomainPattern::Exact {
                            value: "api.anthropic.com".to_string(),
                        },
                        DomainPattern::Wildcard {
                            pattern: "*.anthropic.com".to_string(),
                        },
                    ],
                }],
            );
            rule.priority = 200; // Higher than telemetry block
            rule
        },
        // Allow DNS
        Rule::new(
            "Allow DNS",
            Action::Allow,
            vec![
                Condition::RemotePort {
                    matcher: PortMatcher::Single { port: 53 },
                },
                Condition::Protocol { protocol: Protocol::Udp },
            ],
        ),
        // Allow local network
        Rule::new(
            "Allow Local Network",
            Action::Allow,
            vec![Condition::RemoteAddress {
                matcher: IpMatcher::List {
                    addresses: vec![
                        "192.168.0.0/16".to_string(),
                        "10.0.0.0/8".to_string(),
                        "172.16.0.0/12".to_string(),
                        "127.0.0.0/8".to_string(),
                    ],
                },
            }],
        ),
        // Allow Windows Update
        Rule::new(
            "Allow Windows Update",
            Action::Allow,
            vec![
                Condition::ProcessPath {
                    pattern: "C:\\Windows\\System32\\svchost.exe".to_string(),
                },
                Condition::Domain {
                    patterns: vec![
                        DomainPattern::Wildcard {
                            pattern: "*.windowsupdate.com".to_string(),
                        },
                        DomainPattern::Wildcard {
                            pattern: "*.microsoft.com".to_string(),
                        },
                    ],
                },
            ],
        ),
        // Block telemetry
        {
            let mut rule = Rule::new(
                "Block Telemetry",
                Action::Deny,
                vec![Condition::Domain {
                    patterns: vec![
                        DomainPattern::Wildcard {
                            pattern: "*.data.microsoft.com".to_string(),
                        },
                        DomainPattern::Wildcard {
                            pattern: "telemetry.*".to_string(),
                        },
                        DomainPattern::Wildcard {
                            pattern: "*.telemetry.*".to_string(),
                        },
                    ],
                }],
            );
            rule.priority = 100; // High priority
            rule
        },
        // Allow ICMP (ping, network diagnostics)
        Rule::new(
            "Allow ICMP",
            Action::Allow,
            vec![Condition::Protocol {
                protocol: Protocol::Icmp,
            }],
        ),
    ];

    for rule in factory_rules {
        engine.add_rule(rule)?;
    }

    println!("Initialized with factory rules:");
    println!("  - Allow Claude Code (api.anthropic.com) [priority 200]");
    println!("  - Allow DNS (UDP port 53)");
    println!("  - Allow Local Network (RFC1918)");
    println!("  - Allow Windows Update");
    println!("  - Block Telemetry [priority 100]");
    println!("  - Allow ICMP (ping/diagnostics)");

    Ok(())
}
