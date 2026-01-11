use crate::types::{
    Condition, ConnectionContext, Direction, DomainPattern, IpMatcher, PortMatcher, Protocol,
};
use ipnetwork::IpNetwork;
use regex::Regex;
use std::net::IpAddr;

/// Evaluates rule conditions against connection context
pub struct ConditionEvaluator {
    // Could cache compiled regexes here in the future
}

impl ConditionEvaluator {
    pub fn new() -> Self {
        Self {}
    }

    /// Evaluate all conditions (AND logic)
    pub fn evaluate_all(&self, conditions: &[Condition], ctx: &ConnectionContext) -> bool {
        if conditions.is_empty() {
            return true; // Empty conditions match everything
        }
        conditions.iter().all(|c| self.evaluate(c, ctx))
    }

    /// Evaluate a single condition
    pub fn evaluate(&self, condition: &Condition, ctx: &ConnectionContext) -> bool {
        match condition {
            Condition::ProcessPath { pattern } => self.match_path(&ctx.process_path, pattern),
            Condition::ProcessName { pattern } => self.match_pattern(&ctx.process_name, pattern),
            Condition::RemoteAddress { matcher } => self.match_ip(&ctx.remote_address, matcher),
            Condition::RemotePort { matcher } => self.match_port(ctx.remote_port, matcher),
            Condition::LocalPort { matcher } => self.match_port(ctx.local_port, matcher),
            Condition::Protocol { protocol } => self.match_protocol(&ctx.protocol, protocol),
            Condition::Domain { patterns } => {
                if let Some(domain) = &ctx.domain {
                    self.match_domain(domain, patterns)
                } else {
                    false
                }
            }
            Condition::Direction { direction } => self.match_direction(&ctx.direction, direction),
            Condition::And { conditions } => conditions.iter().all(|c| self.evaluate(c, ctx)),
            Condition::Or { conditions } => conditions.iter().any(|c| self.evaluate(c, ctx)),
            Condition::Not { condition } => !self.evaluate(condition, ctx),
        }
    }

    /// Match a file path against a pattern (case-insensitive on Windows)
    fn match_path(&self, path: &str, pattern: &str) -> bool {
        let path_lower = path.to_lowercase().replace('/', "\\");
        let pattern_lower = pattern.to_lowercase().replace('/', "\\");

        if pattern_lower.contains('*') {
            self.match_wildcard(&path_lower, &pattern_lower)
        } else {
            path_lower == pattern_lower
        }
    }

    /// Match a string against a pattern (supports * and ? wildcards)
    fn match_pattern(&self, value: &str, pattern: &str) -> bool {
        let value_lower = value.to_lowercase();
        let pattern_lower = pattern.to_lowercase();

        if pattern_lower.contains('*') || pattern_lower.contains('?') {
            self.match_wildcard(&value_lower, &pattern_lower)
        } else {
            value_lower == pattern_lower
        }
    }

    /// Simple wildcard matching - builds regex char by char to avoid escaping issues
    fn match_wildcard(&self, value: &str, pattern: &str) -> bool {
        let mut regex_str = String::from("(?i)^");

        for ch in pattern.chars() {
            match ch {
                '*' => regex_str.push_str(".*"),
                '?' => regex_str.push('.'),
                // Escape regex special chars
                '.' | '\\' | '(' | ')' | '[' | ']' | '{' | '}'
                | '+' | '^' | '$' | '|' | '-' => {
                    regex_str.push('\\');
                    regex_str.push(ch);
                }
                _ => regex_str.push(ch),
            }
        }

        regex_str.push('$');

        if let Ok(re) = Regex::new(&regex_str) {
            re.is_match(value)
        } else {
            false
        }
    }

    /// Match an IP address against a matcher
    fn match_ip(&self, addr: &IpAddr, matcher: &IpMatcher) -> bool {
        match matcher {
            IpMatcher::Any => true,
            IpMatcher::Single { address } => {
                if let Ok(match_addr) = address.parse::<IpAddr>() {
                    addr == &match_addr
                } else {
                    false
                }
            }
            IpMatcher::Cidr { network } => {
                if let Ok(net) = network.parse::<IpNetwork>() {
                    net.contains(*addr)
                } else {
                    false
                }
            }
            IpMatcher::List { addresses } => addresses.iter().any(|a| {
                if let Ok(match_addr) = a.parse::<IpAddr>() {
                    addr == &match_addr
                } else if let Ok(net) = a.parse::<IpNetwork>() {
                    net.contains(*addr)
                } else {
                    false
                }
            }),
        }
    }

    /// Match a port against a matcher
    fn match_port(&self, port: u16, matcher: &PortMatcher) -> bool {
        match matcher {
            PortMatcher::Any => true,
            PortMatcher::Single { port: p } => port == *p,
            PortMatcher::Range { start, end } => port >= *start && port <= *end,
            PortMatcher::List { ports } => ports.contains(&port),
        }
    }

    /// Match protocol
    fn match_protocol(&self, actual: &Protocol, expected: &Protocol) -> bool {
        matches!(expected, Protocol::Any) || actual == expected
    }

    /// Match direction
    fn match_direction(&self, actual: &Direction, expected: &Direction) -> bool {
        matches!(expected, Direction::Any) || actual == expected
    }

    /// Match domain against patterns
    fn match_domain(&self, domain: &str, patterns: &[DomainPattern]) -> bool {
        let domain_lower = domain.to_lowercase();

        patterns.iter().any(|p| match p {
            DomainPattern::Exact { value } => domain_lower == value.to_lowercase(),
            DomainPattern::Wildcard { pattern } => {
                let pattern_lower = pattern.to_lowercase();
                if pattern_lower.starts_with("*.") {
                    let suffix = &pattern_lower[1..]; // Keep the dot
                    domain_lower.ends_with(suffix) || domain_lower == pattern_lower[2..]
                } else {
                    domain_lower == pattern_lower
                }
            }
            DomainPattern::Regex { pattern } => {
                if let Ok(re) = Regex::new(pattern) {
                    re.is_match(&domain_lower)
                } else {
                    false
                }
            }
        })
    }
}

impl Default for ConditionEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_evaluator() -> ConditionEvaluator {
        ConditionEvaluator::new()
    }

    fn make_context() -> ConnectionContext {
        ConnectionContext {
            process_path: "C:\\Program Files\\App\\app.exe".to_string(),
            process_name: "app.exe".to_string(),
            process_id: 1234,
            remote_address: "93.184.216.34".parse().unwrap(),
            remote_port: 443,
            local_port: 54321,
            protocol: Protocol::Tcp,
            direction: Direction::Outbound,
            domain: Some("api.example.com".to_string()),
        }
    }

    #[test]
    fn test_exact_path_match() {
        let eval = make_evaluator();
        let ctx = make_context();

        let condition = Condition::ProcessPath {
            pattern: "C:\\Program Files\\App\\app.exe".to_string(),
        };
        assert!(eval.evaluate(&condition, &ctx));

        // Case insensitive
        let condition = Condition::ProcessPath {
            pattern: "c:\\program files\\app\\app.exe".to_string(),
        };
        assert!(eval.evaluate(&condition, &ctx));
    }

    #[test]
    fn test_wildcard_path_match() {
        let eval = make_evaluator();
        let ctx = make_context();

        let condition = Condition::ProcessPath {
            pattern: "C:\\Program Files\\*\\app.exe".to_string(),
        };
        assert!(eval.evaluate(&condition, &ctx));

        let condition = Condition::ProcessPath {
            pattern: "*.exe".to_string(),
        };
        assert!(eval.evaluate(&condition, &ctx));
    }

    #[test]
    fn test_port_matching() {
        let eval = make_evaluator();
        let ctx = make_context();

        // Single port
        let condition = Condition::RemotePort {
            matcher: PortMatcher::Single { port: 443 },
        };
        assert!(eval.evaluate(&condition, &ctx));

        // Port range
        let condition = Condition::RemotePort {
            matcher: PortMatcher::Range { start: 400, end: 500 },
        };
        assert!(eval.evaluate(&condition, &ctx));

        // Port list
        let condition = Condition::RemotePort {
            matcher: PortMatcher::List { ports: vec![80, 443, 8080] },
        };
        assert!(eval.evaluate(&condition, &ctx));

        // Any port
        let condition = Condition::RemotePort {
            matcher: PortMatcher::Any,
        };
        assert!(eval.evaluate(&condition, &ctx));
    }

    #[test]
    fn test_ip_matching() {
        let eval = make_evaluator();
        let ctx = make_context();

        // Exact IP
        let condition = Condition::RemoteAddress {
            matcher: IpMatcher::Single { address: "93.184.216.34".to_string() },
        };
        assert!(eval.evaluate(&condition, &ctx));

        // CIDR
        let condition = Condition::RemoteAddress {
            matcher: IpMatcher::Cidr { network: "93.184.216.0/24".to_string() },
        };
        assert!(eval.evaluate(&condition, &ctx));

        // List
        let condition = Condition::RemoteAddress {
            matcher: IpMatcher::List {
                addresses: vec!["10.0.0.1".to_string(), "93.184.216.0/24".to_string()],
            },
        };
        assert!(eval.evaluate(&condition, &ctx));
    }

    #[test]
    fn test_domain_matching() {
        let eval = make_evaluator();
        let ctx = make_context();

        // Exact domain
        let condition = Condition::Domain {
            patterns: vec![DomainPattern::Exact {
                value: "api.example.com".to_string(),
            }],
        };
        assert!(eval.evaluate(&condition, &ctx));

        // Wildcard subdomain
        let condition = Condition::Domain {
            patterns: vec![DomainPattern::Wildcard {
                pattern: "*.example.com".to_string(),
            }],
        };
        assert!(eval.evaluate(&condition, &ctx));

        // Regex
        let condition = Condition::Domain {
            patterns: vec![DomainPattern::Regex {
                pattern: r".*\.example\.com$".to_string(),
            }],
        };
        assert!(eval.evaluate(&condition, &ctx));
    }

    #[test]
    fn test_compound_conditions() {
        let eval = make_evaluator();
        let ctx = make_context();

        // AND
        let condition = Condition::And {
            conditions: vec![
                Condition::RemotePort { matcher: PortMatcher::Single { port: 443 } },
                Condition::Protocol { protocol: Protocol::Tcp },
            ],
        };
        assert!(eval.evaluate(&condition, &ctx));

        // OR
        let condition = Condition::Or {
            conditions: vec![
                Condition::RemotePort { matcher: PortMatcher::Single { port: 80 } },
                Condition::RemotePort { matcher: PortMatcher::Single { port: 443 } },
            ],
        };
        assert!(eval.evaluate(&condition, &ctx));

        // NOT
        let condition = Condition::Not {
            condition: Box::new(Condition::RemotePort {
                matcher: PortMatcher::Single { port: 80 },
            }),
        };
        assert!(eval.evaluate(&condition, &ctx));
    }
}
