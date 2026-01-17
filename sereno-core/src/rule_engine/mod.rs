mod cache;
mod evaluator;

use crate::database::Database;
use crate::error::Result;
use crate::types::{Action, ConnectionContext, EvalResult, Rule, Validity};
use chrono::Utc;
use parking_lot::RwLock;
use std::sync::Arc;

pub use cache::DecisionCache;
pub use evaluator::ConditionEvaluator;

/// The main rule engine for evaluating connections
pub struct RuleEngine {
    database: Database,
    rules: Arc<RwLock<Vec<Rule>>>,
    cache: DecisionCache,
    default_action: Action,
    evaluator: ConditionEvaluator,
}

impl RuleEngine {
    /// Create a new rule engine
    pub fn new(database: Database) -> Result<Self> {
        let rules = database.get_rules()?;
        Ok(Self {
            database,
            rules: Arc::new(RwLock::new(rules)),
            cache: DecisionCache::new(10_000),
            default_action: Action::Ask,
            evaluator: ConditionEvaluator::new(),
        })
    }

    /// Reload rules from the database
    pub fn reload_rules(&self) -> Result<()> {
        let rules = self.database.get_rules()?;
        *self.rules.write() = rules;
        self.cache.clear();
        Ok(())
    }

    /// Evaluate a connection against all rules
    pub fn evaluate(&self, ctx: &ConnectionContext) -> EvalResult {
        // Check cache first
        let cache_key = self.make_cache_key(ctx);
        if let Some(result) = self.cache.get(&cache_key) {
            return result;
        }

        let rules = self.rules.read();
        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }

            if !self.is_rule_valid(&rule.validity, ctx) {
                continue;
            }

            if self.evaluator.evaluate_all(&rule.conditions, ctx) {
                let result = match rule.action {
                    Action::Allow => EvalResult::Allow {
                        rule_id: rule.id.clone(),
                    },
                    Action::Deny => EvalResult::Deny {
                        rule_id: rule.id.clone(),
                    },
                    Action::Ask => EvalResult::Ask,
                };

                // Cache non-Ask results
                if !matches!(result, EvalResult::Ask) {
                    self.cache.insert(cache_key, result.clone());
                }

                // Update hit count (non-blocking)
                let _ = self.database.increment_hit_count(&rule.id);

                // Handle Once rules - delete after single use
                if matches!(rule.validity, Validity::Once) {
                    let rule_id = rule.id.clone();
                    let _ = self.remove_rule(&rule_id);
                }

                return result;
            }
        }

        // No rule matched, return default action
        match self.default_action {
            Action::Allow => EvalResult::Allow {
                rule_id: String::new(),
            },
            Action::Deny => EvalResult::Deny {
                rule_id: String::new(),
            },
            Action::Ask => EvalResult::Ask,
        }
    }

    /// Check if a rule is still valid
    fn is_rule_valid(&self, validity: &Validity, ctx: &ConnectionContext) -> bool {
        match validity {
            Validity::Permanent => true,
            Validity::Once => true, // Will be deleted after use
            Validity::UntilQuit { process_id } => *process_id == ctx.process_id,
            Validity::Timed { expires_at } => Utc::now() < *expires_at,
        }
    }

    /// Create a cache key for a connection context
    fn make_cache_key(&self, ctx: &ConnectionContext) -> String {
        format!(
            "{}:{}:{}:{}:{:?}",
            ctx.process_path, ctx.remote_address, ctx.remote_port, ctx.local_port, ctx.protocol
        )
    }

    /// Set the default action for unmatched connections
    pub fn set_default_action(&mut self, action: Action) {
        self.default_action = action;
        self.cache.clear();
    }

    /// Get the current default action
    pub fn default_action(&self) -> Action {
        self.default_action
    }

    /// Get all rules
    pub fn rules(&self) -> Vec<Rule> {
        self.rules.read().clone()
    }

    /// Add a new rule
    pub fn add_rule(&self, rule: Rule) -> Result<()> {
        self.database.insert_rule(&rule)?;
        self.rules.write().push(rule);
        self.cache.clear();
        Ok(())
    }

    /// Remove a rule
    pub fn remove_rule(&self, id: &str) -> Result<()> {
        self.database.delete_rule(id)?;
        self.rules.write().retain(|r| r.id != id);
        self.cache.clear();
        Ok(())
    }

    /// Enable or disable a rule
    pub fn set_rule_enabled(&self, id: &str, enabled: bool) -> Result<()> {
        let mut rules = self.rules.write();
        if let Some(rule) = rules.iter_mut().find(|r| r.id == id) {
            rule.enabled = enabled;
            self.database.update_rule(rule)?;
            self.cache.clear();
        }
        Ok(())
    }

    /// Cleanup expired rules (call periodically)
    /// Returns the number of rules deleted
    pub fn cleanup_expired_rules(&self) -> Result<usize> {
        let deleted = self.database.delete_expired_rules()?;
        if deleted > 0 {
            self.reload_rules()?;
        }
        Ok(deleted)
    }

    /// Get rules that will expire soon (for UI display)
    pub fn get_expiring_rules(&self, within_seconds: i64) -> Result<Vec<Rule>> {
        self.database.get_expiring_rules(within_seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Condition, Direction, IpMatcher, PortMatcher, Protocol};
    use std::net::IpAddr;

    fn make_context() -> ConnectionContext {
        ConnectionContext {
            process_path: "C:\\Windows\\System32\\svchost.exe".to_string(),
            process_name: "svchost.exe".to_string(),
            process_id: 1234,
            remote_address: "93.184.216.34".parse::<IpAddr>().unwrap(),
            remote_port: 443,
            local_port: 54321,
            protocol: Protocol::Tcp,
            direction: Direction::Outbound,
            domain: Some("example.com".to_string()),
        }
    }

    #[test]
    fn test_rule_matching() {
        let db = Database::in_memory().unwrap();
        let engine = RuleEngine::new(db).unwrap();

        // Add a rule that matches our context
        let rule = Rule::new(
            "Allow HTTPS",
            Action::Allow,
            vec![
                Condition::RemotePort {
                    matcher: PortMatcher::Single { port: 443 }
                },
                Condition::Protocol { protocol: Protocol::Tcp },
            ],
        );
        engine.add_rule(rule.clone()).unwrap();

        let ctx = make_context();
        let result = engine.evaluate(&ctx);

        match result {
            EvalResult::Allow { rule_id } => assert_eq!(rule_id, rule.id),
            _ => panic!("Expected Allow result"),
        }
    }

    #[test]
    fn test_no_rule_matches() {
        let db = Database::in_memory().unwrap();
        let engine = RuleEngine::new(db).unwrap();

        // Add a rule that doesn't match
        let rule = Rule::new(
            "Block port 80",
            Action::Deny,
            vec![Condition::RemotePort {
                matcher: PortMatcher::Single { port: 80 }
            }],
        );
        engine.add_rule(rule).unwrap();

        let ctx = make_context(); // Uses port 443
        let result = engine.evaluate(&ctx);

        assert!(matches!(result, EvalResult::Ask));
    }

    #[test]
    fn test_rule_priority() {
        let db = Database::in_memory().unwrap();
        let engine = RuleEngine::new(db).unwrap();

        // Add deny rule with lower priority
        let mut deny_rule = Rule::new(
            "Deny all",
            Action::Deny,
            vec![Condition::RemotePort { matcher: PortMatcher::Any }],
        );
        deny_rule.priority = 0;
        engine.add_rule(deny_rule).unwrap();

        // Add allow rule with higher priority
        let mut allow_rule = Rule::new(
            "Allow port 443",
            Action::Allow,
            vec![Condition::RemotePort {
                matcher: PortMatcher::Single { port: 443 }
            }],
        );
        allow_rule.priority = 10;
        engine.add_rule(allow_rule.clone()).unwrap();

        // Need to reload to get proper priority sorting
        engine.reload_rules().unwrap();

        let ctx = make_context();
        let result = engine.evaluate(&ctx);

        match result {
            EvalResult::Allow { rule_id } => assert_eq!(rule_id, allow_rule.id),
            _ => panic!("Expected Allow result from higher priority rule"),
        }
    }
}
