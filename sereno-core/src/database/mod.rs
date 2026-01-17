mod schema;

use crate::error::{Result, SerenoError};
use crate::types::{Action, Connection, Profile, Rule, SilentMode, Validity};
use parking_lot::Mutex;
use rusqlite::{params, Connection as SqliteConnection};
use std::path::Path;
use std::sync::Arc;

pub use schema::SCHEMA;

/// Database handle for Sereno
#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<SqliteConnection>>,
}

impl Database {
    /// Open or create a database at the given path
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = SqliteConnection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Create an in-memory database (for testing)
    pub fn in_memory() -> Result<Self> {
        let conn = SqliteConnection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    // ========== Rule Operations ==========

    /// Insert a new rule
    pub fn insert_rule(&self, rule: &Rule) -> Result<()> {
        let conn = self.conn.lock();
        let conditions_json = serde_json::to_string(&rule.conditions)?;
        let validity_json = serde_json::to_string(&rule.validity)?;

        conn.execute(
            "INSERT INTO rules (id, name, enabled, priority, action, conditions, validity, hit_count, created_at, profile_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                rule.id,
                rule.name,
                rule.enabled,
                rule.priority,
                rule.action.to_string(),
                conditions_json,
                validity_json,
                rule.hit_count,
                rule.created_at.to_rfc3339(),
                rule.profile_id,
            ],
        )?;
        Ok(())
    }

    /// Get all rules, ordered by priority
    pub fn get_rules(&self) -> Result<Vec<Rule>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, name, enabled, priority, action, conditions, validity, hit_count, created_at, profile_id
             FROM rules ORDER BY priority DESC, created_at ASC"
        )?;

        let rules = stmt.query_map([], |row| {
            let action_str: String = row.get(4)?;
            let conditions_json: String = row.get(5)?;
            let validity_json: String = row.get(6)?;
            let created_at_str: String = row.get(8)?;

            Ok(Rule {
                id: row.get(0)?,
                name: row.get(1)?,
                enabled: row.get(2)?,
                priority: row.get(3)?,
                action: match action_str.as_str() {
                    "allow" => Action::Allow,
                    "deny" => Action::Deny,
                    _ => Action::Ask,
                },
                conditions: serde_json::from_str(&conditions_json).unwrap_or_default(),
                validity: serde_json::from_str(&validity_json).unwrap_or(Validity::Permanent),
                hit_count: row.get(7)?,
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now()),
                profile_id: row.get(9)?,
            })
        })?;

        rules.collect::<std::result::Result<Vec<_>, _>>().map_err(SerenoError::from)
    }

    /// Get a single rule by ID
    pub fn get_rule(&self, id: &str) -> Result<Option<Rule>> {
        let rules = self.get_rules()?;
        Ok(rules.into_iter().find(|r| r.id == id))
    }

    /// Update a rule
    pub fn update_rule(&self, rule: &Rule) -> Result<()> {
        let conn = self.conn.lock();
        let conditions_json = serde_json::to_string(&rule.conditions)?;
        let validity_json = serde_json::to_string(&rule.validity)?;

        let rows = conn.execute(
            "UPDATE rules SET name = ?2, enabled = ?3, priority = ?4, action = ?5,
             conditions = ?6, validity = ?7, hit_count = ?8, profile_id = ?9
             WHERE id = ?1",
            params![
                rule.id,
                rule.name,
                rule.enabled,
                rule.priority,
                rule.action.to_string(),
                conditions_json,
                validity_json,
                rule.hit_count,
                rule.profile_id,
            ],
        )?;

        if rows == 0 {
            return Err(SerenoError::RuleNotFound(rule.id.clone()));
        }
        Ok(())
    }

    /// Delete a rule
    pub fn delete_rule(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock();
        let rows = conn.execute("DELETE FROM rules WHERE id = ?1", params![id])?;
        if rows == 0 {
            return Err(SerenoError::RuleNotFound(id.to_string()));
        }
        Ok(())
    }

    /// Increment hit count for a rule
    pub fn increment_hit_count(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE rules SET hit_count = hit_count + 1 WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    /// Delete expired Timed rules (where expires_at < now)
    /// Returns the number of rules deleted
    pub fn delete_expired_rules(&self) -> Result<usize> {
        let conn = self.conn.lock();
        // SQLite doesn't natively compare ISO timestamps, but string comparison works for ISO 8601
        let now = chrono::Utc::now().to_rfc3339();
        let rows = conn.execute(
            "DELETE FROM rules WHERE validity LIKE '%\"type\":\"timed\"%'
             AND json_extract(validity, '$.expires_at') < ?1",
            params![now],
        )?;
        Ok(rows)
    }

    /// Get rules that will expire within the given duration
    pub fn get_expiring_rules(&self, within_seconds: i64) -> Result<Vec<Rule>> {
        let rules = self.get_rules()?;
        let cutoff = chrono::Utc::now() + chrono::Duration::seconds(within_seconds);

        Ok(rules.into_iter().filter(|r| {
            if let Validity::Timed { expires_at } = &r.validity {
                *expires_at <= cutoff
            } else {
                false
            }
        }).collect())
    }

    // ========== Profile Operations ==========

    /// Insert a new profile
    pub fn insert_profile(&self, profile: &Profile) -> Result<()> {
        let conn = self.conn.lock();
        let silent_mode = profile.silent_mode.map(|s| match s {
            SilentMode::AllowAll => "allow_all",
            SilentMode::DenyAll => "deny_all",
        });

        conn.execute(
            "INSERT INTO profiles (id, name, is_active, silent_mode, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                profile.id,
                profile.name,
                profile.is_active,
                silent_mode,
                profile.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Get all profiles
    pub fn get_profiles(&self) -> Result<Vec<Profile>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, name, is_active, silent_mode, created_at FROM profiles ORDER BY name"
        )?;

        let profiles = stmt.query_map([], |row| {
            let silent_mode_str: Option<String> = row.get(3)?;
            let created_at_str: String = row.get(4)?;

            Ok(Profile {
                id: row.get(0)?,
                name: row.get(1)?,
                is_active: row.get(2)?,
                silent_mode: silent_mode_str.and_then(|s| match s.as_str() {
                    "allow_all" => Some(SilentMode::AllowAll),
                    "deny_all" => Some(SilentMode::DenyAll),
                    _ => None,
                }),
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now()),
            })
        })?;

        profiles.collect::<std::result::Result<Vec<_>, _>>().map_err(SerenoError::from)
    }

    /// Get active profile
    pub fn get_active_profile(&self) -> Result<Option<Profile>> {
        let profiles = self.get_profiles()?;
        Ok(profiles.into_iter().find(|p| p.is_active))
    }

    /// Set active profile
    pub fn set_active_profile(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute("UPDATE profiles SET is_active = 0", [])?;
        let rows = conn.execute(
            "UPDATE profiles SET is_active = 1 WHERE id = ?1",
            params![id],
        )?;
        if rows == 0 {
            return Err(SerenoError::ProfileNotFound(id.to_string()));
        }
        Ok(())
    }

    // ========== Connection Log Operations ==========

    /// Log a connection
    pub fn log_connection(&self, conn_data: &Connection) -> Result<()> {
        let db_conn = self.conn.lock();
        db_conn.execute(
            "INSERT INTO connections (id, process_path, process_name, process_id, remote_address,
             remote_port, local_port, protocol, direction, domain, country, bytes_sent,
             bytes_received, allowed, rule_id, started_at, ended_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                conn_data.id,
                conn_data.process_path,
                conn_data.process_name,
                conn_data.process_id,
                conn_data.remote_address.to_string(),
                conn_data.remote_port,
                conn_data.local_port,
                conn_data.protocol.to_string(),
                format!("{:?}", conn_data.direction).to_lowercase(),
                conn_data.domain,
                conn_data.country,
                conn_data.bytes_sent,
                conn_data.bytes_received,
                conn_data.allowed,
                conn_data.rule_id,
                conn_data.started_at.to_rfc3339(),
                conn_data.ended_at.map(|dt| dt.to_rfc3339()),
            ],
        )?;
        Ok(())
    }

    /// Get recent connections
    pub fn get_recent_connections(&self, limit: usize) -> Result<Vec<Connection>> {
        let db_conn = self.conn.lock();
        let mut stmt = db_conn.prepare(
            "SELECT id, process_path, process_name, process_id, remote_address, remote_port,
             local_port, protocol, direction, domain, country, bytes_sent, bytes_received,
             allowed, rule_id, started_at, ended_at
             FROM connections ORDER BY started_at DESC LIMIT ?1"
        )?;

        let connections = stmt.query_map([limit as i64], |row| {
            let remote_addr_str: String = row.get(4)?;
            let protocol_str: String = row.get(7)?;
            let direction_str: String = row.get(8)?;
            let started_at_str: String = row.get(15)?;
            let ended_at_str: Option<String> = row.get(16)?;

            Ok(Connection {
                id: row.get(0)?,
                process_path: row.get(1)?,
                process_name: row.get(2)?,
                process_id: row.get(3)?,
                remote_address: remote_addr_str.parse().unwrap_or_else(|_| "0.0.0.0".parse().unwrap()),
                remote_port: row.get(5)?,
                local_port: row.get(6)?,
                protocol: match protocol_str.as_str() {
                    "tcp" => crate::types::Protocol::Tcp,
                    "udp" => crate::types::Protocol::Udp,
                    "icmp" => crate::types::Protocol::Icmp,
                    _ => crate::types::Protocol::Any,
                },
                direction: match direction_str.as_str() {
                    "inbound" => crate::types::Direction::Inbound,
                    "outbound" => crate::types::Direction::Outbound,
                    _ => crate::types::Direction::Any,
                },
                domain: row.get(9)?,
                country: row.get(10)?,
                bytes_sent: row.get(11)?,
                bytes_received: row.get(12)?,
                allowed: row.get(13)?,
                rule_id: row.get(14)?,
                started_at: chrono::DateTime::parse_from_rfc3339(&started_at_str)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now()),
                ended_at: ended_at_str.and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                        .ok()
                }),
            })
        })?;

        connections.collect::<std::result::Result<Vec<_>, _>>().map_err(SerenoError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Action, Condition, PortMatcher};

    #[test]
    fn test_insert_and_get_rule() {
        let db = Database::in_memory().unwrap();

        let rule = Rule::new(
            "Block telemetry",
            Action::Deny,
            vec![Condition::RemotePort {
                matcher: PortMatcher::Single { port: 443 }
            }],
        );

        db.insert_rule(&rule).unwrap();

        let rules = db.get_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "Block telemetry");
        assert_eq!(rules[0].action, Action::Deny);
    }

    #[test]
    fn test_update_rule() {
        let db = Database::in_memory().unwrap();

        let mut rule = Rule::new("Test", Action::Allow, vec![]);
        db.insert_rule(&rule).unwrap();

        rule.name = "Updated".to_string();
        rule.action = Action::Deny;
        db.update_rule(&rule).unwrap();

        let updated = db.get_rule(&rule.id).unwrap().unwrap();
        assert_eq!(updated.name, "Updated");
        assert_eq!(updated.action, Action::Deny);
    }

    #[test]
    fn test_delete_rule() {
        let db = Database::in_memory().unwrap();

        let rule = Rule::new("To delete", Action::Allow, vec![]);
        db.insert_rule(&rule).unwrap();

        db.delete_rule(&rule.id).unwrap();

        let rules = db.get_rules().unwrap();
        assert!(rules.is_empty());
    }
}
