use crate::db::{Database, DbError};
use chrono::{DateTime, Utc};
use cyber_hashira_plugin_sdk::AuditLogEntry;
use rusqlite::params;

pub struct AuditManager {
    db: Database,
}

impl AuditManager {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub fn list_logs(&self, limit: usize) -> Result<Vec<AuditLogEntry>, DbError> {
        let conn = self.db.get_connection();
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, actor, action, target, module_id, status, details
             FROM audit_logs ORDER BY timestamp DESC LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            let id: String = row.get(0)?;
            let ts_str: String = row.get(1)?;
            let actor: String = row.get(2)?;
            let action: String = row.get(3)?;
            let target: Option<String> = row.get(4)?;
            let module_id: Option<String> = row.get(5)?;
            let status: String = row.get(6)?;
            let details_str: Option<String> = row.get(7)?;

            let timestamp = DateTime::parse_from_rfc3339(&ts_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            let details = details_str
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());

            Ok(AuditLogEntry {
                id,
                timestamp,
                actor,
                action,
                target,
                module_id,
                status,
                details,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }
}
