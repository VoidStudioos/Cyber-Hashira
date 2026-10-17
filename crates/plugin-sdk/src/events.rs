use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub module_id: Option<String>,
    pub status: String,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub title: String,
    pub message: String,
    pub level: String, // "info", "warning", "error", "success"
    pub read: bool,
}
