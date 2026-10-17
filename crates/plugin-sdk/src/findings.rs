use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Informational => write!(f, "Informational"),
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingStatus {
    Open,
    Confirmed,
    FalsePositive,
    Remediated,
    Accepted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub project_id: Option<String>,
    pub target_id: Option<String>,
    pub module_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    #[serde(default)]
    pub cvss_v3: Option<f32>,
    #[serde(default)]
    pub cve: Option<String>,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub evidence: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub status: FindingStatus,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default)]
    pub analyst_notes: Option<String>,
}
