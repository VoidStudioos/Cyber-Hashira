use crate::db::{Database, DbError};
use chrono::{DateTime, Utc};
use cyber_hashira_plugin_sdk::{Finding, FindingStatus, Severity};
use rusqlite::params;
use std::str::FromStr;

pub struct FindingManager {
    db: Database,
}

impl FindingManager {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub fn insert_finding(&self, finding: &Finding) -> Result<(), DbError> {
        let conn = self.db.get_connection();
        let status_str = format!("{:?}", finding.status);
        let sev_str = format!("{:?}", finding.severity);
        let time_str = finding.timestamp.to_rfc3339();

        conn.execute(
            "INSERT OR REPLACE INTO findings (
                id, project_id, target_id, module_id, title, description,
                severity, cvss_v3, cve, cwe, evidence, status, remediation, analyst_notes, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                finding.id,
                finding.project_id,
                finding.target_id,
                finding.module_id,
                finding.title,
                finding.description,
                sev_str,
                finding.cvss_v3,
                finding.cve,
                finding.cwe,
                finding.evidence,
                status_str,
                finding.remediation,
                finding.analyst_notes,
                time_str
            ],
        )?;

        drop(conn);
        self.db.log_audit(
            &finding.module_id,
            "finding:record",
            finding.target_id.as_deref(),
            Some(&finding.module_id),
            "SUCCESS",
            Some(&format!("Recorded finding '{}' ({})", finding.title, finding.severity)),
        )?;

        Ok(())
    }

    pub fn list_findings(&self, project_id: Option<&str>) -> Result<Vec<Finding>, DbError> {
        let conn = self.db.get_connection();
        let query = match project_id {
            Some(_) => "SELECT id, project_id, target_id, module_id, title, description, severity, cvss_v3, cve, cwe, evidence, status, remediation, analyst_notes, created_at FROM findings WHERE project_id = ?1 ORDER BY created_at DESC",
            None => "SELECT id, project_id, target_id, module_id, title, description, severity, cvss_v3, cve, cwe, evidence, status, remediation, analyst_notes, created_at FROM findings ORDER BY created_at DESC",
        };

        let mut stmt = conn.prepare(query)?;
        let map_row = |row: &rusqlite::Row| {
            let id: String = row.get(0)?;
            let proj_id: Option<String> = row.get(1)?;
            let targ_id: Option<String> = row.get(2)?;
            let module_id: String = row.get(3)?;
            let title: String = row.get(4)?;
            let description: String = row.get(5)?;
            let sev_str: String = row.get(6)?;
            let cvss_v3: Option<f32> = row.get(7)?;
            let cve: Option<String> = row.get(8)?;
            let cwe: Option<String> = row.get(9)?;
            let evidence: Option<String> = row.get(10)?;
            let status_str: String = row.get(11)?;
            let remediation: Option<String> = row.get(12)?;
            let analyst_notes: Option<String> = row.get(13)?;
            let created_at_str: String = row.get(14)?;

            let severity = match sev_str.as_str() {
                "Critical" => Severity::Critical,
                "High" => Severity::High,
                "Medium" => Severity::Medium,
                "Low" => Severity::Low,
                _ => Severity::Informational,
            };

            let status = match status_str.as_str() {
                "Confirmed" => FindingStatus::Confirmed,
                "FalsePositive" => FindingStatus::FalsePositive,
                "Remediated" => FindingStatus::Remediated,
                "Accepted" => FindingStatus::Accepted,
                _ => FindingStatus::Open,
            };

            let timestamp = DateTime::parse_from_rfc3339(&created_at_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            Ok(Finding {
                id,
                project_id: proj_id,
                target_id: targ_id,
                module_id,
                title,
                description,
                severity,
                cvss_v3,
                cve,
                cwe,
                evidence,
                status,
                remediation,
                analyst_notes,
                timestamp,
            })
        };

        let rows = if let Some(pid) = project_id {
            stmt.query_map(params![pid], map_row)?
        } else {
            stmt.query_map([], map_row)?
        };

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }
}
