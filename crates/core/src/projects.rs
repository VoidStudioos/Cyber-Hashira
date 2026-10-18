use crate::db::{Database, DbError};
use chrono::Utc;
use cyber_hashira_scope_guard::{ScopeGuard, ScopeRule, ScopeRuleType};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub target_value: String,
    pub target_type: String, // "domain", "ip", "cidr", "url"
    pub authorized: bool,
    pub authorized_by: Option<String>,
    pub created_at: String,
}

pub struct ProjectManager {
    db: Database,
}

impl ProjectManager {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub fn create_project(&self, name: &str, description: Option<&str>) -> Result<Project, DbError> {
        let conn = self.db.get_connection();
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        conn.execute(
            "INSERT INTO projects (id, name, description, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, name, description, now, now],
        )?;

        drop(conn);
        self.db.log_audit(
            "operator",
            "project:create",
            Some(name),
            None,
            "SUCCESS",
            Some(&format!("Created project '{}' ({})", name, id)),
        )?;

        Ok(Project {
            id,
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub fn list_projects(&self) -> Result<Vec<Project>, DbError> {
        let conn = self.db.get_connection();
        let mut stmt = conn.prepare("SELECT id, name, description, created_at, updated_at FROM projects ORDER BY created_at DESC")?;
        let rows = stmt.query_map([], |row| {
            Ok(Project {
                id: row.get(0)?,
                name: row.get(1)?,
                description: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    pub fn add_target(
        &self,
        project_id: &str,
        name: &str,
        target_value: &str,
        target_type: &str,
        authorized: bool,
        authorized_by: Option<&str>,
    ) -> Result<Target, DbError> {
        let conn = self.db.get_connection();
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        conn.execute(
            "INSERT INTO targets (id, project_id, name, target_value, target_type, authorized, authorized_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id,
                project_id,
                name,
                target_value,
                target_type,
                if authorized { 1 } else { 0 },
                authorized_by,
                now
            ],
        )?;

        // Automatically create a corresponding scope rule if authorized
        if authorized {
            let rule_type = match target_type.to_lowercase().as_str() {
                "cidr" => ScopeRuleType::CidrBlock,
                "ip" => ScopeRuleType::IpAddress,
                "url" => ScopeRuleType::UrlPrefix,
                _ => {
                    if target_value.starts_with("*.") {
                        ScopeRuleType::WildcardSubdomain
                    } else {
                        ScopeRuleType::ExactDomain
                    }
                }
            };

            let rule_type_str = format!("{:?}", rule_type);
            conn.execute(
                "INSERT INTO scope_rules (id, project_id, rule_type, pattern, is_allowed, created_at)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5)",
                params![Uuid::new_v4().to_string(), project_id, rule_type_str, target_value, now],
            )?;
        }

        drop(conn);
        self.db.log_audit(
            authorized_by.unwrap_or("operator"),
            "target:add",
            Some(target_value),
            None,
            "SUCCESS",
            Some(&format!(
                "Added target '{}' (authorized={}) to project {}",
                target_value, authorized, project_id
            )),
        )?;

        Ok(Target {
            id,
            project_id: project_id.to_string(),
            name: name.to_string(),
            target_value: target_value.to_string(),
            target_type: target_type.to_string(),
            authorized,
            authorized_by: authorized_by.map(|s| s.to_string()),
            created_at: now,
        })
    }

    pub fn list_targets(&self, project_id: &str) -> Result<Vec<Target>, DbError> {
        let conn = self.db.get_connection();
        let mut stmt = conn.prepare(
            "SELECT id, project_id, name, target_value, target_type, authorized, authorized_by, created_at
             FROM targets WHERE project_id = ?1 ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(params![project_id], |row| {
            let auth_int: i32 = row.get(5)?;
            Ok(Target {
                id: row.get(0)?,
                project_id: row.get(1)?,
                name: row.get(2)?,
                target_value: row.get(3)?,
                target_type: row.get(4)?,
                authorized: auth_int == 1,
                authorized_by: row.get(6)?,
                created_at: row.get(7)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    pub fn get_scope_guard(&self, project_id: &str) -> Result<ScopeGuard, DbError> {
        let conn = self.db.get_connection();
        let mut stmt = conn.prepare(
            "SELECT id, rule_type, pattern, is_allowed FROM scope_rules WHERE project_id = ?1",
        )?;

        let rows = stmt.query_map(params![project_id], |row| {
            let id: String = row.get(0)?;
            let rule_type_str: String = row.get(1)?;
            let pattern: String = row.get(2)?;
            let is_allowed_int: i32 = row.get(3)?;

            let rule_type = match rule_type_str.as_str() {
                "WildcardSubdomain" => ScopeRuleType::WildcardSubdomain,
                "IpAddress" => ScopeRuleType::IpAddress,
                "CidrBlock" => ScopeRuleType::CidrBlock,
                "UrlPrefix" => ScopeRuleType::UrlPrefix,
                _ => ScopeRuleType::ExactDomain,
            };

            Ok(ScopeRule {
                id,
                rule_type,
                pattern,
                description: None,
                is_allowed: is_allowed_int == 1,
            })
        })?;

        let mut rules = Vec::new();
        for r in rows {
            rules.push(r?);
        }

        Ok(ScopeGuard::new(rules))
    }
}
