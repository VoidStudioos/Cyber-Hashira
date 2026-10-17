use serde::{Deserialize, Serialize};
use crate::findings::Finding;

/// Standard Request envelope sent from Host to Module process
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum HostRequest {
    Init {
        host_version: String,
        config: serde_json::Value,
    },
    HealthCheck,
    RunTask {
        task_id: String,
        target: String,
        scope_approved: bool,
        options: serde_json::Value,
    },
    CancelTask {
        task_id: String,
    },
}

/// Standard Response envelope sent from Module process to Host
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum ModuleResponse {
    HealthCheckResult {
        healthy: bool,
        message: String,
        details: Option<serde_json::Value>,
    },
    TaskProgress {
        task_id: String,
        percent: f32,
        message: String,
    },
    TaskCompleted {
        task_id: String,
        success: bool,
        findings: Vec<Finding>,
        raw_output: Option<String>,
        error: Option<String>,
    },
    Error {
        message: String,
        code: Option<String>,
    },
}
