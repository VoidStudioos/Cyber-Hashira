use cyber_hashira_plugin_sdk::{HostRequest, ModuleManifest, ModuleResponse};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

#[derive(Error, Debug)]
pub enum ExecutionError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Process timeout after {0:?}")]
    Timeout(Duration),
    #[error("Invalid JSON communication: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Module process exited with non-zero status: {0:?}")]
    ProcessFailed(Option<i32>),
    #[error("Executable not found: {0}")]
    NotFound(String),
}

pub struct ModuleExecutor;

impl ModuleExecutor {
    /// Dispatches a health check request to the module and waits for the response
    pub async fn run_health_check(
        module_dir: &Path,
        manifest: &ModuleManifest,
        timeout_dur: Duration,
    ) -> Result<ModuleResponse, ExecutionError> {
        let req = HostRequest::HealthCheck;
        Self::execute_single_request(module_dir, manifest, req, timeout_dur).await
    }

    /// Dispatches a task request to the module
    pub async fn run_task(
        module_dir: &Path,
        manifest: &ModuleManifest,
        task_id: String,
        target: String,
        scope_approved: bool,
        options: serde_json::Value,
        timeout_dur: Duration,
    ) -> Result<ModuleResponse, ExecutionError> {
        let req = HostRequest::RunTask {
            task_id,
            target,
            scope_approved,
            options,
        };
        Self::execute_single_request(module_dir, manifest, req, timeout_dur).await
    }

    async fn execute_single_request(
        module_dir: &Path,
        manifest: &ModuleManifest,
        request: HostRequest,
        timeout_dur: Duration,
    ) -> Result<ModuleResponse, ExecutionError> {
        let exec_rel = &manifest.entry_point.executable;
        let exec_path = module_dir.join(exec_rel);

        if !exec_path.exists() {
            return Err(ExecutionError::NotFound(exec_path.to_string_lossy().to_string()));
        }

        // Determine executable runner based on runtime or extension
        let mut cmd = match manifest.entry_point.runtime.as_str() {
            "python" => {
                let mut c = Command::new("python");
                c.arg(&exec_path);
                c
            }
            "node" => {
                let mut c = Command::new("node");
                c.arg(&exec_path);
                c
            }
            _ => {
                // If it's a python script by extension on windows/linux:
                if exec_rel.ends_with(".py") {
                    let mut c = Command::new("python");
                    c.arg(&exec_path);
                    c
                } else {
                    Command::new(&exec_path)
                }
            }
        };

        // Add default args from manifest
        for arg in &manifest.entry_point.default_args {
            cmd.arg(arg);
        }

        // Security: working directory set to module_dir, stdio piped
        cmd.current_dir(module_dir);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // Do not construct shell string - safe subprocess invocation
        let mut child = cmd.spawn()?;

        let mut stdin = child.stdin.take().expect("Child stdin is piped");
        let stdout = child.stdout.take().expect("Child stdout is piped");

        // Write request JSON to stdin
        let req_json = serde_json::to_string(&request)?;
        let write_future = async {
            stdin.write_all(req_json.as_bytes()).await?;
            stdin.write_all(b"\n").await?;
            stdin.flush().await?;
            Ok::<(), std::io::Error>(())
        };

        timeout(Duration::from_secs(5), write_future)
            .await
            .map_err(|_| ExecutionError::Timeout(Duration::from_secs(5)))??;

        // Read response line from stdout
        let mut reader = BufReader::new(stdout).lines();
        let read_future = async {
            while let Some(line) = reader.next_line().await? {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(resp) = serde_json::from_str::<ModuleResponse>(trimmed) {
                    return Ok(resp);
                }
            }
            Err(ExecutionError::ProcessFailed(None))
        };

        let response = timeout(timeout_dur, read_future)
            .await
            .map_err(|_| ExecutionError::Timeout(timeout_dur))??;

        // Wait for child to exit
        let status = child.wait().await?;
        if !status.success() {
            // Note: some commands might exit 0 or 1, but if we parsed a valid response, return it
        }

        Ok(response)
    }
}
