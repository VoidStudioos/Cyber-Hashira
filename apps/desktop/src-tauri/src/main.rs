// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use cyber_hashira_core::db::Database;
use cyber_hashira_core::projects::{Project, ProjectManager, Target};
use cyber_hashira_core::findings::FindingManager;
use cyber_hashira_core::audit::AuditManager;
use cyber_hashira_module_runtime::installer::{InstalledModuleInfo, ModuleInstaller};
use cyber_hashira_module_runtime::registry::{RegistryCatalog, RegistryClient};
use cyber_hashira_module_runtime::executor::ModuleExecutor;
use cyber_hashira_plugin_sdk::{AuditLogEntry, Finding, ModuleManifest, ModuleResponse};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::State;

struct AppState {
    db: Database,
    project_mgr: ProjectManager,
    finding_mgr: FindingManager,
    audit_mgr: AuditManager,
    installer: ModuleInstaller,
    app_data_dir: PathBuf,
}

#[derive(Serialize)]
struct HostInfo {
    name: String,
    version: String,
    os: String,
    arch: String,
    database: String,
}

#[tauri::command]
fn get_host_info() -> HostInfo {
    HostInfo {
        name: "Cyber Hashira Host".to_string(),
        version: "0.1.0".to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        database: "SQLite (Local Isolated)".to_string(),
    }
}

#[tauri::command]
fn list_projects(state: State<'_, Arc<Mutex<AppState>>>) -> Result<Vec<Project>, String> {
    let app = state.lock().map_err(|e| e.to_string())?;
    app.project_mgr.list_projects().map_err(|e| e.to_string())
}

#[tauri::command]
fn create_project(
    name: String,
    description: Option<String>,
    state: State<'_, Arc<Mutex<AppState>>>,
) -> Result<Project, String> {
    let app = state.lock().map_err(|e| e.to_string())?;
    app.project_mgr
        .create_project(&name, description.as_deref())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn list_targets(
    project_id: String,
    state: State<'_, Arc<Mutex<AppState>>>,
) -> Result<Vec<Target>, String> {
    let app = state.lock().map_err(|e| e.to_string())?;
    app.project_mgr.list_targets(&project_id).map_err(|e| e.to_string())
}

#[tauri::command]
fn add_target(
    project_id: String,
    name: String,
    target_value: String,
    target_type: String,
    authorized: bool,
    authorized_by: Option<String>,
    state: State<'_, Arc<Mutex<AppState>>>,
) -> Result<Target, String> {
    let app = state.lock().map_err(|e| e.to_string())?;
    app.project_mgr
        .add_target(
            &project_id,
            &name,
            &target_value,
            &target_type,
            authorized,
            authorized_by.as_deref(),
        )
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn validate_target_scope(
    project_id: String,
    target: String,
    state: State<'_, Arc<Mutex<AppState>>>,
) -> Result<bool, String> {
    let app = state.lock().map_err(|e| e.to_string())?;
    let guard = app.project_mgr.get_scope_guard(&project_id).map_err(|e| e.to_string())?;
    guard.validate_target(&target).map(|_| true).map_err(|e| e.to_string())
}

#[tauri::command]
fn fetch_registry_modules(
    state: State<'_, Arc<Mutex<AppState>>>,
) -> Result<Vec<ModuleManifest>, String> {
    let app = state.lock().map_err(|e| e.to_string())?;
    let registry_file = app.app_data_dir.join("registry").join("v1").join("modules.json");
    if registry_file.exists() {
        let catalog = RegistryClient::load_from_file(&registry_file).map_err(|e| e.to_string())?;
        Ok(catalog.modules)
    } else {
        // Fallback: search workspace registry directory
        let fallback = PathBuf::from("registry/v1/modules.json");
        if fallback.exists() {
            let catalog = RegistryClient::load_from_file(&fallback).map_err(|e| e.to_string())?;
            Ok(catalog.modules)
        } else {
            Ok(vec![])
        }
    }
}

#[tauri::command]
fn list_installed_modules(
    state: State<'_, Arc<Mutex<AppState>>>,
) -> Result<Vec<InstalledModuleInfo>, String> {
    let app = state.lock().map_err(|e| e.to_string())?;
    app.installer.list_installed().map_err(|e| e.to_string())
}

#[tauri::command]
async fn install_module(
    module_id: String,
    state: State<'_, Arc<Mutex<AppState>>>,
) -> Result<InstalledModuleInfo, String> {
    let (app_data_dir, installer, registry_catalog) = {
        let app = state.lock().map_err(|e| e.to_string())?;
        let reg_file = app.app_data_dir.join("registry").join("v1").join("modules.json");
        let path = if reg_file.exists() {
            reg_file
        } else {
            PathBuf::from("registry/v1/modules.json")
        };
        let catalog = RegistryClient::load_from_file(path).map_err(|e| e.to_string())?;
        (app.app_data_dir.clone(), app.installer.clone(), catalog)
    };

    let manifest = RegistryClient::find_module(&registry_catalog, &module_id)
        .ok_or_else(|| format!("Module '{}' not found in registry", module_id))?
        .clone();

    // Check package location: look in local artifacts or download
    let archive_path = app_data_dir
        .join("registry")
        .join("artifacts")
        .join(format!("{}-{}.tar.gz", manifest.id, manifest.version));

    let archive = if archive_path.exists() {
        archive_path
    } else {
        let workspace_artifact = PathBuf::from("registry/artifacts")
            .join(format!("{}-{}.tar.gz", manifest.id, manifest.version));
        if workspace_artifact.exists() {
            workspace_artifact
        } else {
            return Err(format!("Module package archive not found for '{}'", module_id));
        }
    };

    let installed_info = installer
        .install_from_archive(&archive, &manifest)
        .map_err(|e| e.to_string())?;

    // Perform health check
    let module_dir = PathBuf::from(&installed_info.install_path);
    let health = ModuleExecutor::run_health_check(&module_dir, &manifest, Duration::from_secs(10))
        .await
        .map_err(|e| format!("Module installed, but health check failed: {}", e))?;

    match health {
        ModuleResponse::HealthCheckResult { healthy, message, .. } => {
            if !healthy {
                return Err(format!("Module health check failed: {}", message));
            }
        }
        _ => {}
    }

    Ok(installed_info)
}

#[tauri::command]
fn enable_module(
    module_id: String,
    state: State<'_, Arc<Mutex<AppState>>>,
) -> Result<(), String> {
    let app = state.lock().map_err(|e| e.to_string())?;
    app.installer
        .set_module_status(&module_id, "enabled")
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn disable_module(
    module_id: String,
    state: State<'_, Arc<Mutex<AppState>>>,
) -> Result<(), String> {
    let app = state.lock().map_err(|e| e.to_string())?;
    app.installer
        .set_module_status(&module_id, "disabled")
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn uninstall_module(
    module_id: String,
    state: State<'_, Arc<Mutex<AppState>>>,
) -> Result<(), String> {
    let app = state.lock().map_err(|e| e.to_string())?;
    app.installer
        .uninstall_module(&module_id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn run_module_task(
    module_id: String,
    project_id: String,
    target: String,
    options: serde_json::Value,
    state: State<'_, Arc<Mutex<AppState>>>,
) -> Result<ModuleResponse, String> {
    // 1. Mandatory Scope Check
    let (module_path, guard) = {
        let app = state.lock().map_err(|e| e.to_string())?;
        let guard = app.project_mgr.get_scope_guard(&project_id).map_err(|e| e.to_string())?;
        guard.validate_target(&target).map_err(|e| format!("SCOPE REJECTION: {}", e))?;

        let installed = app.installer.list_installed().map_err(|e| e.to_string())?;
        let module_info = installed
            .into_iter()
            .find(|m| m.id == module_id)
            .ok_or_else(|| format!("Module '{}' is not installed", module_id))?;

        if module_info.status != "enabled" {
            return Err(format!("Module '{}' is currently disabled", module_id));
        }

        (PathBuf::from(module_info.install_path), guard)
    };

    let manifest_path = module_path.join("manifest.json");
    let manifest_content = std::fs::read_to_string(&manifest_path).map_err(|e| e.to_string())?;
    let manifest: ModuleManifest = serde_json::from_str(&manifest_content).map_err(|e| e.to_string())?;

    let task_id = uuid::Uuid::new_v4().to_string();

    // 2. Safe execution via ModuleExecutor
    let resp = ModuleExecutor::run_task(
        &module_path,
        &manifest,
        task_id,
        target,
        true, // Scope verified
        options,
        Duration::from_secs(60),
    )
    .await
    .map_err(|e| e.to_string())?;

    // 3. Store findings in database if task completed
    if let ModuleResponse::TaskCompleted { ref findings, .. } = resp {
        let app = state.lock().map_err(|e| e.to_string())?;
        for f in findings {
            let mut f_clone = f.clone();
            f_clone.project_id = Some(project_id.clone());
            app.finding_mgr.insert_finding(&f_clone).map_err(|e| e.to_string())?;
        }
    }

    Ok(resp)
}

#[tauri::command]
fn list_findings(
    project_id: Option<String>,
    state: State<'_, Arc<Mutex<AppState>>>,
) -> Result<Vec<Finding>, String> {
    let app = state.lock().map_err(|e| e.to_string())?;
    app.finding_mgr
        .list_findings(project_id.as_deref())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn list_audit_logs(
    limit: Option<usize>,
    state: State<'_, Arc<Mutex<AppState>>>,
) -> Result<Vec<AuditLogEntry>, String> {
    let app = state.lock().map_err(|e| e.to_string())?;
    app.audit_mgr
        .list_logs(limit.unwrap_or(100))
        .map_err(|e| e.to_string())
}

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let app_data_dir = dirs_fallback();
    std::fs::create_dir_all(&app_data_dir).ok();

    let db_path = app_data_dir.join("cyber_hashira.db");
    let db = Database::open_file(&db_path).expect("Failed to initialize SQLite database");

    let project_mgr = ProjectManager::new(db.clone());
    let finding_mgr = FindingManager::new(db.clone());
    let audit_mgr = AuditManager::new(db.clone());
    let installer = ModuleInstaller::new(app_data_dir.join("installed_modules"), db.clone());

    // Create a default project if none exists
    if let Ok(projects) = project_mgr.list_projects() {
        if projects.is_empty() {
            let _ = project_mgr.create_project(
                "Default Assessment",
                Some("Default project for authorized security auditing"),
            );
        }
    }

    let state = Arc::new(Mutex::new(AppState {
        db,
        project_mgr,
        finding_mgr,
        audit_mgr,
        installer,
        app_data_dir,
    }));

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            get_host_info,
            list_projects,
            create_project,
            list_targets,
            add_target,
            validate_target_scope,
            fetch_registry_modules,
            list_installed_modules,
            install_module,
            enable_module,
            disable_module,
            uninstall_module,
            run_module_task,
            list_findings,
            list_audit_logs,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Cyber Hashira application");
}

fn dirs_fallback() -> PathBuf {
    if let Some(mut dir) = std::env::var_os("APPDATA").map(PathBuf::from) {
        dir.push("CyberHashira");
        dir
    } else if let Some(mut dir) = std::env::var_os("HOME").map(PathBuf::from) {
        dir.push(".cyberhashira");
        dir
    } else {
        PathBuf::from(".cyberhashira")
    }
}
