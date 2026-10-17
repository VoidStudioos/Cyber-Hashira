use cyber_hashira_core::db::{Database, DbError};
use cyber_hashira_plugin_sdk::ModuleManifest;
use flate2::read::GzDecoder;
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use tar::Archive;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum InstallError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Database error: {0}")]
    Db(#[from] DbError),
    #[error("Integrity check failed: expected sha256 {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },
    #[error("Invalid manifest: {0}")]
    InvalidManifest(String),
    #[error("Unsupported platform: OS '{0}' is not supported by this module")]
    UnsupportedPlatform(String),
    #[error("Security violation: path traversal detected '{0}'")]
    PathTraversal(String),
    #[error("Module '{0}' is already installed")]
    AlreadyInstalled(String),
    #[error("Module '{0}' is not installed")]
    NotInstalled(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InstalledModuleInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub status: String, // "installed", "enabled", "disabled"
    pub install_path: String,
    pub installed_at: String,
    pub enabled_at: Option<String>,
    pub permissions: Vec<String>,
}

pub struct ModuleInstaller {
    modules_root: PathBuf,
    db: Database,
}

impl ModuleInstaller {
    pub fn new<P: Into<PathBuf>>(modules_root: P, db: Database) -> Self {
        let root = modules_root.into();
        std::fs::create_dir_all(&root).ok();
        Self {
            modules_root: root,
            db,
        }
    }

    /// Verifies SHA-256 checksum of an archive file
    pub fn verify_checksum<P: AsRef<Path>>(archive_path: P, expected_sha256: &str) -> Result<(), InstallError> {
        let mut file = File::open(archive_path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }
        let actual = hex::encode(hasher.finalize());
        if !actual.eq_ignore_ascii_case(expected_sha256) {
            return Err(InstallError::ChecksumMismatch {
                expected: expected_sha256.to_string(),
                actual,
            });
        }
        Ok(())
    }

    /// Securely unpacks a .tar.gz archive preventing path traversal
    fn unpack_tar_gz<P: AsRef<Path>>(archive_path: P, destination: &Path) -> Result<(), InstallError> {
        let tar_gz = File::open(archive_path)?;
        let tar = GzDecoder::new(tar_gz);
        let mut archive = Archive::new(tar);

        std::fs::create_dir_all(destination)?;
        let canonical_dest = destination.canonicalize()?;

        for entry_res in archive.entries()? {
            let mut entry = entry_res?;
            let path = entry.path()?;

            // Check for path traversal: disallow any component that is ParentDir or absolute
            for comp in path.components() {
                if comp == std::path::Component::ParentDir {
                    return Err(InstallError::PathTraversal(path.display().to_string()));
                }
            }

            let target_path = destination.join(&path);
            if let Some(parent) = target_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            entry.unpack(&target_path)?;

            // Extra safety verification: canonical path must start with destination
            if target_path.exists() {
                let canonical_target = target_path.canonicalize()?;
                if !canonical_target.starts_with(&canonical_dest) {
                    return Err(InstallError::PathTraversal(path.display().to_string()));
                }
            }
        }

        Ok(())
    }

    /// Installs a module from a local archive with full verification and transactional rollback
    pub fn install_from_archive<P: AsRef<Path>>(
        &self,
        archive_path: P,
        expected_manifest: &ModuleManifest,
    ) -> Result<InstalledModuleInfo, InstallError> {
        let current_os = std::env::consts::OS;
        if !expected_manifest.is_os_supported(current_os) {
            return Err(InstallError::UnsupportedPlatform(current_os.to_string()));
        }

        // Verify checksum if provided in artifact metadata
        if let Some(artifact) = &expected_manifest.artifact {
            if !artifact.sha256.is_empty() {
                Self::verify_checksum(archive_path.as_ref(), &artifact.sha256)?;
            }
        }

        let module_dir = self.modules_root.join(&expected_manifest.id).join(&expected_manifest.version);
        if module_dir.exists() {
            // Clean up existing dir for reinstall/update
            std::fs::remove_dir_all(&module_dir).ok();
        }

        // Unpack archive into staging directory
        if let Err(e) = Self::unpack_tar_gz(archive_path.as_ref(), &module_dir) {
            // Rollback: clean up
            std::fs::remove_dir_all(&module_dir).ok();
            return Err(e);
        }

        // Validate unpacked manifest.json
        let manifest_file = module_dir.join("manifest.json");
        if !manifest_file.exists() {
            std::fs::remove_dir_all(&module_dir).ok();
            return Err(InstallError::InvalidManifest("manifest.json missing inside module package".to_string()));
        }

        let manifest_content = std::fs::read_to_string(&manifest_file)?;
        let unpacked_manifest: ModuleManifest = serde_json::from_str(&manifest_content)
            .map_err(|e| {
                std::fs::remove_dir_all(&module_dir).ok();
                InstallError::InvalidManifest(format!("Failed to parse manifest.json: {}", e))
            })?;

        if unpacked_manifest.id != expected_manifest.id {
            std::fs::remove_dir_all(&module_dir).ok();
            return Err(InstallError::InvalidManifest("Module ID in archive does not match expected ID".to_string()));
        }

        // Check entrypoint executable exists
        let executable_path = module_dir.join(&unpacked_manifest.entry_point.executable);
        if !executable_path.exists() {
            std::fs::remove_dir_all(&module_dir).ok();
            return Err(InstallError::InvalidManifest(format!(
                "Executable '{}' specified in entry_point does not exist in package",
                unpacked_manifest.entry_point.executable
            )));
        }

        // Register in database
        let now = chrono::Utc::now().to_rfc3339();
        let permissions_json = serde_json::to_string(&unpacked_manifest.required_permissions).unwrap_or_default();
        let conn = self.db.get_connection();

        conn.execute(
            "INSERT OR REPLACE INTO installed_modules (id, name, version, status, install_path, installed_at, permissions)
             VALUES (?1, ?2, ?3, 'enabled', ?4, ?5, ?6)",
            params![
                unpacked_manifest.id,
                unpacked_manifest.name,
                unpacked_manifest.version,
                module_dir.to_string_lossy().to_string(),
                now,
                permissions_json
            ],
        )?;

        drop(conn);
        self.db.log_audit(
            "operator",
            "module:install",
            None,
            Some(&unpacked_manifest.id),
            "SUCCESS",
            Some(&format!(
                "Successfully installed module '{}' version {}",
                unpacked_manifest.name, unpacked_manifest.version
            )),
        )?;

        Ok(InstalledModuleInfo {
            id: unpacked_manifest.id,
            name: unpacked_manifest.name,
            version: unpacked_manifest.version,
            status: "enabled".to_string(),
            install_path: module_dir.to_string_lossy().to_string(),
            installed_at: now.clone(),
            enabled_at: Some(now),
            permissions: unpacked_manifest.required_permissions,
        })
    }

    pub fn set_module_status(&self, module_id: &str, status: &str) -> Result<(), InstallError> {
        let conn = self.db.get_connection();
        let now = chrono::Utc::now().to_rfc3339();

        let updated = if status == "enabled" {
            conn.execute(
                "UPDATE installed_modules SET status = ?1, enabled_at = ?2 WHERE id = ?3",
                params![status, now, module_id],
            )?
        } else {
            conn.execute(
                "UPDATE installed_modules SET status = ?1 WHERE id = ?2",
                params![status, module_id],
            )?
        };

        if updated == 0 {
            return Err(InstallError::NotInstalled(module_id.to_string()));
        }

        drop(conn);
        self.db.log_audit(
            "operator",
            &format!("module:{}", status),
            None,
            Some(module_id),
            "SUCCESS",
            Some(&format!("Set status of module '{}' to {}", module_id, status)),
        )?;

        Ok(())
    }

    pub fn uninstall_module(&self, module_id: &str) -> Result<(), InstallError> {
        let conn = self.db.get_connection();
        let mut stmt = conn.prepare("SELECT install_path FROM installed_modules WHERE id = ?1")?;
        let install_path: Option<String> = stmt.query_row(params![module_id], |row| row.get(0)).ok();

        if let Some(path) = install_path {
            let p = PathBuf::from(path);
            if p.exists() {
                std::fs::remove_dir_all(&p).ok();
            }
        }

        conn.execute("DELETE FROM installed_modules WHERE id = ?1", params![module_id])?;

        drop(conn);
        self.db.log_audit(
            "operator",
            "module:uninstall",
            None,
            Some(module_id),
            "SUCCESS",
            Some(&format!("Uninstalled module '{}'", module_id)),
        )?;

        Ok(())
    }

    pub fn list_installed(&self) -> Result<Vec<InstalledModuleInfo>, InstallError> {
        let conn = self.db.get_connection();
        let mut stmt = conn.prepare(
            "SELECT id, name, version, status, install_path, installed_at, enabled_at, permissions
             FROM installed_modules ORDER BY installed_at DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            let id: String = row.get(0)?;
            let name: String = row.get(1)?;
            let version: String = row.get(2)?;
            let status: String = row.get(3)?;
            let install_path: String = row.get(4)?;
            let installed_at: String = row.get(5)?;
            let enabled_at: Option<String> = row.get(6)?;
            let permissions_json: Option<String> = row.get(7)?;

            let permissions = permissions_json
                .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
                .unwrap_or_default();

            Ok(InstalledModuleInfo {
                id,
                name,
                version,
                status,
                install_path,
                installed_at,
                enabled_at,
                permissions,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }
}
