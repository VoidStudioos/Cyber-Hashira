use cyber_hashira_plugin_sdk::ModuleManifest;
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RegistryError {
    #[error("Failed to read registry: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to parse registry JSON: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("Module '{0}' not found in registry")]
    NotFound(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryCatalog {
    pub schema_version: String,
    pub generated_at: String,
    pub modules: Vec<ModuleManifest>,
}

pub struct RegistryClient;

impl RegistryClient {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<RegistryCatalog, RegistryError> {
        let content = std::fs::read_to_string(path)?;
        let catalog: RegistryCatalog = serde_json::from_str(&content)?;
        Ok(catalog)
    }

    pub fn load_from_str(json_str: &str) -> Result<RegistryCatalog, RegistryError> {
        let catalog: RegistryCatalog = serde_json::from_str(json_str)?;
        Ok(catalog)
    }

    pub fn find_module<'a>(catalog: &'a RegistryCatalog, module_id: &str) -> Option<&'a ModuleManifest> {
        catalog.modules.iter().find(|m| m.id == module_id)
    }
}
