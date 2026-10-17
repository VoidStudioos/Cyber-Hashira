use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Official Cyber Hashira Plugin Manifest Standard (Section 6)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleManifest {
    pub id: String,
    pub name: String,
    pub description: String,
    pub author: String,
    pub version: String,
    pub min_host_version: String,
    
    #[serde(default)]
    pub supported_os: Vec<String>,
    
    #[serde(default)]
    pub supported_arch: Vec<String>,
    
    #[serde(default)]
    pub required_dependencies: HashMap<String, String>,
    
    #[serde(default)]
    pub optional_dependencies: HashMap<String, String>,
    
    #[serde(default)]
    pub required_permissions: Vec<String>,
    
    pub entry_point: ModuleEntryPoint,
    
    #[serde(default)]
    pub config_schema: Option<serde_json::Value>,
    
    #[serde(default)]
    pub contracts: Option<ModuleContracts>,
    
    #[serde(default)]
    pub artifact: Option<ArtifactMetadata>,
    
    pub license: String,
    
    #[serde(default)]
    pub documentation_url: Option<String>,
    
    #[serde(default)]
    pub changelog: Option<String>,

    #[serde(default)]
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleEntryPoint {
    pub runtime: String, // "binary", "python", "node", "script"
    pub executable: String, // relative path to binary or script inside module package
    #[serde(default)]
    pub default_args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleContracts {
    pub input_schema: Option<serde_json::Value>,
    pub output_schema: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactMetadata {
    pub download_url: Option<String>,
    pub sha256: String,
    pub signature: Option<String>,
    pub size_bytes: Option<u64>,
}

impl ModuleManifest {
    pub fn is_os_supported(&self, current_os: &str) -> bool {
        if self.supported_os.is_empty() || self.supported_os.iter().any(|os| os == "all" || os == "*") {
            return true;
        }
        self.supported_os.iter().any(|os| os.eq_ignore_ascii_case(current_os))
    }

    pub fn is_arch_supported(&self, current_arch: &str) -> bool {
        if self.supported_arch.is_empty() || self.supported_arch.iter().any(|arch| arch == "all" || arch == "*") {
            return true;
        }
        self.supported_arch.iter().any(|arch| arch.eq_ignore_ascii_case(current_arch))
    }

    pub fn validate_basics(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            return Err("Module ID cannot be empty".to_string());
        }
        if self.name.trim().is_empty() {
            return Err("Module name cannot be empty".to_string());
        }
        if self.version.trim().is_empty() {
            return Err("Module version cannot be empty".to_string());
        }
        if self.entry_point.executable.trim().is_empty() {
            return Err("Module executable cannot be empty".to_string());
        }
        // Disallow dangerous path traversal characters in entrypoint executable
        if self.entry_point.executable.contains("..") || self.entry_point.executable.starts_with('/') || self.entry_point.executable.starts_with('\\') {
            return Err("Module executable cannot contain path traversal sequences or absolute paths".to_string());
        }
        Ok(())
    }
}
