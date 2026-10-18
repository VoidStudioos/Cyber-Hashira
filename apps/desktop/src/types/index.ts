export type Severity = "Critical" | "High" | "Medium" | "Low" | "Informational";

export type FindingStatus = "Open" | "Confirmed" | "FalsePositive" | "Remediated" | "Accepted";

export interface Finding {
  id: string;
  project_id?: string;
  target_id?: string;
  module_id: string;
  title: string;
  description: string;
  severity: Severity;
  cvss_v3?: number;
  cve?: string;
  cwe?: string;
  evidence?: string;
  timestamp: string;
  status: FindingStatus;
  remediation?: string;
  analyst_notes?: string;
}

export interface Project {
  id: string;
  name: string;
  description?: string;
  created_at: string;
  updated_at: string;
}

export interface Target {
  id: string;
  project_id: string;
  name: string;
  target_value: string;
  target_type: string;
  authorized: boolean;
  authorized_by?: string;
  created_at: string;
}

export interface ModuleManifest {
  id: string;
  name: string;
  description: string;
  author: string;
  version: string;
  min_host_version: string;
  category: string;
  supported_os: string[];
  supported_arch: string[];
  required_permissions: string[];
  entry_point: {
    runtime: string;
    executable: string;
    default_args: string[];
  };
  artifact?: {
    download_url?: string;
    sha256: string;
    size_bytes?: number;
  };
  license: string;
  documentation_url?: string;
  icon?: string;
  banner_url?: string;
}

export interface InstalledModuleInfo {
  id: string;
  name: string;
  version: string;
  status: "installed" | "enabled" | "disabled";
  install_path: string;
  installed_at: string;
  enabled_at?: string;
  permissions: string[];
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  target?: string;
  module_id?: string;
  status: string;
  details?: Record<string, unknown>;
}

export interface HostInfo {
  name: string;
  version: string;
  os: string;
  arch: string;
  database: string;
}
