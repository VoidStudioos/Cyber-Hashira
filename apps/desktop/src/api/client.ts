import {
  AuditLogEntry,
  Finding,
  HostInfo,
  InstalledModuleInfo,
  ModuleManifest,
  Project,
  Target,
} from "../types";

// Check if running inside Tauri runtime
const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

// Dynamic Tauri invoke loader
async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (isTauri) {
    try {
      const { invoke: tauriInvoke } = await import("@tauri-apps/api/core");
      return await tauriInvoke<T>(cmd, args);
    } catch (e) {
      console.warn(`Tauri invoke failed for '${cmd}', falling back to simulated memory store:`, e);
    }
  }

  // Web/Dev Fallback Mock Data Store for responsive browser development & preview
  return mockInvoke<T>(cmd, args);
}

// Memory fallback store
let mockProjects: Project[] = [
  {
    id: "proj-1",
    name: "Enterprise Perimeter Assessment",
    description: "Authorized external penetration test & attack surface mapping",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
];

let mockTargets: Target[] = [
  {
    id: "targ-1",
    project_id: "proj-1",
    name: "Main Corporate Domain",
    target_value: "example.com",
    target_type: "domain",
    authorized: true,
    authorized_by: "CISO Office",
    created_at: new Date().toISOString(),
  },
  {
    id: "targ-2",
    project_id: "proj-1",
    name: "Staging Subnet",
    target_value: "192.168.10.0/24",
    target_type: "cidr",
    authorized: true,
    authorized_by: "Security Operations",
    created_at: new Date().toISOString(),
  },
];

let mockInstalledModules: InstalledModuleInfo[] = [];

let mockRegistryModules: ModuleManifest[] = [
  {
    id: "sample-dns",
    name: "DNS & Domain Reconnaissance",
    description: "Performs DNS record inspection, MX discovery, SPF/DMARC validation, and domain reconnaissance on authorized targets.",
    author: "Cyber Hashira Security Team",
    version: "1.0.0",
    min_host_version: "0.1.0",
    category: "Reconnaissance & OSINT",
    supported_os: ["windows", "linux", "macos"],
    supported_arch: ["x86_64", "aarch64"],
    required_permissions: ["network:connect", "dns:query"],
    entry_point: {
      runtime: "python",
      executable: "worker.py",
      default_args: [],
    },
    artifact: {
      sha256: "f9c129075cfa22a7f1154bccf45431be9007480a3257be927c95aabc98c2942b",
      size_bytes: 2849,
    },
    license: "Apache-2.0",
  },
  {
    id: "web-security",
    name: "Web Application Security Suite",
    description: "Intercepting HTTP/S proxy, Repeater, Decoder, OWASP ZAP adapter, and active web vulnerability scanner.",
    author: "Cyber Hashira Core",
    version: "0.5.0",
    min_host_version: "0.1.0",
    category: "Web Security",
    supported_os: ["windows", "linux"],
    supported_arch: ["x86_64"],
    required_permissions: ["network:listen", "network:connect", "tls:intercept"],
    entry_point: {
      runtime: "binary",
      executable: "web-security-worker",
      default_args: [],
    },
    license: "Apache-2.0",
  },
  {
    id: "network-security",
    name: "Network & Port Discovery (Nmap Core)",
    description: "High-performance port scanning, service versioning, NSE scripting engine integration, and network topology mapping.",
    author: "Cyber Hashira Core",
    version: "0.4.2",
    min_host_version: "0.1.0",
    category: "Network Security",
    supported_os: ["windows", "linux"],
    supported_arch: ["x86_64"],
    required_permissions: ["network:raw_socket", "process:exec"],
    entry_point: {
      runtime: "binary",
      executable: "nmap-adapter",
      default_args: [],
    },
    license: "GPL-2.0-or-later",
  },
  {
    id: "hashira-ai",
    name: "Hashira AI Security Assistant",
    description: "AI-assisted vulnerability triage, remediation guidance, CVE correlation, and natural language query processing.",
    author: "Cyber Hashira AI Labs",
    version: "0.3.0",
    min_host_version: "0.1.0",
    category: "Hashira AI",
    supported_os: ["windows", "linux", "macos"],
    supported_arch: ["x86_64", "aarch64"],
    required_permissions: ["network:connect", "findings:read"],
    entry_point: {
      runtime: "python",
      executable: "hashira_ai_worker.py",
      default_args: [],
    },
    license: "Apache-2.0",
  },
];

let mockFindings: Finding[] = [
  {
    id: "find-1",
    project_id: "proj-1",
    target_id: "targ-1",
    module_id: "sample-dns",
    title: "SPF Record Missing or Permissive (~all)",
    description: "The domain example.com does not enforce a strict SPF -all policy, allowing possible email spoofing.",
    severity: "Medium",
    cvss_v3: 5.3,
    cve: "CVE-2024-DNS-01",
    cwe: "CWE-200",
    evidence: "v=spf1 include:_spf.example.com ~all",
    timestamp: new Date().toISOString(),
    status: "Open",
    remediation: "Configure a strict SPF TXT record with hard fail policy: 'v=spf1 include:_spf.example.com -all'.",
  },
];

let mockAuditLogs: AuditLogEntry[] = [
  {
    id: "log-1",
    timestamp: new Date().toISOString(),
    actor: "operator",
    action: "system:boot",
    status: "SUCCESS",
    details: { event: "Host initialization complete" },
  },
];

async function mockInvoke<T>(cmd: string, args?: Record<string, any>): Promise<T> {
  await new Promise((r) => setTimeout(r, 80)); // Simulate brief IPC latency

  switch (cmd) {
    case "get_host_info":
      return {
        name: "Cyber Hashira Host",
        version: "0.1.0",
        os: "Windows 11 / Ubuntu 24.04 (Multi-platform)",
        arch: "x86_64",
        database: "SQLite (Local Isolated)",
      } as T;

    case "list_projects":
      return [...mockProjects] as T;

    case "create_project": {
      const newProj: Project = {
        id: `proj-${Date.now()}`,
        name: args?.name || "New Project",
        description: args?.description,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      mockProjects.unshift(newProj);
      return newProj as T;
    }

    case "list_targets":
      return mockTargets.filter((t) => !args?.project_id || t.project_id === args.project_id) as T;

    case "add_target": {
      const newTarget: Target = {
        id: `targ-${Date.now()}`,
        project_id: args?.project_id || "proj-1",
        name: args?.name || "Target",
        target_value: args?.target_value || "",
        target_type: args?.target_type || "domain",
        authorized: !!args?.authorized,
        authorized_by: args?.authorized_by,
        created_at: new Date().toISOString(),
      };
      mockTargets.unshift(newTarget);
      return newTarget as T;
    }

    case "validate_target_scope": {
      const target = (args?.target as string) || "";
      const isAllowed = mockTargets.some((t) => t.authorized && target.includes(t.target_value));
      if (!isAllowed) {
        throw new Error(`Target '${target}' is outside authorized scope`);
      }
      return true as T;
    }

    case "fetch_registry_modules":
      return [...mockRegistryModules] as T;

    case "list_installed_modules":
      return [...mockInstalledModules] as T;

    case "install_module": {
      const mod = mockRegistryModules.find((m) => m.id === args?.module_id);
      if (!mod) throw new Error("Module not found");
      const installed: InstalledModuleInfo = {
        id: mod.id,
        name: mod.name,
        version: mod.version,
        status: "enabled",
        install_path: `installed_modules/${mod.id}/${mod.version}`,
        installed_at: new Date().toISOString(),
        enabled_at: new Date().toISOString(),
        permissions: mod.required_permissions,
      };
      mockInstalledModules = mockInstalledModules.filter((m) => m.id !== mod.id);
      mockInstalledModules.push(installed);
      mockAuditLogs.unshift({
        id: `log-${Date.now()}`,
        timestamp: new Date().toISOString(),
        actor: "operator",
        action: "module:install",
        module_id: mod.id,
        status: "SUCCESS",
      });
      return installed as T;
    }

    case "enable_module": {
      const item = mockInstalledModules.find((m) => m.id === args?.module_id);
      if (item) {
        item.status = "enabled";
        item.enabled_at = new Date().toISOString();
      }
      return true as T;
    }

    case "disable_module": {
      const item = mockInstalledModules.find((m) => m.id === args?.module_id);
      if (item) item.status = "disabled";
      return true as T;
    }

    case "uninstall_module": {
      mockInstalledModules = mockInstalledModules.filter((m) => m.id !== args?.module_id);
      mockAuditLogs.unshift({
        id: `log-${Date.now()}`,
        timestamp: new Date().toISOString(),
        actor: "operator",
        action: "module:uninstall",
        module_id: args?.module_id,
        status: "SUCCESS",
      });
      return true as T;
    }

    case "list_findings":
      return [...mockFindings] as T;

    case "list_audit_logs":
      return [...mockAuditLogs] as T;

    default:
      throw new Error(`Unknown command: ${cmd}`);
  }
}

export const api = {
  getHostInfo: () => invoke<HostInfo>("get_host_info"),
  listProjects: () => invoke<Project[]>("list_projects"),
  createProject: (name: string, description?: string) =>
    invoke<Project>("create_project", { name, description }),
  listTargets: (project_id: string) => invoke<Target[]>("list_targets", { project_id }),
  addTarget: (
    project_id: string,
    name: string,
    target_value: string,
    target_type: string,
    authorized: boolean,
    authorized_by?: string
  ) =>
    invoke<Target>("add_target", {
      project_id,
      name,
      target_value,
      target_type,
      authorized,
      authorized_by,
    }),
  validateTargetScope: (project_id: string, target: string) =>
    invoke<boolean>("validate_target_scope", { project_id, target }),
  fetchRegistryModules: () => invoke<ModuleManifest[]>("fetch_registry_modules"),
  listInstalledModules: () => invoke<InstalledModuleInfo[]>("list_installed_modules"),
  installModule: (module_id: string) =>
    invoke<InstalledModuleInfo>("install_module", { module_id }),
  enableModule: (module_id: string) => invoke<void>("enable_module", { module_id }),
  disableModule: (module_id: string) => invoke<void>("disable_module", { module_id }),
  uninstallModule: (module_id: string) => invoke<void>("uninstall_module", { module_id }),
  runModuleTask: (module_id: string, project_id: string, target: string, options: any) =>
    invoke<any>("run_module_task", { module_id, project_id, target, options }),
  listFindings: (project_id?: string) => invoke<Finding[]>("list_findings", { project_id }),
  listAuditLogs: (limit?: number) => invoke<AuditLogEntry[]>("list_audit_logs", { limit }),
};
