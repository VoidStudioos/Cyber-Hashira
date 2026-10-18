import React from "react";
import {
  Shield,
  ShieldAlert,
  LayoutDashboard,
  FolderGit2,
  Crosshair,
  Store,
  Boxes,
  Bug,
  ScrollText,
  Settings,
  ChevronLeft,
  ChevronRight,
  Globe,
  Network,
  Terminal,
  GitFork,
  Sparkles,
  Radar,
  FileSearch,
  Code2,
  Lock,
  Github,
  Code,
  Cloud,
  Key,
} from "lucide-react";
import { InstalledModuleInfo } from "../types";

interface SidebarProps {
  currentView: string;
  onSelectView: (view: string) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
  installedModules: InstalledModuleInfo[];
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentView,
  onSelectView,
  collapsed,
  onToggleCollapse,
  installedModules,
}) => {
  const coreNavItems = [
    { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
    { id: "projects", label: "Projects", icon: FolderGit2 },
    { id: "targets", label: "Targets & Scope", icon: Crosshair },
    { id: "findings", label: "Findings", icon: Bug },
    { id: "workflow", label: "Automation Pipelines", icon: GitFork },
    { id: "activity", label: "Activity Logs", icon: ScrollText },
  ];

  const storeNavItems = [
    { id: "module-store", label: "Module Store", icon: Store },
    {
      id: "installed-modules",
      label: "Installed Modules",
      icon: Boxes,
      badge: installedModules.filter((m) => m.status === "enabled").length,
    },
  ];

  // Dynamic modules that are installed and enabled
  const dynamicModuleNavItems = installedModules
    .filter((m) => m.status === "enabled")
    .map((m) => {
    if (m.id === "web-security") {
      return {
        id: "web-security",
        label: m.name,
        icon: Globe,
      };
    }
    if (m.id === "network-security") {
      return {
        id: "network-security",
        label: m.name,
        icon: Network,
      };
    }
    if (m.id === "vulnerability-assessment") {
      return {
        id: "vulnerability-assessment",
        label: m.name,
        icon: ShieldAlert,
      };
    }
    if (m.id === "hashira-ai") {
      return {
        id: "hashira-ai",
        label: m.name,
        icon: Sparkles,
      };
    }
    if (m.id === "threat-intelligence") {
      return {
        id: "threat-intelligence",
        label: m.name,
        icon: Radar,
      };
    }
    if (m.id === "digital-forensics") {
      return {
        id: "digital-forensics",
        label: m.name,
        icon: FileSearch,
      };
    }
    if (m.id === "api-security") {
      return {
        id: "api-security",
        label: m.name,
        icon: Code2,
      };
    }
    if (m.id === "tls-cryptography") {
      return {
        id: "tls-cryptography",
        label: m.name,
        icon: Lock,
      };
    }
    if (m.id === "github-actions-security") {
      return {
        id: "github-actions-security",
        label: m.name,
        icon: Github,
      };
    }
    if (m.id === "container-security") {
      return {
        id: "container-security",
        label: m.name,
        icon: Boxes,
      };
    }
    if (m.id === "sast-source-scanner") {
      return {
        id: "sast-source-scanner",
        label: m.name,
        icon: Code,
      };
    }
    if (m.id === "cloud-iac-security") {
      return {
        id: "cloud-iac-security",
        label: m.name,
        icon: Cloud,
      };
    }
    if (m.id === "secrets-leak-scanner") {
      return {
        id: "secrets-leak-scanner",
        label: m.name,
        icon: Key,
      };
    }
    let icon = Terminal;
    if (m.id.includes("dns") || m.id.includes("recon")) icon = Globe;
    return {
      id: `module:${m.id}`,
      label: m.name,
      icon,
    };
  });

  return (
    <aside
      className={`h-screen bg-[#0b0f19] border-r border-[#1e293b] flex flex-col transition-all duration-300 z-20 ${
        collapsed ? "w-16" : "w-64"
      }`}
    >
      {/* Brand Header */}
      <div className="h-16 flex items-center justify-between px-4 border-b border-[#1e293b]">
        {!collapsed && (
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="font-bold text-sm tracking-wider uppercase text-cyan-400">
                Cyber Hashira
              </h1>
              <span className="text-[10px] text-slate-400 font-mono tracking-widest block">
                HOST v0.1.0
              </span>
            </div>
          </div>
        )}

        {collapsed && (
          <div className="mx-auto w-9 h-9 rounded-lg bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center">
            <Shield className="w-5 h-5 text-white" />
          </div>
        )}

        <button
          onClick={onToggleCollapse}
          className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800/60 transition"
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </div>

      {/* Navigation Links */}
      <div className="flex-1 overflow-y-auto px-2 py-4 space-y-6">
        {/* Core Workspace */}
        <div>
          {!collapsed && (
            <p className="px-3 text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-2">
              Workspace
            </p>
          )}
          <nav className="space-y-1">
            {coreNavItems.map((item) => {
              const Icon = item.icon;
              const active = currentView === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onSelectView(item.id)}
                  className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition ${
                    active
                      ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/30"
                      : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
                  }`}
                  title={item.label}
                >
                  <Icon className="w-4 h-4 shrink-0" />
                  {!collapsed && <span>{item.label}</span>}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Modular Ecosystem */}
        <div>
          {!collapsed && (
            <p className="px-3 text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-2">
              Module Ecosystem
            </p>
          )}
          <nav className="space-y-1">
            {storeNavItems.map((item) => {
              const Icon = item.icon;
              const active = currentView === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onSelectView(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm font-medium transition ${
                    active
                      ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/30"
                      : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
                  }`}
                  title={item.label}
                >
                  <div className="flex items-center gap-3">
                    <Icon className="w-4 h-4 shrink-0" />
                    {!collapsed && <span>{item.label}</span>}
                  </div>
                  {!collapsed && item.badge !== undefined && item.badge > 0 && (
                    <span className="text-xs bg-cyan-950 text-cyan-300 font-mono px-2 py-0.5 rounded-full border border-cyan-800">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Active Modules (On Demand) */}
        {dynamicModuleNavItems.length > 0 && (
          <div>
            {!collapsed && (
              <p className="px-3 text-[11px] font-semibold text-emerald-500 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                Active Tools
              </p>
            )}
            <nav className="space-y-1">
              {dynamicModuleNavItems.map((item) => {
                const Icon = item.icon;
                const active = currentView === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => onSelectView(item.id)}
                    className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition ${
                      active
                        ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                        : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
                    }`}
                    title={item.label}
                  >
                    <Icon className="w-4 h-4 shrink-0 text-emerald-400" />
                    {!collapsed && <span className="truncate">{item.label}</span>}
                  </button>
                );
              })}
            </nav>
          </div>
        )}
      </div>

      {/* Settings Footer */}
      <div className="p-3 border-t border-[#1e293b]">
        <button
          onClick={() => onSelectView("settings")}
          className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition ${
            currentView === "settings"
              ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/30"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
          }`}
          title="Settings"
        >
          <Settings className="w-4 h-4 shrink-0" />
          {!collapsed && <span>Settings</span>}
        </button>
      </div>
    </aside>
  );
};
