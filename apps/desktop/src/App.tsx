import React, { useEffect, useState } from "react";
import { Sidebar } from "./components/Sidebar";
import { Header } from "./components/Header";
import { DashboardView } from "./views/DashboardView";
import { ProjectsView } from "./views/ProjectsView";
import { TargetsView } from "./views/TargetsView";
import { ModuleStoreView } from "./views/ModuleStoreView";
import { InstalledModulesView } from "./views/InstalledModulesView";
import { FindingsView } from "./views/FindingsView";
import { ActivityLogsView } from "./views/ActivityLogsView";
import { SettingsView } from "./views/SettingsView";
import { api } from "./api/client";
import {
  AuditLogEntry,
  Finding,
  HostInfo,
  InstalledModuleInfo,
  ModuleManifest,
  Project,
  Target,
} from "./types";

export const App: React.FC = () => {
  const [currentView, setCurrentView] = useState("dashboard");
  const [collapsed, setCollapsed] = useState(false);
  const [isRtl, setIsRtl] = useState(false);

  const [hostInfo, setHostInfo] = useState<HostInfo | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [activeProject, setActiveProject] = useState<Project | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [registryModules, setRegistryModules] = useState<ModuleManifest[]>([]);
  const [installedModules, setInstalledModules] = useState<InstalledModuleInfo[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);

  // Initial data loading
  useEffect(() => {
    loadAllData();
  }, []);

  const loadAllData = async () => {
    try {
      const info = await api.getHostInfo();
      setHostInfo(info);

      const projs = await api.listProjects();
      setProjects(projs);
      if (projs.length > 0 && !activeProject) {
        setActiveProject(projs[0]);
      }

      const regMods = await api.fetchRegistryModules();
      setRegistryModules(regMods);

      const instMods = await api.listInstalledModules();
      setInstalledModules(instMods);

      const finds = await api.listFindings();
      setFindings(finds);

      const auditLogs = await api.listAuditLogs(100);
      setLogs(auditLogs);
    } catch (e) {
      console.error("Failed to load platform data:", e);
    }
  };

  // Reload targets whenever active project changes
  useEffect(() => {
    if (activeProject) {
      api.listTargets(activeProject.id).then(setTargets).catch(console.error);
    }
  }, [activeProject]);

  const handleSelectProject = (project: Project) => {
    setActiveProject(project);
  };

  const handleCreateProject = async (name: string, description?: string) => {
    const newProj = await api.createProject(name, description);
    const updated = await api.listProjects();
    setProjects(updated);
    setActiveProject(newProj);
    const updatedLogs = await api.listAuditLogs(100);
    setLogs(updatedLogs);
  };

  const handleAddTarget = async (
    name: string,
    targetValue: string,
    targetType: string,
    authorized: boolean,
    authorizedBy?: string
  ) => {
    if (!activeProject) return;
    await api.addTarget(
      activeProject.id,
      name,
      targetValue,
      targetType,
      authorized,
      authorizedBy
    );
    const updated = await api.listTargets(activeProject.id);
    setTargets(updated);
    const updatedLogs = await api.listAuditLogs(100);
    setLogs(updatedLogs);
  };

  const handleValidateScope = async (target: string): Promise<boolean> => {
    if (!activeProject) return false;
    return await api.validateTargetScope(activeProject.id, target);
  };

  const handleInstallModule = async (moduleId: string) => {
    await api.installModule(moduleId);
    const updated = await api.listInstalledModules();
    setInstalledModules(updated);
    const updatedLogs = await api.listAuditLogs(100);
    setLogs(updatedLogs);
  };

  const handleEnableModule = async (moduleId: string) => {
    await api.enableModule(moduleId);
    const updated = await api.listInstalledModules();
    setInstalledModules(updated);
    const updatedLogs = await api.listAuditLogs(100);
    setLogs(updatedLogs);
  };

  const handleDisableModule = async (moduleId: string) => {
    await api.disableModule(moduleId);
    const updated = await api.listInstalledModules();
    setInstalledModules(updated);
    const updatedLogs = await api.listAuditLogs(100);
    setLogs(updatedLogs);
  };

  const handleUninstallModule = async (moduleId: string) => {
    await api.uninstallModule(moduleId);
    const updated = await api.listInstalledModules();
    setInstalledModules(updated);
    const updatedLogs = await api.listAuditLogs(100);
    setLogs(updatedLogs);
  };

  const handleRunTask = async (moduleId: string, target: string, options: any) => {
    if (!activeProject) throw new Error("No active project selected");
    const result = await api.runModuleTask(moduleId, activeProject.id, target, options);
    // Refresh findings and audit logs
    const updatedFindings = await api.listFindings(activeProject.id);
    setFindings(updatedFindings);
    const updatedLogs = await api.listAuditLogs(100);
    setLogs(updatedLogs);
    return result;
  };

  return (
    <div
      dir={isRtl ? "rtl" : "ltr"}
      className="flex h-screen w-screen overflow-hidden bg-[#080c14] text-slate-100"
    >
      {/* Sidebar */}
      <Sidebar
        currentView={currentView}
        onSelectView={setCurrentView}
        collapsed={collapsed}
        onToggleCollapse={() => setCollapsed(!collapsed)}
        installedModules={installedModules}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col h-screen overflow-hidden">
        <Header
          hostInfo={hostInfo}
          projects={projects}
          activeProject={activeProject}
          onSelectProject={handleSelectProject}
          isRtl={isRtl}
          onToggleRtl={() => setIsRtl(!isRtl)}
        />

        <main className="flex-1 overflow-hidden relative">
          {currentView === "dashboard" && (
            <DashboardView
              activeProject={activeProject}
              targets={targets}
              installedModules={installedModules}
              findings={findings}
              onNavigate={setCurrentView}
            />
          )}

          {currentView === "projects" && (
            <ProjectsView
              projects={projects}
              activeProject={activeProject}
              onSelectProject={handleSelectProject}
              onCreateProject={handleCreateProject}
            />
          )}

          {currentView === "targets" && (
            <TargetsView
              activeProject={activeProject}
              targets={targets}
              onAddTarget={handleAddTarget}
              onValidateScope={handleValidateScope}
            />
          )}

          {currentView === "module-store" && (
            <ModuleStoreView
              registryModules={registryModules}
              installedModules={installedModules}
              onInstall={handleInstallModule}
              onEnable={handleEnableModule}
              onDisable={handleDisableModule}
              onUninstall={handleUninstallModule}
            />
          )}

          {(currentView === "installed-modules" || currentView.startsWith("module:")) && (
            <InstalledModulesView
              installedModules={installedModules}
              targets={targets}
              activeProject={activeProject}
              onRunTask={handleRunTask}
            />
          )}

          {currentView === "findings" && <FindingsView findings={findings} />}

          {currentView === "activity" && <ActivityLogsView logs={logs} />}

          {currentView === "settings" && <SettingsView hostInfo={hostInfo} />}
        </main>
      </div>
    </div>
  );
};
