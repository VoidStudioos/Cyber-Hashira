import React, { useState } from "react";
import {
  Store,
  Search,
  Filter,
  CheckCircle2,
  Download,
  Trash2,
  Power,
  Shield,
  AlertCircle,
  Key,
} from "lucide-react";
import { InstalledModuleInfo, ModuleManifest } from "../types";

interface ModuleStoreViewProps {
  registryModules: ModuleManifest[];
  installedModules: InstalledModuleInfo[];
  onInstall: (moduleId: string) => Promise<void>;
  onEnable: (moduleId: string) => Promise<void>;
  onDisable: (moduleId: string) => Promise<void>;
  onUninstall: (moduleId: string) => Promise<void>;
}

export const ModuleStoreView: React.FC<ModuleStoreViewProps> = ({
  registryModules,
  installedModules,
  onInstall,
  onEnable,
  onDisable,
  onUninstall,
}) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedCategory, setSelectedCategory] = useState("All");
  const [loadingModuleId, setLoadingModuleId] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const categories = [
    "All",
    "Reconnaissance & OSINT",
    "Web Security",
    "Network Security",
    "Vulnerability Assessment",
    "Hashira AI",
  ];

  const filtered = registryModules.filter((m) => {
    const matchSearch =
      m.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      m.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      m.id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchCat = selectedCategory === "All" || m.category === selectedCategory;
    return matchSearch && matchCat;
  });

  const getInstalledState = (moduleId: string) => {
    return installedModules.find((m) => m.id === moduleId);
  };

  const handleAction = async (action: () => Promise<void>, moduleId: string) => {
    try {
      setErrorMsg(null);
      setLoadingModuleId(moduleId);
      await action();
    } catch (e: any) {
      setErrorMsg(e?.message || String(e));
    } finally {
      setLoadingModuleId(null);
    }
  };

  return (
    <div className="p-8 space-y-6 overflow-y-auto max-h-[calc(100vh-4rem)]">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Store className="w-6 h-6 text-cyan-400" />
            <span>Module Store & Marketplace</span>
          </h2>
          <p className="text-slate-400 text-sm mt-1">
            Browse and install verified on-demand cybersecurity modules. Every package is verified via SHA-256 before activation.
          </p>
        </div>

        {/* Search & Filter Bar */}
        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search modules..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-[#0f1626] border border-[#1e293b] text-slate-200 text-sm rounded-xl pl-9 pr-4 py-2 w-64 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="relative">
            <Filter className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="bg-[#0f1626] border border-[#1e293b] text-slate-200 text-sm rounded-xl pl-9 pr-4 py-2 focus:outline-none focus:border-cyan-500"
            >
              {categories.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {errorMsg && (
        <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl text-red-400 text-sm flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Module Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filtered.map((module) => {
          const installed = getInstalledState(module.id);
          const isLoading = loadingModuleId === module.id;

          return (
            <div
              key={module.id}
              className="bg-[#0f1626] border border-[#1e293b] hover:border-slate-700 rounded-2xl p-6 flex flex-col justify-between transition group"
            >
              <div>
                {/* Category & Version */}
                <div className="flex items-center justify-between mb-3">
                  <span className="text-[11px] font-semibold text-cyan-400 bg-cyan-950/60 border border-cyan-800/60 px-2.5 py-0.5 rounded-full">
                    {module.category || "General Security"}
                  </span>
                  <span className="text-xs font-mono text-slate-400">
                    v{module.version}
                  </span>
                </div>

                {/* Title */}
                <h3 className="text-base font-bold text-white group-hover:text-cyan-300 transition">
                  {module.name}
                </h3>
                <p className="text-xs text-slate-400 mt-2 line-clamp-3 leading-relaxed">
                  {module.description}
                </p>

                {/* Permissions Preview */}
                <div className="mt-4 pt-3 border-t border-[#1e293b]">
                  <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1 flex items-center gap-1">
                    <Key className="w-3 h-3 text-amber-400" />
                    Required Permissions:
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {module.required_permissions.map((p) => (
                      <span
                        key={p}
                        className="text-[10px] font-mono bg-slate-800/80 text-slate-300 px-2 py-0.5 rounded"
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Platform Compatibility */}
                <div className="mt-3 flex items-center gap-2 text-xs text-slate-400">
                  <Shield className="w-3.5 h-3.5 text-slate-500" />
                  <span>OS: {module.supported_os.join(", ")}</span>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="mt-6 pt-4 border-t border-[#1e293b] flex items-center justify-between">
                {installed ? (
                  <div className="flex items-center justify-between w-full">
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`w-2.5 h-2.5 rounded-full ${
                          installed.status === "enabled"
                            ? "bg-emerald-500 animate-pulse"
                            : "bg-slate-500"
                        }`}
                      />
                      <span className="text-xs font-medium text-slate-300 capitalize">
                        {installed.status}
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      {installed.status === "enabled" ? (
                        <button
                          disabled={isLoading}
                          onClick={() => handleAction(() => onDisable(module.id), module.id)}
                          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded-lg flex items-center gap-1.5 transition"
                          title="Disable Module"
                        >
                          <Power className="w-3.5 h-3.5" />
                          <span>Disable</span>
                        </button>
                      ) : (
                        <button
                          disabled={isLoading}
                          onClick={() => handleAction(() => onEnable(module.id), module.id)}
                          className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs rounded-lg flex items-center gap-1.5 transition"
                          title="Enable Module"
                        >
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Enable</span>
                        </button>
                      )}

                      <button
                        disabled={isLoading}
                        onClick={() => handleAction(() => onUninstall(module.id), module.id)}
                        className="p-1.5 bg-red-500/10 hover:bg-red-500/20 text-red-400 rounded-lg transition"
                        title="Uninstall Module"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                ) : (
                  <button
                    disabled={isLoading}
                    onClick={() => handleAction(() => onInstall(module.id), module.id)}
                    className="w-full py-2 bg-cyan-500 hover:bg-cyan-400 text-[#090d16] font-semibold text-xs rounded-xl flex items-center justify-center gap-2 transition shadow-md shadow-cyan-500/10"
                  >
                    {isLoading ? (
                      <span className="animate-spin inline-block w-4 h-4 border-2 border-current border-t-transparent rounded-full" />
                    ) : (
                      <Download className="w-3.5 h-3.5" />
                    )}
                    <span>{isLoading ? "Verifying & Installing..." : "Install Module"}</span>
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
