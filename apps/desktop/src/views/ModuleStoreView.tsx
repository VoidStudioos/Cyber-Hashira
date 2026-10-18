import React, { useState, useEffect } from "react";
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
  Edit3,
  Image,
  Tag,
  Save,
  X,
  Plus,
  Sparkles,
  Globe,
  Network,
  ShieldAlert,
  Terminal,
  Radar,
  FileSearch,
  Code2,
  Lock,
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

interface CustomModuleMeta {
  customName?: string;
  customCategory?: string;
  customDescription?: string;
  customBannerUrl?: string;
  customIcon?: string;
}

const ICON_MAP: Record<string, React.ElementType> = {
  store: Store,
  globe: Globe,
  network: Network,
  shield: ShieldAlert,
  sparkles: Sparkles,
  radar: Radar,
  forensics: FileSearch,
  code: Code2,
  lock: Lock,
  terminal: Terminal,
};

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

  // Admin Customization State (Stored locally in localStorage for persistent styling)
  const [customMetadata, setCustomMetadata] = useState<Record<string, CustomModuleMeta>>({});
  const [editingModuleId, setEditingModuleId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState<CustomModuleMeta>({});
  const [availableCategories, setAvailableCategories] = useState<string[]>([
    "All",
    "Reconnaissance & OSINT",
    "Web Security",
    "Network Security",
    "Vulnerability Assessment",
    "Hashira AI",
    "Threat Intelligence",
    "Digital Forensics",
    "API Security",
    "TLS & Cryptography",
    "Source Code & CI/CD",
    "Container Security",
    "Wireless Security",
    "Automotive & Hardware",
    "Network Forensics",
  ]);
  const [newCategoryInput, setNewCategoryInput] = useState("");
  const [showAddCategory, setShowAddCategory] = useState(false);

  // Load custom metadata on mount
  useEffect(() => {
    try {
      const saved = localStorage.getItem("hashira_module_customizations");
      if (saved) {
        setCustomMetadata(JSON.parse(saved));
      }
      const savedCats = localStorage.getItem("hashira_custom_categories");
      if (savedCats) {
        setAvailableCategories(JSON.parse(savedCats));
      }
    } catch (e) {
      console.error("Failed to load module customizations:", e);
    }
  }, []);

  const saveCustomizations = (newMeta: Record<string, CustomModuleMeta>) => {
    setCustomMetadata(newMeta);
    localStorage.setItem("hashira_module_customizations", JSON.stringify(newMeta));
  };

  const handleOpenEdit = (mod: ModuleManifest) => {
    setEditingModuleId(mod.id);
    const existing = customMetadata[mod.id] || {};
    setEditForm({
      customName: existing.customName || mod.name,
      customCategory: existing.customCategory || mod.category,
      customDescription: existing.customDescription || mod.description,
      customBannerUrl: existing.customBannerUrl || mod.banner_url || "",
      customIcon: existing.customIcon || mod.icon || "shield",
    });
  };

  const handleSaveEdit = (moduleId: string) => {
    const updated = {
      ...customMetadata,
      [moduleId]: editForm,
    };
    saveCustomizations(updated);
    setEditingModuleId(null);
  };

  const handleResetCustomization = (moduleId: string) => {
    const updated = { ...customMetadata };
    delete updated[moduleId];
    saveCustomizations(updated);
    setEditingModuleId(null);
  };

  const handleAddNewCategory = () => {
    if (!newCategoryInput.trim()) return;
    const cat = newCategoryInput.trim();
    if (!availableCategories.includes(cat)) {
      const updated = [...availableCategories, cat];
      setAvailableCategories(updated);
      localStorage.setItem("hashira_custom_categories", JSON.stringify(updated));
    }
    setNewCategoryInput("");
    setShowAddCategory(false);
  };

  const getEffectiveCategory = (m: ModuleManifest) => {
    return customMetadata[m.id]?.customCategory || m.category || "General Security";
  };

  const getEffectiveName = (m: ModuleManifest) => {
    return customMetadata[m.id]?.customName || m.name;
  };

  const getEffectiveDescription = (m: ModuleManifest) => {
    return customMetadata[m.id]?.customDescription || m.description;
  };

  const getEffectiveBanner = (m: ModuleManifest) => {
    return customMetadata[m.id]?.customBannerUrl || m.banner_url || null;
  };

  const getEffectiveIcon = (m: ModuleManifest) => {
    const iconName = customMetadata[m.id]?.customIcon || m.icon || "shield";
    return ICON_MAP[iconName.toLowerCase()] || Shield;
  };

  const filtered = registryModules.filter((m) => {
    const effName = getEffectiveName(m).toLowerCase();
    const effDesc = getEffectiveDescription(m).toLowerCase();
    const effCat = getEffectiveCategory(m);

    const matchSearch =
      effName.includes(searchTerm.toLowerCase()) ||
      effDesc.includes(searchTerm.toLowerCase()) ||
      m.id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchCat = selectedCategory === "All" || effCat === selectedCategory;
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
            <span className="text-xs font-mono bg-cyan-950/80 border border-cyan-800/80 text-cyan-300 px-2 py-0.5 rounded-full">
              ADMIN CUSTOMIZATION ENABLED
            </span>
          </h2>
          <p className="text-slate-400 text-sm mt-1">
            Browse, customize, and install verified security modules. Administrators can customize titles, categories, icons, and visual banners.
          </p>
        </div>

        {/* Search & Filter Bar */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search modules..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-[#0f1626] border border-[#1e293b] text-slate-200 text-sm rounded-xl pl-9 pr-4 py-2 w-56 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="relative">
            <Filter className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="bg-[#0f1626] border border-[#1e293b] text-slate-200 text-sm rounded-xl pl-9 pr-8 py-2 focus:outline-none focus:border-cyan-500 appearance-none"
            >
              {availableCategories.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={() => setShowAddCategory(!showAddCategory)}
            className="p-2 bg-[#0f1626] hover:bg-slate-800 border border-[#1e293b] text-slate-300 hover:text-cyan-400 rounded-xl text-xs flex items-center gap-1 transition"
            title="Create Custom Category"
          >
            <Plus className="w-4 h-4" />
            <span>Category</span>
          </button>
        </div>
      </div>

      {/* Add New Category Box */}
      {showAddCategory && (
        <div className="bg-[#101726] border border-cyan-800/60 p-4 rounded-xl flex items-center gap-3">
          <Tag className="w-4 h-4 text-cyan-400 shrink-0" />
          <input
            type="text"
            value={newCategoryInput}
            onChange={(e) => setNewCategoryInput(e.target.value)}
            placeholder="New Category Name (e.g. Red Teaming, Industrial OT, AI Jailbreaks)..."
            className="bg-[#080c14] border border-slate-700 text-white text-xs rounded-lg px-3 py-2 flex-1 focus:outline-none focus:border-cyan-500"
          />
          <button
            onClick={handleAddNewCategory}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded-lg flex items-center gap-1"
          >
            <Plus className="w-3.5 h-3.5" />
            Add Category
          </button>
          <button
            onClick={() => setShowAddCategory(false)}
            className="p-2 text-slate-400 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

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
          const isEditing = editingModuleId === module.id;

          const effName = getEffectiveName(module);
          const effCategory = getEffectiveCategory(module);
          const effDesc = getEffectiveDescription(module);
          const effBanner = getEffectiveBanner(module);
          const IconComponent = getEffectiveIcon(module);

          return (
            <div
              key={module.id}
              className="bg-[#0f1626] border border-[#1e293b] hover:border-slate-700 rounded-2xl overflow-hidden flex flex-col justify-between transition group shadow-lg"
            >
              {/* Optional Custom Banner Image */}
              {effBanner && (
                <div className="h-28 w-full overflow-hidden border-b border-[#1e293b] relative">
                  <img
                    src={effBanner}
                    alt={effName}
                    className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
                  />
                  <div className="absolute inset-0 bg-gradient-to-t from-[#0f1626] via-transparent to-transparent" />
                </div>
              )}

              <div className="p-6 flex-1 flex flex-col justify-between">
                <div>
                  {/* Category & Edit Button */}
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-[11px] font-semibold text-cyan-400 bg-cyan-950/60 border border-cyan-800/60 px-2.5 py-0.5 rounded-full">
                      {effCategory}
                    </span>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-slate-400">
                        v{module.version}
                      </span>
                      <button
                        onClick={() => handleOpenEdit(module)}
                        className="p-1 hover:bg-slate-800 text-slate-400 hover:text-cyan-400 rounded-md transition"
                        title="Customize Category, Title & Banner"
                      >
                        <Edit3 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>

                  {/* Icon & Title */}
                  <div className="flex items-center gap-3 mb-2">
                    <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-950 to-blue-950 border border-cyan-800/40 flex items-center justify-center text-cyan-400 shrink-0">
                      <IconComponent className="w-5 h-5" />
                    </div>
                    <h3 className="font-bold text-base text-white group-hover:text-cyan-400 transition">
                      {effName}
                    </h3>
                  </div>

                  {/* Description */}
                  <p className="text-xs text-slate-400 line-clamp-3 leading-relaxed mt-2">
                    {effDesc}
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

              {/* In-Card Admin Customizer Modal */}
              {isEditing && (
                <div className="p-4 bg-[#080c14] border-t border-cyan-800/80 space-y-3">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                    <span className="text-xs font-bold text-cyan-400 flex items-center gap-1">
                      <Edit3 className="w-3 h-3" />
                      Customize Module Presentation
                    </span>
                    <button
                      onClick={() => setEditingModuleId(null)}
                      className="text-slate-400 hover:text-white"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>

                  <div>
                    <label className="text-[10px] text-slate-400 block mb-1">Display Title</label>
                    <input
                      type="text"
                      value={editForm.customName || ""}
                      onChange={(e) => setEditForm({ ...editForm, customName: e.target.value })}
                      className="w-full bg-[#101726] border border-slate-700 rounded px-2 py-1 text-xs text-white"
                    />
                  </div>

                  <div>
                    <label className="text-[10px] text-slate-400 block mb-1">Category</label>
                    <select
                      value={editForm.customCategory || effCategory}
                      onChange={(e) => setEditForm({ ...editForm, customCategory: e.target.value })}
                      className="w-full bg-[#101726] border border-slate-700 rounded px-2 py-1 text-xs text-white"
                    >
                      {availableCategories.filter((c) => c !== "All").map((c) => (
                        <option key={c} value={c}>
                          {c}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="text-[10px] text-slate-400 block mb-1 flex items-center gap-1">
                      <Image className="w-3 h-3 text-cyan-400" />
                      Banner Image URL (Unsplash, CDN or Local)
                    </label>
                    <input
                      type="text"
                      value={editForm.customBannerUrl || ""}
                      onChange={(e) => setEditForm({ ...editForm, customBannerUrl: e.target.value })}
                      placeholder="https://images.unsplash.com/photo-..."
                      className="w-full bg-[#101726] border border-slate-700 rounded px-2 py-1 text-xs text-white font-mono"
                    />
                  </div>

                  <div>
                    <label className="text-[10px] text-slate-400 block mb-1">Icon Style</label>
                    <select
                      value={editForm.customIcon || "shield"}
                      onChange={(e) => setEditForm({ ...editForm, customIcon: e.target.value })}
                      className="w-full bg-[#101726] border border-slate-700 rounded px-2 py-1 text-xs text-white"
                    >
                      <option value="shield">Shield</option>
                      <option value="globe">Globe (Web)</option>
                      <option value="network">Network</option>
                      <option value="sparkles">Sparkles (AI)</option>
                      <option value="radar">Radar (Intel)</option>
                      <option value="forensics">File Search (Forensics)</option>
                      <option value="code">Code (API)</option>
                      <option value="lock">Lock (Cryptography)</option>
                      <option value="terminal">Terminal</option>
                    </select>
                  </div>

                  <div className="flex items-center justify-between pt-2">
                    <button
                      onClick={() => handleResetCustomization(module.id)}
                      className="text-[10px] text-slate-400 hover:text-red-400 underline"
                    >
                      Reset to Default
                    </button>
                    <button
                      onClick={() => handleSaveEdit(module.id)}
                      className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded flex items-center gap-1"
                    >
                      <Save className="w-3 h-3" />
                      Save
                    </button>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
