import React, { useState } from "react";
import { FolderGit2, Plus, Calendar, ArrowRight } from "lucide-react";
import { Project } from "../types";

interface ProjectsViewProps {
  projects: Project[];
  activeProject: Project | null;
  onSelectProject: (p: Project) => void;
  onCreateProject: (name: string, description?: string) => Promise<void>;
}

export const ProjectsView: React.FC<ProjectsViewProps> = ({
  projects,
  activeProject,
  onSelectProject,
  onCreateProject,
}) => {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    await onCreateProject(name, description);
    setName("");
    setDescription("");
  };

  return (
    <div className="p-8 space-y-8 overflow-y-auto max-h-[calc(100vh-4rem)]">
      <div>
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <FolderGit2 className="w-6 h-6 text-cyan-400" />
          <span>Security Assessment Projects</span>
        </h2>
        <p className="text-slate-400 text-sm mt-1">
          Isolate targets, scopes, credentials, evidence, and findings by engagement.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Create Project Form */}
        <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-6">
          <h3 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
            <Plus className="w-4 h-4 text-cyan-400" />
            <span>Create New Project</span>
          </h3>

          <form onSubmit={handleCreate} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
                Project Name
              </label>
              <input
                type="text"
                placeholder="e.g. Q4 Cloud Infrastructure Audit"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                className="w-full bg-[#0b0f19] border border-[#1e293b] text-slate-200 text-sm rounded-xl px-3 py-2 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
                Description & Scope Purpose
              </label>
              <textarea
                rows={3}
                placeholder="Notes on assessment objectives, authorized testing window, client contact..."
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="w-full bg-[#0b0f19] border border-[#1e293b] text-slate-200 text-sm rounded-xl px-3 py-2 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <button
              type="submit"
              className="w-full py-2.5 bg-cyan-500 hover:bg-cyan-400 text-[#090d16] font-semibold text-sm rounded-xl transition shadow-lg shadow-cyan-500/20"
            >
              Create Project
            </button>
          </form>
        </div>

        {/* Existing Projects Grid */}
        <div className="lg:col-span-2 space-y-4">
          <h3 className="text-base font-semibold text-white">Active Projects ({projects.length})</h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {projects.map((p) => {
              const isActive = activeProject?.id === p.id;

              return (
                <div
                  key={p.id}
                  onClick={() => onSelectProject(p)}
                  className={`p-5 rounded-2xl border transition cursor-pointer select-none flex flex-col justify-between ${
                    isActive
                      ? "bg-cyan-950/20 border-cyan-500/50 shadow-lg shadow-cyan-500/10"
                      : "bg-[#0f1626] border-[#1e293b] hover:border-slate-700"
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-mono text-cyan-400">
                        {p.id.slice(0, 8)}...
                      </span>
                      {isActive && (
                        <span className="text-[10px] uppercase font-bold bg-cyan-500 text-[#090d16] px-2 py-0.5 rounded-full">
                          ACTIVE
                        </span>
                      )}
                    </div>

                    <h4 className="text-base font-bold text-white">{p.name}</h4>
                    <p className="text-xs text-slate-400 mt-1 line-clamp-2">
                      {p.description || "No description provided."}
                    </p>
                  </div>

                  <div className="mt-4 pt-3 border-t border-[#1e293b] flex items-center justify-between text-xs text-slate-500">
                    <span className="flex items-center gap-1">
                      <Calendar className="w-3.5 h-3.5" />
                      {new Date(p.created_at).toLocaleDateString()}
                    </span>
                    <span className="text-cyan-400 font-medium flex items-center gap-1">
                      <span>Switch</span>
                      <ArrowRight className="w-3 h-3" />
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
