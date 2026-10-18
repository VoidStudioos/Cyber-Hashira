import React, { useState } from "react";
import {
  Sparkles,
  Send,
  RotateCw,
  Shield,
  EyeOff,
  Cpu,
  Copy,
  Terminal,
  Languages,
} from "lucide-react";
import { Finding, Target } from "../types";

interface HashiraAiViewProps {
  findings: Finding[];
  targets: Target[];
  onRunTask: (moduleId: string, target: string, options: any) => Promise<any>;
}

interface ChatMessage {
  id: string;
  sender: "user" | "ai";
  text: string;
  patch?: string;
  timestamp: string;
}

export const HashiraAiView: React.FC<HashiraAiViewProps> = ({
  findings,
  onRunTask,
}) => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: "msg-1",
      sender: "ai",
      text: "Hello, I am **Hashira AI**, your defensive cybersecurity assistant. I can triage your project's vulnerabilities, explain complex CVEs, generate secure configuration patches, and draft executive reports.\n\nAll queries are automatically processed through the local **Secret Redaction Engine** before analysis.",
      timestamp: new Date().toLocaleTimeString(),
    },
  ]);

  const [inputQuery, setInputQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [lang, setLang] = useState<"en" | "fa">("en");
  const [modelEndpoint, setModelEndpoint] = useState("Local Offline Engine (Hashira Core)");

  const handleSendMessage = async (customAction?: string) => {
    const queryToSend = customAction || inputQuery;
    if (!queryToSend.trim()) return;

    const userMsg: ChatMessage = {
      id: `usr-${Date.now()}`,
      sender: "user",
      text: queryToSend,
      timestamp: new Date().toLocaleTimeString(),
    };
    setMessages((prev) => [...prev, userMsg]);
    if (!customAction) setInputQuery("");
    setLoading(true);

    try {
      let options: any = {
        action: "chat",
        language: lang,
        query: queryToSend,
      };

      if (customAction === "triage") {
        options = {
          action: "triage",
          language: lang,
          findings_list: findings,
        };
      } else if (customAction === "explain" && findings.length > 0) {
        options = {
          action: "explain",
          language: lang,
          finding: findings[0],
        };
      }

      const res = await onRunTask("hashira-ai", "Assessment Project", options);
      const aiReply = res?.payload?.response || "Analysis completed.";
      const patch = res?.payload?.remediation_patch || undefined;

      const aiMsg: ChatMessage = {
        id: `ai-${Date.now()}`,
        sender: "ai",
        text: aiReply,
        patch,
        timestamp: new Date().toLocaleTimeString(),
      };
      setMessages((prev) => [...prev, aiMsg]);
    } catch (e: any) {
      const errMsg: ChatMessage = {
        id: `err-${Date.now()}`,
        sender: "ai",
        text: `Error during AI inference: ${e?.message || String(e)}`,
        timestamp: new Date().toLocaleTimeString(),
      };
      setMessages((prev) => [...prev, errMsg]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-8 space-y-6 overflow-y-auto max-h-[calc(100vh-4rem)]">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[#1e293b]">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Sparkles className="w-6 h-6 text-cyan-400" />
            <span>Hashira AI Defensive Security Assistant</span>
          </h2>
          <p className="text-slate-400 text-sm mt-1">
            Defensive triage, CVE impact explanation, and bilingual executive report drafting.
          </p>
        </div>

        {/* Model Endpoint & Privacy Status */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs px-3 py-1.5 rounded-xl font-mono">
            <EyeOff className="w-3.5 h-3.5" />
            <span>Secret Redaction: ON</span>
          </div>

          <button
            onClick={() => setLang(lang === "en" ? "fa" : "en")}
            className="flex items-center gap-1.5 text-xs text-slate-200 bg-[#0f1626] border border-[#1e293b] px-3 py-1.5 rounded-xl hover:bg-slate-800 transition"
          >
            <Languages className="w-3.5 h-3.5 text-cyan-400" />
            <span>{lang === "fa" ? "زبان: فارسی" : "Lang: English"}</span>
          </button>
        </div>
      </div>

      {/* Main Workspace Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Quick Actions & Configuration */}
        <div className="space-y-4">
          <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-5 space-y-3">
            <h3 className="text-xs font-semibold uppercase text-slate-400 tracking-wider flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <span>Inference Engine</span>
            </h3>
            <select
              value={modelEndpoint}
              onChange={(e) => setModelEndpoint(e.target.value)}
              className="w-full bg-[#0b0f19] border border-[#1e293b] text-slate-200 text-xs rounded-xl px-3 py-2 focus:outline-none focus:border-cyan-500"
            >
              <option value="Local Offline Engine (Hashira Core)">Local Offline Engine (Hashira Core)</option>
              <option value="Ollama (127.0.0.1:11434)">Ollama Local Daemon (127.0.0.1:11434)</option>
              <option value="Custom OpenAI Compatible API">Custom OpenAI-Compatible API</option>
            </select>
          </div>

          {/* Quick Analysis Actions */}
          <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-5 space-y-3">
            <h3 className="text-xs font-semibold uppercase text-slate-400 tracking-wider">
              One-Click AI Security Tasks
            </h3>
            <div className="space-y-2">
              <button
                disabled={loading || findings.length === 0}
                onClick={() => handleSendMessage("triage")}
                className="w-full p-2.5 bg-[#0b0f19] hover:bg-slate-800 border border-[#1e293b] text-left text-xs text-cyan-300 font-medium rounded-xl flex items-center justify-between transition"
              >
                <span>Triage Current Project Findings</span>
                <span className="text-[10px] bg-cyan-950 px-2 py-0.5 rounded font-mono">
                  {findings.length} findings
                </span>
              </button>

              <button
                disabled={loading || findings.length === 0}
                onClick={() => handleSendMessage("explain")}
                className="w-full p-2.5 bg-[#0b0f19] hover:bg-slate-800 border border-[#1e293b] text-left text-xs text-slate-200 font-medium rounded-xl flex items-center justify-between transition"
              >
                <span>Explain Top Vulnerability & Patch</span>
                <Terminal className="w-3.5 h-3.5 text-slate-400" />
              </button>
            </div>
          </div>

          {/* Security Guardrails Note */}
          <div className="bg-cyan-950/20 border border-cyan-900/30 rounded-2xl p-4 text-xs text-slate-400 space-y-1">
            <span className="font-semibold text-cyan-400 flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5" />
              Non-Intrusive Safety Policy
            </span>
            <p>
              Hashira AI provides strictly defensive guidance and remediation code. It is architecturally prohibited from launching autonomous intrusive attacks without explicit user approval.
            </p>
          </div>
        </div>

        {/* Right: Interactive Dialogue Stream */}
        <div className="lg:col-span-2 bg-[#0f1626] border border-[#1e293b] rounded-2xl flex flex-col h-[580px] overflow-hidden">
          {/* Messages Scroll Area */}
          <div className="flex-1 overflow-y-auto p-6 space-y-4">
            {messages.map((m) => (
              <div
                key={m.id}
                className={`flex flex-col ${
                  m.sender === "user" ? "items-end" : "items-start"
                }`}
              >
                <div
                  className={`max-w-[85%] rounded-2xl p-4 text-xs leading-relaxed ${
                    m.sender === "user"
                      ? "bg-cyan-500 text-[#090d16] font-medium rounded-br-none"
                      : "bg-[#0a0e1a] border border-[#1e293b] text-slate-200 rounded-bl-none space-y-3"
                  }`}
                >
                  <div className="whitespace-pre-wrap">{m.text}</div>

                  {m.patch && (
                    <div className="mt-2 pt-2 border-t border-slate-800">
                      <div className="flex items-center justify-between mb-1 text-[11px] font-mono text-cyan-400 font-bold">
                        <span>Generated Hardening Patch:</span>
                        <button
                          onClick={() => navigator.clipboard.writeText(m.patch || "")}
                          className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-white"
                        >
                          <Copy className="w-3 h-3" />
                          <span>Copy</span>
                        </button>
                      </div>
                      <pre className="p-3 bg-[#080b12] rounded-xl text-[11px] font-mono text-emerald-300 border border-slate-800 overflow-x-auto whitespace-pre-wrap">
                        {m.patch}
                      </pre>
                    </div>
                  )}
                </div>
                <span className="text-[10px] text-slate-500 mt-1 px-1">{m.timestamp}</span>
              </div>
            ))}
          </div>

          {/* Input Bar */}
          <div className="p-4 bg-[#0b0f19] border-t border-[#1e293b] flex items-center gap-3">
            <input
              type="text"
              placeholder={
                lang === "fa"
                  ? "سوال امنیتی خود را بپرسید یا درخواست تحلیل دهید..."
                  : "Ask a defensive security question, request remediation advice..."
              }
              value={inputQuery}
              onChange={(e) => setInputQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !loading && handleSendMessage()}
              className="flex-1 bg-[#0f1626] border border-[#1e293b] text-slate-200 text-xs rounded-xl px-4 py-2.5 focus:outline-none focus:border-cyan-500"
            />
            <button
              disabled={loading || !inputQuery.trim()}
              onClick={() => handleSendMessage()}
              className="px-5 py-2.5 bg-cyan-500 hover:bg-cyan-400 text-[#090d16] font-bold text-xs rounded-xl flex items-center gap-2 transition disabled:opacity-50"
            >
              {loading ? <RotateCw className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
              <span>Send</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
