import React, { useState } from "react";
import {
  Globe,
  Radio,
  RotateCw,
  Binary,
  Send,
  Sliders,
  Copy,
  Layers,
  Bug,
} from "lucide-react";
import { Finding, Project, Target } from "../types";

interface WebSecurityViewProps {
  activeProject: Project | null;
  targets: Target[];
  onRunTask: (moduleId: string, target: string, options: any) => Promise<any>;
  onRefreshFindings?: () => void;
}

interface CapturedRequest {
  id: string;
  method: string;
  url: string;
  status: number;
  timeMs: number;
  reqHeaders: Record<string, string>;
  reqBody: string;
  respHeaders: Record<string, string>;
  respBody: string;
}

export const WebSecurityView: React.FC<WebSecurityViewProps> = ({
  onRunTask,
  onRefreshFindings,
}) => {
  const [activeTab, setActiveTab] = useState<"history" | "repeater" | "decoder">("history");

  // Proxy state
  const [proxyActive, setProxyActive] = useState(true);
  const [proxyPort] = useState(8080);
  const [interceptEnabled, setInterceptEnabled] = useState(false);

  // History state
  const [history] = useState<CapturedRequest[]>([
    {
      id: "req-1",
      method: "GET",
      url: "https://example.com/api/v1/user",
      status: 200,
      timeMs: 142,
      reqHeaders: {
        Host: "example.com",
        "User-Agent": "CyberHashira/0.1.0",
        Accept: "application/json",
      },
      reqBody: "",
      respHeaders: {
        "Content-Type": "application/json; charset=utf-8",
        Server: "nginx/1.24.0",
        "Set-Cookie": "auth_token=abc123xyz; Path=/",
      },
      respBody: '{\n  "status": "authenticated",\n  "user_id": 4921,\n  "role": "auditor"\n}',
    },
    {
      id: "req-2",
      method: "POST",
      url: "https://example.com/api/v1/auth/login",
      status: 401,
      timeMs: 98,
      reqHeaders: {
        Host: "example.com",
        "Content-Type": "application/json",
      },
      reqBody: '{"username": "test_account", "password": "•••"}',
      respHeaders: {
        "Content-Type": "application/json",
        "X-Frame-Options": "DENY",
      },
      respBody: '{\n  "error": "invalid_credentials"\n}',
    },
  ]);
  const [selectedReq, setSelectedReq] = useState<CapturedRequest | null>(history[0]);

  // Repeater state
  const [repMethod, setRepMethod] = useState("GET");
  const [repUrl, setRepUrl] = useState("https://example.com/api/v1/status");
  const [repHeaders, setRepHeaders] = useState("Host: example.com\nUser-Agent: CyberHashira-Repeater/1.0\nAccept: */*");
  const [repBody, setRepBody] = useState("");
  const [repLoading, setRepLoading] = useState(false);
  const [repResponse, setRepResponse] = useState<any | null>(null);
  const [repFindings, setRepFindings] = useState<Finding[]>([]);
  const [repError, setRepError] = useState<string | null>(null);

  // Decoder state
  const [decodeInput, setDecodeInput] = useState("");
  const [decodeOutput, setDecodeOutput] = useState("");

  // Send request from History to Repeater
  const sendToRepeater = (req: CapturedRequest) => {
    setRepMethod(req.method);
    setRepUrl(req.url);
    const hStr = Object.entries(req.reqHeaders)
      .map(([k, v]) => `${k}: ${v}`)
      .join("\n");
    setRepHeaders(hStr);
    setRepBody(req.reqBody);
    setActiveTab("repeater");
  };

  // Execute Repeater Request
  const handleRepeaterSend = async () => {
    if (!repUrl.trim()) return;
    setRepLoading(true);
    setRepError(null);
    setRepResponse(null);
    setRepFindings([]);

    try {
      // Parse header string
      const headersObj: Record<string, string> = {};
      repHeaders.split("\n").forEach((line) => {
        const colonIdx = line.indexOf(":");
        if (colonIdx > 0) {
          const k = line.slice(0, colonIdx).trim();
          const v = line.slice(colonIdx + 1).trim();
          if (k) headersObj[k] = v;
        }
      });

      const res = await onRunTask("web-security", repUrl, {
        action: "repeater",
        repeater_request: {
          method: repMethod,
          url: repUrl,
          headers: headersObj,
          body: repBody,
        },
      });

      if (res && res.payload) {
        setRepResponse({
          raw_output: res.payload.raw_output,
          success: res.payload.success,
        });
        if (res.payload.findings) {
          setRepFindings(res.payload.findings);
        }
      }
      if (onRefreshFindings) onRefreshFindings();
    } catch (e: any) {
      setRepError(e?.message || String(e));
    } finally {
      setRepLoading(false);
    }
  };

  // Decoder transformations
  const handleUrlEncode = () => setDecodeOutput(encodeURIComponent(decodeInput));
  const handleUrlDecode = () => {
    try {
      setDecodeOutput(decodeURIComponent(decodeInput));
    } catch {
      setDecodeOutput("Error: Invalid URL encoded string");
    }
  };

  const handleBase64Encode = () => {
    try {
      setDecodeOutput(btoa(decodeInput));
    } catch {
      setDecodeOutput("Error: String contains characters outside Latin1");
    }
  };

  const handleBase64Decode = () => {
    try {
      setDecodeOutput(atob(decodeInput.trim()));
    } catch {
      setDecodeOutput("Error: Invalid Base64 payload");
    }
  };

  const handleHexEncode = () => {
    let hex = "";
    for (let i = 0; i < decodeInput.length; i++) {
      hex += decodeInput.charCodeAt(i).toString(16).padStart(2, "0") + " ";
    }
    setDecodeOutput(hex.trim());
  };

  const handleJwtDecode = () => {
    try {
      const parts = decodeInput.trim().split(".");
      if (parts.length < 2) {
        setDecodeOutput("Error: Not a valid 3-part JWT token");
        return;
      }
      const header = JSON.parse(atob(parts[0]));
      const payload = JSON.parse(atob(parts[1]));
      setDecodeOutput(
        `=== JWT HEADER ===\n${JSON.stringify(header, null, 2)}\n\n=== JWT PAYLOAD ===\n${JSON.stringify(
          payload,
          null,
          2
        )}`
      );
    } catch (e: any) {
      setDecodeOutput(`Error decoding JWT: ${e.message}`);
    }
  };

  return (
    <div className="p-8 space-y-6 overflow-y-auto max-h-[calc(100vh-4rem)]">
      {/* Top Bar with Tabs and Proxy Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[#1e293b]">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Globe className="w-6 h-6 text-cyan-400" />
            <span>Web Security Workspace</span>
          </h2>
          <p className="text-slate-400 text-sm mt-1">
            HTTP/HTTPS intercepting proxy, Repeater, Decoder, and passive vulnerability analysis.
          </p>
        </div>

        {/* Proxy Status Pill & Controls */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-[#0f1626] border border-[#1e293b] px-3 py-1.5 rounded-xl text-xs font-mono">
            <Radio
              className={`w-3.5 h-3.5 ${
                proxyActive ? "text-emerald-400 animate-pulse" : "text-slate-500"
              }`}
            />
            <span className="text-slate-400">Proxy:</span>
            <span className="text-slate-200">127.0.0.1:{proxyPort}</span>
            <button
              onClick={() => setProxyActive(!proxyActive)}
              className={`ml-2 px-2 py-0.5 rounded text-[10px] font-bold uppercase transition ${
                proxyActive
                  ? "bg-emerald-500/20 text-emerald-400 hover:bg-emerald-500/30"
                  : "bg-slate-700 text-slate-300 hover:bg-slate-600"
              }`}
            >
              {proxyActive ? "Running" : "Stopped"}
            </button>
          </div>

          <button
            onClick={() => setInterceptEnabled(!interceptEnabled)}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition ${
              interceptEnabled
                ? "bg-cyan-500 text-[#090d16] shadow-md shadow-cyan-500/20"
                : "bg-[#0f1626] text-slate-300 hover:bg-slate-800 border border-[#1e293b]"
            }`}
          >
            <Sliders className="w-3.5 h-3.5" />
            <span>Intercept: {interceptEnabled ? "ON" : "OFF"}</span>
          </button>
        </div>
      </div>

      {/* Workspace Tabs Navigation */}
      <div className="flex items-center gap-2 border-b border-[#1e293b] pb-2">
        <button
          onClick={() => setActiveTab("history")}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition flex items-center gap-2 ${
            activeTab === "history"
              ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/30"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
          }`}
        >
          <Layers className="w-4 h-4" />
          <span>HTTP History & Inspector</span>
          <span className="bg-cyan-950 text-cyan-300 text-[10px] px-1.5 py-0.2 rounded font-mono">
            {history.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab("repeater")}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition flex items-center gap-2 ${
            activeTab === "repeater"
              ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/30"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
          }`}
        >
          <Send className="w-4 h-4" />
          <span>HTTP Repeater</span>
        </button>

        <button
          onClick={() => setActiveTab("decoder")}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition flex items-center gap-2 ${
            activeTab === "decoder"
              ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/30"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
          }`}
        >
          <Binary className="w-4 h-4" />
          <span>Decoder / Encoder & JWT</span>
        </button>
      </div>

      {/* TAB 1: HTTP HISTORY & INSPECTOR */}
      {activeTab === "history" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Left: Request History Table */}
          <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-4 flex flex-col h-[560px]">
            <h3 className="text-sm font-semibold text-white mb-3">Captured HTTP Traffic</h3>
            <div className="flex-1 overflow-y-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#0b0f19] text-slate-400 border-b border-[#1e293b] sticky top-0">
                  <tr>
                    <th className="py-2.5 px-3">Method</th>
                    <th className="py-2.5 px-3">URL</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3">Time</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e293b]">
                  {history.map((req) => (
                    <tr
                      key={req.id}
                      onClick={() => setSelectedReq(req)}
                      className={`cursor-pointer transition ${
                        selectedReq?.id === req.id
                          ? "bg-cyan-500/10 text-cyan-300"
                          : "hover:bg-slate-800/30 text-slate-300"
                      }`}
                    >
                      <td className="py-2 px-3 font-bold text-cyan-400">{req.method}</td>
                      <td className="py-2 px-3 truncate max-w-[200px]">{req.url}</td>
                      <td className="py-2 px-3">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] ${
                            req.status < 300
                              ? "bg-emerald-500/10 text-emerald-400"
                              : req.status < 400
                              ? "bg-blue-500/10 text-blue-400"
                              : "bg-red-500/10 text-red-400"
                          }`}
                        >
                          {req.status}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-slate-500">{req.timeMs}ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Right: Request & Response Inspector */}
          {selectedReq ? (
            <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-5 flex flex-col h-[560px] space-y-4">
              <div className="flex items-center justify-between border-b border-[#1e293b] pb-3">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold bg-cyan-500/20 text-cyan-400 px-2 py-0.5 rounded font-mono">
                    {selectedReq.method}
                  </span>
                  <span className="text-xs font-mono text-slate-200 truncate max-w-sm">
                    {selectedReq.url}
                  </span>
                </div>
                <button
                  onClick={() => sendToRepeater(selectedReq)}
                  className="px-3 py-1 bg-cyan-500 hover:bg-cyan-400 text-[#090d16] font-bold text-xs rounded-lg flex items-center gap-1.5 transition"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>To Repeater</span>
                </button>
              </div>

              {/* Inspector Content */}
              <div className="flex-1 grid grid-cols-2 gap-4 overflow-hidden">
                {/* Request View */}
                <div className="flex flex-col overflow-hidden bg-[#0a0e1a] border border-[#1e293b] rounded-xl p-3">
                  <span className="text-[11px] font-semibold uppercase text-slate-400 tracking-wider mb-2">
                    Request Headers & Body
                  </span>
                  <pre className="flex-1 overflow-y-auto text-xs font-mono text-slate-300 whitespace-pre-wrap">
                    {Object.entries(selectedReq.reqHeaders)
                      .map(([k, v]) => `${k}: ${v}`)
                      .join("\n")}
                    {"\n\n"}
                    {selectedReq.reqBody}
                  </pre>
                </div>

                {/* Response View */}
                <div className="flex flex-col overflow-hidden bg-[#0a0e1a] border border-[#1e293b] rounded-xl p-3">
                  <span className="text-[11px] font-semibold uppercase text-slate-400 tracking-wider mb-2">
                    Response Headers & Body ({selectedReq.status})
                  </span>
                  <pre className="flex-1 overflow-y-auto text-xs font-mono text-slate-300 whitespace-pre-wrap">
                    {Object.entries(selectedReq.respHeaders)
                      .map(([k, v]) => `${k}: ${v}`)
                      .join("\n")}
                    {"\n\n"}
                    {selectedReq.respBody}
                  </pre>
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl flex items-center justify-center text-slate-500 text-sm">
              Select an item from HTTP history to inspect
            </div>
          )}
        </div>
      )}

      {/* TAB 2: HTTP REPEATER */}
      {activeTab === "repeater" && (
        <div className="space-y-4">
          {/* Target URL & Send Controls */}
          <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-4 flex flex-col md:flex-row items-center gap-3">
            <select
              value={repMethod}
              onChange={(e) => setRepMethod(e.target.value)}
              className="bg-[#0b0f19] border border-[#1e293b] text-cyan-400 font-bold text-sm rounded-xl px-3 py-2 font-mono focus:outline-none focus:border-cyan-500"
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
              <option value="PATCH">PATCH</option>
              <option value="OPTIONS">OPTIONS</option>
              <option value="HEAD">HEAD</option>
            </select>

            <input
              type="text"
              value={repUrl}
              onChange={(e) => setRepUrl(e.target.value)}
              placeholder="https://example.com/api/v1/..."
              className="flex-1 bg-[#0b0f19] border border-[#1e293b] text-slate-200 text-sm rounded-xl px-4 py-2 font-mono focus:outline-none focus:border-cyan-500"
            />

            <button
              disabled={repLoading}
              onClick={handleRepeaterSend}
              className="px-6 py-2 bg-cyan-500 hover:bg-cyan-400 text-[#090d16] font-bold text-sm rounded-xl flex items-center gap-2 transition shadow-lg shadow-cyan-500/20"
            >
              {repLoading ? (
                <RotateCw className="w-4 h-4 animate-spin" />
              ) : (
                <Send className="w-4 h-4" />
              )}
              <span>{repLoading ? "Dispatching..." : "Send"}</span>
            </button>
          </div>

          {repError && (
            <div className="p-3 bg-red-500/10 border border-red-500/30 text-red-400 text-xs rounded-xl">
              {repError}
            </div>
          )}

          {/* Request / Response Split Editors */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Request Editor */}
            <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-5 flex flex-col h-[480px] space-y-3">
              <span className="text-xs font-semibold uppercase text-slate-400 tracking-wider">
                Request Headers
              </span>
              <textarea
                value={repHeaders}
                onChange={(e) => setRepHeaders(e.target.value)}
                rows={5}
                className="w-full bg-[#0a0e1a] border border-[#1e293b] rounded-xl p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
              />

              <span className="text-xs font-semibold uppercase text-slate-400 tracking-wider">
                Request Body (Raw Payload)
              </span>
              <textarea
                value={repBody}
                onChange={(e) => setRepBody(e.target.value)}
                placeholder="Request body (JSON, form data, XML)..."
                className="flex-1 w-full bg-[#0a0e1a] border border-[#1e293b] rounded-xl p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 resize-none"
              />
            </div>

            {/* Response Viewer */}
            <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-5 flex flex-col h-[480px]">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-semibold uppercase text-slate-400 tracking-wider">
                  Response Telemetry
                </span>
                {repFindings.length > 0 && (
                  <span className="text-xs font-semibold bg-amber-500/20 text-amber-400 border border-amber-500/40 px-2 py-0.5 rounded-full flex items-center gap-1">
                    <Bug className="w-3 h-3" />
                    <span>{repFindings.length} Passive Findings</span>
                  </span>
                )}
              </div>

              {repResponse ? (
                <div className="flex-1 flex flex-col overflow-hidden space-y-3">
                  <pre className="flex-1 p-4 bg-[#0a0e1a] border border-[#1e293b] rounded-xl text-xs font-mono text-slate-200 overflow-y-auto whitespace-pre-wrap">
                    {repResponse.raw_output}
                  </pre>

                  {repFindings.length > 0 && (
                    <div className="p-3 bg-amber-950/20 border border-amber-900/40 rounded-xl space-y-1">
                      <span className="text-[11px] font-semibold text-amber-400 block">
                        Passive Vulnerabilities Identified in Response:
                      </span>
                      <div className="space-y-1">
                        {repFindings.map((f, i) => (
                          <div key={i} className="text-xs text-slate-300 flex items-center gap-2">
                            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-400">
                              {f.severity}
                            </span>
                            <span>{f.title}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="flex-1 flex items-center justify-center text-slate-500 text-sm">
                  Click 'Send' to dispatch request and inspect server response
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: DECODER / ENCODER & JWT */}
      {activeTab === "decoder" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Input Panel */}
          <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-5 flex flex-col h-[520px] space-y-3">
            <span className="text-xs font-semibold uppercase text-slate-400 tracking-wider">
              Input Text / Raw Token
            </span>
            <textarea
              value={decodeInput}
              onChange={(e) => setDecodeInput(e.target.value)}
              placeholder="Paste raw text, Base64 string, URL-encoded string, or JWT token..."
              className="flex-1 w-full bg-[#0a0e1a] border border-[#1e293b] rounded-xl p-4 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 resize-none"
            />

            {/* Transform Action Buttons */}
            <div className="flex flex-wrap gap-2 pt-2">
              <button
                onClick={handleUrlDecode}
                className="px-3 py-1.5 bg-[#0b0f19] hover:bg-slate-800 text-cyan-400 text-xs font-semibold rounded-lg border border-[#1e293b] transition"
              >
                URL Decode
              </button>
              <button
                onClick={handleUrlEncode}
                className="px-3 py-1.5 bg-[#0b0f19] hover:bg-slate-800 text-slate-300 text-xs font-semibold rounded-lg border border-[#1e293b] transition"
              >
                URL Encode
              </button>
              <button
                onClick={handleBase64Decode}
                className="px-3 py-1.5 bg-[#0b0f19] hover:bg-slate-800 text-cyan-400 text-xs font-semibold rounded-lg border border-[#1e293b] transition"
              >
                Base64 Decode
              </button>
              <button
                onClick={handleBase64Encode}
                className="px-3 py-1.5 bg-[#0b0f19] hover:bg-slate-800 text-slate-300 text-xs font-semibold rounded-lg border border-[#1e293b] transition"
              >
                Base64 Encode
              </button>
              <button
                onClick={handleHexEncode}
                className="px-3 py-1.5 bg-[#0b0f19] hover:bg-slate-800 text-slate-300 text-xs font-semibold rounded-lg border border-[#1e293b] transition"
              >
                Hex Encode
              </button>
              <button
                onClick={handleJwtDecode}
                className="px-3 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-[#090d16] text-xs font-bold rounded-lg transition"
              >
                Decode JWT Token
              </button>
            </div>
          </div>

          {/* Output Panel */}
          <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-5 flex flex-col h-[520px] space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase text-slate-400 tracking-wider">
                Transformed Output
              </span>
              {decodeOutput && (
                <button
                  onClick={() => navigator.clipboard.writeText(decodeOutput)}
                  className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                >
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy</span>
                </button>
              )}
            </div>

            <textarea
              readOnly
              value={decodeOutput}
              placeholder="Transformation result will appear here..."
              className="flex-1 w-full bg-[#0a0e1a] border border-[#1e293b] rounded-xl p-4 text-xs font-mono text-cyan-300 focus:outline-none resize-none"
            />
          </div>
        </div>
      )}
    </div>
  );
};
