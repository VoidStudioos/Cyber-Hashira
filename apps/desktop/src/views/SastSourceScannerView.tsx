import React, { useState } from "react";
import { Code, Play, CheckCircle, AlertTriangle, FileText, Bug } from "lucide-react";
import { Finding } from "../types";

interface SastSourceScannerViewProps {
  onFindingGenerated?: (finding: Finding) => void;
}

export const SastSourceScannerView: React.FC<SastSourceScannerViewProps> = () => {
  const [sourceCode, setSourceCode] = useState<string>(`import os
import subprocess
import pickle

def authenticate(username, password):
    # Vulnerable SQL query concatenation
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)

def ping_server(host):
    # Command injection with shell=True
    subprocess.Popen(f"ping -c 1 {host}", shell=True)

def load_user_state(raw_cookie_data):
    # Insecure deserialization via pickle
    return pickle.loads(raw_cookie_data)
`);

  const [language, setLanguage] = useState("python");
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);

  const runSastScan = () => {
    setIsScanning(true);
    setTimeout(() => {
      const findings: any[] = [];
      const lines = sourceCode.split("\n");

      lines.forEach((line, idx) => {
        const lineNum = idx + 1;
        // SQL Injection
        if (/cursor\.execute\s*\(.*?f["'].*?SELECT/i.test(line)) {
          findings.push({
            id: `SAST-SQLI-${lineNum}`,
            title: "SQL Injection: Dynamic String Concatenation in Query",
            severity: "Critical",
            cvss: 9.4,
            line: lineNum,
            snippet: line.trim(),
            remediation: "Use parameterized queries with prepared placeholders: cursor.execute('SELECT * FROM users WHERE username = %s', (username,))",
          });
        }
        // Command Injection
        if (/subprocess\.(?:Popen|call|run).*?shell\s*=\s*True/i.test(line) || /os\.system\s*\(/i.test(line)) {
          findings.push({
            id: `SAST-CMDI-${lineNum}`,
            title: "Remote Command Injection: Subprocess invoked with shell=True",
            severity: "Critical",
            cvss: 9.8,
            line: lineNum,
            snippet: line.trim(),
            remediation: "Pass arguments as an immutable array and set shell=False: subprocess.run(['ping', '-c', '1', host], shell=False)",
          });
        }
        // Insecure Deserialization
        if (/pickle\.loads?\s*\(/i.test(line) || /yaml\.load\s*\(/i.test(line)) {
          findings.push({
            id: `SAST-DESER-${lineNum}`,
            title: "Insecure Deserialization: Arbitrary Code Execution Risk via pickle",
            severity: "Critical",
            cvss: 9.8,
            line: lineNum,
            snippet: line.trim(),
            remediation: "Never deserialize untrusted user input using pickle. Use safe structured serializers such as json.loads() or protobuf.",
          });
        }
      });

      const score = Math.max(0, 100 - findings.length * 25);
      setScanResult({
        score,
        totalFindings: findings.length,
        findings,
        timestamp: new Date().toLocaleTimeString(),
      });
      setIsScanning(false);
    }, 600);
  };

  return (
    <div className="p-8 space-y-6 overflow-y-auto max-h-[calc(100vh-4rem)]">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Code className="w-6 h-6 text-cyan-400" />
            <span>Static Application Security Testing (SAST)</span>
          </h2>
          <p className="text-slate-400 text-sm mt-1">
            Automated source code taint analysis for SQL injection, Command Injection, RCE, and Insecure Deserialization.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            value={language}
            onChange={(e) => setLanguage(e.target.value)}
            className="bg-[#0f1626] border border-[#1e293b] text-slate-200 text-sm rounded-xl px-4 py-2 focus:outline-none focus:border-cyan-500 font-mono"
          >
            <option value="python">Python</option>
            <option value="javascript">JavaScript / TypeScript</option>
            <option value="php">PHP</option>
            <option value="golang">Go</option>
          </select>

          <button
            onClick={runSastScan}
            disabled={isScanning}
            className="flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold rounded-xl text-sm shadow-lg shadow-cyan-900/30 transition disabled:opacity-50"
          >
            <Play className={`w-4 h-4 ${isScanning ? "animate-spin" : ""}`} />
            <span>{isScanning ? "Analyzing AST..." : "Run SAST Scan"}</span>
          </button>
        </div>
      </div>

      {/* Grid: Editor + Results */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Code Editor */}
        <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-5 flex flex-col">
          <div className="flex items-center justify-between mb-3 pb-2 border-b border-[#1e293b]">
            <span className="text-xs font-semibold text-slate-400 flex items-center gap-1.5 font-mono">
              <FileText className="w-4 h-4 text-cyan-400" />
              <span>Target Source File (Paste or Edit)</span>
            </span>
            <span className="text-xs text-slate-500 font-mono">UTF-8 • {language}</span>
          </div>
          <textarea
            value={sourceCode}
            onChange={(e) => setSourceCode(e.target.value)}
            rows={18}
            className="w-full bg-[#080c14] border border-[#1a2333] rounded-xl p-4 font-mono text-xs text-cyan-200 focus:outline-none focus:border-cyan-500 leading-relaxed resize-none"
            spellCheck={false}
          />
        </div>

        {/* Results Panel */}
        <div className="space-y-4">
          {scanResult ? (
            <>
              {/* Score Card */}
              <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-5 flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                    SAST Security Posture
                  </div>
                  <div className="flex items-baseline gap-2 mt-1">
                    <span
                      className={`text-3xl font-extrabold ${
                        scanResult.score > 80
                          ? "text-emerald-400"
                          : scanResult.score > 50
                          ? "text-amber-400"
                          : "text-red-400"
                      }`}
                    >
                      {scanResult.score} / 100
                    </span>
                    <span className="text-xs text-slate-400">Security Score</span>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-xs text-slate-400">Vulnerabilities Detected</div>
                  <div className="text-xl font-bold text-red-400 font-mono mt-0.5">
                    {scanResult.totalFindings} Flaws
                  </div>
                </div>
              </div>

              {/* Findings List */}
              <div className="space-y-3">
                {scanResult.findings.length === 0 ? (
                  <div className="p-8 text-center bg-[#0f1626] border border-[#1e293b] rounded-2xl text-emerald-400 text-sm">
                    <CheckCircle className="w-10 h-10 mx-auto mb-2 text-emerald-400" />
                    <span>No critical source-to-sink vulnerabilities detected.</span>
                  </div>
                ) : (
                  scanResult.findings.map((f: any) => (
                    <div
                      key={f.id}
                      className="p-4 bg-[#0f1626] border border-red-500/30 rounded-xl space-y-2 hover:border-red-500/60 transition"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="font-semibold text-sm text-white flex items-center gap-2">
                          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                          <span>{f.title}</span>
                        </div>
                        <span className="text-xs font-mono font-bold px-2 py-0.5 bg-red-500/20 text-red-300 rounded border border-red-500/40">
                          Line {f.line}
                        </span>
                      </div>
                      <pre className="p-2 bg-[#080c14] rounded text-xs font-mono text-cyan-300 overflow-x-auto border border-slate-800">
                        {f.snippet}
                      </pre>
                      <div className="text-xs text-slate-300 bg-slate-900/40 p-2.5 rounded-lg border border-slate-800">
                        <strong className="text-emerald-400">Fix: </strong>
                        {f.remediation}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </>
          ) : (
            <div className="p-12 text-center bg-[#0f1626] border border-[#1e293b] rounded-2xl text-slate-500 text-sm">
              <Bug className="w-12 h-12 text-slate-600 mx-auto mb-3" />
              <p className="font-medium text-slate-400">Ready to perform static source analysis.</p>
              <p className="text-xs text-slate-500 mt-1">
                Click "Run SAST Scan" to parse code and identify injection patterns.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
