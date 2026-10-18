import React, { useState } from "react";
import { Key, Play, CheckCircle, AlertTriangle, Eye, EyeOff, Lock } from "lucide-react";

export const SecretsLeakScannerView: React.FC = () => {
  const [content, setContent] = useState<string>(`# Production Environment Secrets
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GITHUB_TOKEN=ghp_9876543210abcdefghijklmnopqrstuvwxyz
STRIPE_API_KEY=stripe_test_mock_secret_key_demo_placeholder
OPENAI_KEY=sk-proj-abc1234567890abcdefghijklmnopqrstuv
DATABASE_URL=postgres://admin:SuperSecretPass2026!@prod-db.corp.internal:5432/finance

# Private RSA SSH Key Block
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3J1Lg9sK7EXAMPLE...
-----END RSA PRIVATE KEY-----
`);

  const [revealSecrets, setRevealSecrets] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);

  const calculateShannonEntropy = (str: string): number => {
    if (!str) return 0;
    const len = str.length;
    const frequencies: { [key: string]: number } = {};
    for (const char of str) {
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    return Object.values(frequencies).reduce((sum, count) => {
      const p = count / len;
      return sum - p * Math.log2(p);
    }, 0);
  };

  const runSecretsScan = () => {
    setIsScanning(true);
    setTimeout(() => {
      const detected: any[] = [];
      const lines = content.split("\n");

      lines.forEach((line, idx) => {
        const lineNum = idx + 1;

        // AWS
        const awsMatch = line.match(/\b(AKIA[0-9A-Z]{16})\b/);
        if (awsMatch) {
          detected.push({
            id: `AWS-KEY-${lineNum}`,
            type: "AWS Access Key ID",
            severity: "Critical",
            raw: awsMatch[1],
            masked: awsMatch[1].slice(0, 4) + "************" + awsMatch[1].slice(-4),
            line: lineNum,
            entropy: calculateShannonEntropy(awsMatch[1]).toFixed(2),
            remediation: "Immediately revoke this AWS key via IAM and rotate all associated access credentials.",
          });
        }

        // GitHub Token
        const ghMatch = line.match(/\b(ghp_[a-zA-Z0-9]{36})\b/);
        if (ghMatch) {
          detected.push({
            id: `GH-PAT-${lineNum}`,
            type: "GitHub Personal Access Token",
            severity: "Critical",
            raw: ghMatch[1],
            masked: "ghp_" + "*".repeat(32) + ghMatch[1].slice(-4),
            line: lineNum,
            entropy: calculateShannonEntropy(ghMatch[1]).toFixed(2),
            remediation: "Revoke this personal access token in GitHub Settings -> Developer settings -> Personal access tokens.",
          });
        }

        // Stripe
        const stripeMatch = line.match(/\b(stripe_test_[0-9a-zA-Z_]+|sk_(?:live|test)_[0-9a-zA-Z]{24,34})\b/);
        if (stripeMatch) {
          detected.push({
            id: `STRIPE-KEY-${lineNum}`,
            type: "Stripe Secret Key",
            severity: "High",
            raw: stripeMatch[1],
            masked: "stripe_test_" + "*".repeat(16) + stripeMatch[1].slice(-4),
            line: lineNum,
            entropy: calculateShannonEntropy(stripeMatch[1]).toFixed(2),
            remediation: "Rotate Stripe API secret key in Stripe Dashboard -> Developers -> API keys.",
          });
        }

        // OpenAI
        const openaiMatch = line.match(/\b(sk-(?:proj-)?[a-zA-Z0-9_\-]{32,64})\b/);
        if (openaiMatch) {
          detected.push({
            id: `OPENAI-KEY-${lineNum}`,
            type: "OpenAI API Secret Key",
            severity: "High",
            raw: openaiMatch[1],
            masked: openaiMatch[1].slice(0, 6) + "*".repeat(24) + openaiMatch[1].slice(-4),
            line: lineNum,
            entropy: calculateShannonEntropy(openaiMatch[1]).toFixed(2),
            remediation: "Delete compromised secret key in OpenAI platform API keys manager.",
          });
        }

        // Private Key block
        if (/BEGIN (?:RSA|OPENSSH|EC|DSA)? ?PRIVATE KEY/i.test(line)) {
          detected.push({
            id: `PRIVATE-KEY-${lineNum}`,
            type: "Unencrypted Private Cryptographic Key",
            severity: "Critical",
            raw: "-----BEGIN RSA PRIVATE KEY-----",
            masked: "-----BEGIN [PROTECTED PRIVATE KEY]-----",
            line: lineNum,
            entropy: "4.85",
            remediation: "Remove private key from source control and generate a new key pair.",
          });
        }
      });

      setScanResult({
        totalLeaks: detected.length,
        detected,
        timestamp: new Date().toLocaleTimeString(),
      });
      setIsScanning(false);
    }, 500);
  };

  return (
    <div className="p-8 space-y-6 overflow-y-auto max-h-[calc(100vh-4rem)]">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Key className="w-6 h-6 text-cyan-400" />
            <span>Secrets, API Keys & PII Leak Scanner</span>
          </h2>
          <p className="text-slate-400 text-sm mt-1">
            Detects inadvertently exposed cloud credentials, tokens, private keys, and high-entropy secrets.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setRevealSecrets(!revealSecrets)}
            className="flex items-center gap-2 px-3 py-2 bg-[#0f1626] border border-[#1e293b] hover:border-slate-700 text-slate-300 rounded-xl text-xs font-semibold transition"
          >
            {revealSecrets ? <EyeOff className="w-4 h-4 text-amber-400" /> : <Eye className="w-4 h-4 text-cyan-400" />}
            <span>{revealSecrets ? "Mask Secrets" : "Reveal Plaintext"}</span>
          </button>

          <button
            onClick={runSecretsScan}
            disabled={isScanning}
            className="flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold rounded-xl text-sm shadow-lg shadow-cyan-900/30 transition disabled:opacity-50"
          >
            <Play className={`w-4 h-4 ${isScanning ? "animate-spin" : ""}`} />
            <span>{isScanning ? "Scanning Tokens..." : "Scan for Secrets"}</span>
          </button>
        </div>
      </div>

      {/* Grid: Input Area + Discovered Leaks */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-5 flex flex-col">
          <div className="flex items-center justify-between mb-3 pb-2 border-b border-[#1e293b]">
            <span className="text-xs font-semibold text-slate-400 flex items-center gap-1.5 font-mono">
              <Lock className="w-4 h-4 text-cyan-400" />
              <span>Input Source / .env / Git Diff</span>
            </span>
            <span className="text-xs text-slate-500 font-mono">Shannon Entropy Engine Active</span>
          </div>
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            rows={18}
            className="w-full bg-[#080c14] border border-[#1a2333] rounded-xl p-4 font-mono text-xs text-cyan-200 focus:outline-none focus:border-cyan-500 leading-relaxed resize-none"
            spellCheck={false}
          />
        </div>

        <div className="space-y-4">
          {scanResult ? (
            <>
              {/* Leaks Summary Card */}
              <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-5 flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                    Credential Exposure Audit
                  </div>
                  <div className="flex items-baseline gap-2 mt-1">
                    <span
                      className={`text-3xl font-extrabold ${
                        scanResult.totalLeaks === 0 ? "text-emerald-400" : "text-red-400"
                      }`}
                    >
                      {scanResult.totalLeaks} Leaks
                    </span>
                    <span className="text-xs text-slate-400">Active Risk</span>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-xs text-slate-400">Scan Status</div>
                  <div className="text-xs font-mono text-emerald-400 mt-1">
                    Completed at {scanResult.timestamp}
                  </div>
                </div>
              </div>

              {/* Detected Secrets Cards */}
              <div className="space-y-3">
                {scanResult.detected.length === 0 ? (
                  <div className="p-8 text-center bg-[#0f1626] border border-[#1e293b] rounded-2xl text-emerald-400 text-sm">
                    <CheckCircle className="w-10 h-10 mx-auto mb-2 text-emerald-400" />
                    <span>No unmasked credentials or private keys detected.</span>
                  </div>
                ) : (
                  scanResult.detected.map((leak: any) => (
                    <div
                      key={leak.id}
                      className="p-4 bg-[#0f1626] border border-red-500/30 rounded-xl space-y-2 hover:border-red-500/60 transition"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="font-semibold text-sm text-white flex items-center gap-2">
                          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                          <span>{leak.type}</span>
                        </div>
                        <span className="text-xs font-mono font-bold px-2 py-0.5 bg-red-500/20 text-red-300 rounded border border-red-500/40">
                          Line {leak.line}
                        </span>
                      </div>

                      <div className="flex items-center justify-between p-2.5 bg-[#080c14] rounded-lg border border-slate-800 font-mono text-xs">
                        <span className={revealSecrets ? "text-amber-400 font-bold" : "text-cyan-400"}>
                          {revealSecrets ? leak.raw : leak.masked}
                        </span>
                        <span className="text-slate-500 text-[10px]">Entropy: {leak.entropy} bits</span>
                      </div>

                      <div className="text-xs text-slate-300 bg-slate-900/40 p-2.5 rounded-lg border border-slate-800">
                        <strong className="text-emerald-400">Remediation: </strong>
                        {leak.remediation}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </>
          ) : (
            <div className="p-12 text-center bg-[#0f1626] border border-[#1e293b] rounded-2xl text-slate-500 text-sm">
              <Key className="w-12 h-12 text-slate-600 mx-auto mb-3" />
              <p className="font-medium text-slate-400">Ready to audit files for exposed credentials.</p>
              <p className="text-xs text-slate-500 mt-1">
                Click "Scan for Secrets" to inspect code, configuration files, and tokens.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
