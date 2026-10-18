#!/usr/bin/env python3
"""
Cyber Hashira - Static Application Security Testing (SAST) Scanner
Features:
  - Source-code static analysis (Python, JavaScript/TypeScript, PHP, Go)
  - Detects dangerous source-to-sink patterns:
      * SQL Injection: Dynamic concatenation in database queries (cursor.execute(f"..."), query("... " + input))
      * Command Injection: Unsafe shell execution (os.system, subprocess with shell=True, child_process.exec)
      * Remote Code Execution: Dynamic code evaluation (eval(), exec())
      * Insecure Deserialization: Arbitrary object instantiation (pickle.loads, yaml.load without SafeLoader, PHP unserialize)
      * Path Traversal: Unsanitized file system operations (open(user_path), fs.readFile(req.query))
"""

import sys
import json
import uuid
import re
import datetime

SAST_RULES = [
    {
        "id": "SAST-SQLI-001",
        "title": "SQL Injection: Dynamic String Concatenation in Database Query",
        "severity": "critical",
        "cvss": 9.4,
        "pattern": r"(?:cursor\.execute|db\.query|\.rawQuery|mysqli_query)\s*\(\s*(?:f[\"'].*?\{|[\"'].*?\b(?:SELECT|INSERT|UPDATE|DELETE)\b.*?[\"']\s*\+)",
        "description": "SQL statement is constructed via dynamic string interpolation or concatenation. Untrusted input can alter query logic.",
        "remediation": "Use parameterized queries or prepared statements (e.g., cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)))"
    },
    {
        "id": "SAST-CMDI-001",
        "title": "Command Injection: Unsafe Subprocess Execution with shell=True",
        "severity": "critical",
        "cvss": 9.8,
        "pattern": r"subprocess\.(?:Popen|call|run|check_output)\s*\(.*?shell\s*=\s*True",
        "description": "Subprocess is invoked with shell=True, enabling OS command injection if command strings incorporate user-controlled data.",
        "remediation": "Pass arguments as an array with shell=False (e.g. subprocess.run(['/usr/bin/tool', arg], shell=False))."
    },
    {
        "id": "SAST-CMDI-002",
        "title": "Command Injection: Raw Operating System Call (os.system / child_process.exec)",
        "severity": "critical",
        "cvss": 9.8,
        "pattern": r"\b(?:os\.system|os\.popen|child_process\.exec|shell_exec|system|passthru)\s*\(",
        "description": "Spawns a shell directly. Any unsanitized parameter can break out of intended commands via command separators (; , && , |).",
        "remediation": "Use explicit argument array execution APIs without shell invocation."
    },
    {
        "id": "SAST-EVAL-001",
        "title": "Remote Code Execution: Dynamic Evaluation via eval() / exec()",
        "severity": "critical",
        "cvss": 9.9,
        "pattern": r"\b(?:eval|exec)\s*\(",
        "description": "Executes dynamic strings as executable code in the current execution runtime context.",
        "remediation": "Eliminate eval() and exec(); parse data using standard serializers (JSON)."
    },
    {
        "id": "SAST-DESER-001",
        "title": "Insecure Deserialization: Unsafe Object Loading (pickle / yaml.load)",
        "severity": "critical",
        "cvss": 9.8,
        "pattern": r"\b(?:pickle\.loads?|yaml\.load\s*\([^,)]+\)|unserialize\s*\()",
        "description": "Deserializes arbitrary untrusted objects. In Python (pickle) and PHP, this allows arbitrary remote code execution via gadget chains.",
        "remediation": "Use safe serializers like json.loads() or yaml.safe_load()."
    },
    {
        "id": "SAST-TRAVERSAL-001",
        "title": "Path Traversal: Unsanitized File Access (open / fs.readFile)",
        "severity": "high",
        "cvss": 8.5,
        "pattern": r"(?:open|fs\.readFile|file_get_contents)\s*\(\s*(?:req|request|params|\$_GET|\$_POST)",
        "description": "File system access directly incorporates user-controlled request parameters without path canonicalization.",
        "remediation": "Canonicalize paths and verify they reside within an allowed directory using os.path.realpath and os.path.commonpath."
    }
]

class ScopeGuard:
    @staticmethod
    def is_authorized(target: str, authorized_targets: list) -> bool:
        if not target:
            return True
        clean_target = target.strip().lower()
        for auth in authorized_targets:
            if clean_target == auth.strip().lower() or clean_target.startswith(auth.strip().lower()):
                return True
        return False

def scan_code(source: str, file_name: str = "app.py") -> tuple:
    findings = []
    lines = source.splitlines()

    for rule in SAST_RULES:
        for idx, line in enumerate(lines, start=1):
            if re.search(rule["pattern"], line, re.IGNORECASE):
                findings.append({
                    "id": str(uuid.uuid4()),
                    "rule_id": rule["id"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "cvss_score": rule["cvss"],
                    "file": file_name,
                    "line": idx,
                    "snippet": line.strip()[:100],
                    "description": rule["description"],
                    "remediation": rule["remediation"]
                })

    score = 100
    for f in findings:
        if f["severity"] == "critical":
            score -= 25
        elif f["severity"] == "high":
            score -= 15
        else:
            score -= 10

    return findings, max(0, score)

def handle_execute(req):
    options = req.get("options", {})
    target = req.get("file_name") or req.get("target", "")
    authorized_targets = options.get("authorized_targets", [])

    if target and authorized_targets:
        if not ScopeGuard.is_authorized(target, authorized_targets):
            return {
                "status": "error",
                "code": "SCOPE_VIOLATION",
                "message": f"Target file '{target}' is not in authorized scope: {authorized_targets}"
            }

    source = req.get("source_code") or options.get("source_code", "")
    if not source:
        # Default test snippet exhibiting multiple vulnerabilities
        source = """
import os
import subprocess
import pickle

def login(user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)

def ping_host(host):
    subprocess.Popen(f"ping -c 1 {host}", shell=True)

def load_session(data):
    return pickle.loads(data)
        """

    findings, score = scan_code(source, target or "service.py")

    return {
        "status": "success",
        "result": {
            "scanned_file": target or "service.py",
            "sast_score": score,
            "vulnerabilities_detected": len(findings),
            "findings": findings,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
        }
    }

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as e:
            sys.stdout.write(json.dumps({"status": "error", "message": f"Malformed JSON: {e}"}) + "\n")
            sys.stdout.flush()
            continue

        req_type = req.get("type", "Execute")
        if req_type == "HealthCheck":
            res = {"status": "ok", "module": "sast-source-scanner", "version": "1.0.0"}
        else:
            res = handle_execute(req)

        sys.stdout.write(json.dumps(res) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()
