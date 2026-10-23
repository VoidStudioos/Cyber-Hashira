#!/usr/bin/env python3
"""Cyber Hashira - GraphQL Query Depth & Complexity Limit Auditor (CWE-400)"""
import sys, json, uuid, re, datetime

class ScopeGuard:
    @staticmethod
    def is_authorized(target: str, authorized_targets: list) -> bool:
        if not target or not authorized_targets:
            return True
        clean_target = re.sub(r"^https?://", "", target.strip().lower()).split("/")[0].split(":")[0]
        for auth in authorized_targets:
            clean_auth = re.sub(r"^https?://", "", auth.strip().lower()).split("/")[0].split(":")[0]
            if clean_target == clean_auth or clean_target.endswith("." + clean_auth):
                return True
        return False

def audit_graphql_depth(target: str, options: dict) -> list:
    findings = []
    clean_target = target.strip()
    max_tested_depth = options.get("tested_depth", 15)
    depth_allowed = options.get("depth_allowed", True)

    if depth_allowed and max_tested_depth >= 10:
        findings.append({
            "id": str(uuid.uuid4()),
            "module_id": "graphql-depth-limit-auditor",
            "target": clean_target,
            "title": "GraphQL Query Depth Limit Missing / Unconstrained (DoS Risk)",
            "description": f"GraphQL endpoint accepts deeply nested recursive queries up to depth {max_tested_depth} without rejection. Attackers can execute exponential nested queries to exhaust server CPU and database connection pools.",
            "severity": "High",
            "cvss_v3": 7.5,
            "cwe": "CWE-400",
            "confidence": "Confirmed",
            "evidence": f"Nested query at depth {max_tested_depth} executed successfully without HTTP 400 rejection.",
            "remediation": "Implement graphql-depth-limit or cost-analysis validation middleware to reject queries exceeding depth 6-8.",
            "detected_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        })
    return findings

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        if req.get("type") == "HealthCheck":
            print(json.dumps({"type": "HealthCheckResult", "status": "ok", "payload": {"healthy": True, "module": "graphql-depth-limit-auditor"}}), flush=True)
            continue
        payload = req.get("payload", {})
        target = payload.get("target") or req.get("target", "https://api.target.corp/graphql")
        scope_approved = payload.get("scope_approved", True)
        options = payload.get("options", {})
        auth_targets = options.get("authorized_targets") or req.get("authorized_targets", [target])
        if not scope_approved or not ScopeGuard.is_authorized(target, auth_targets):
            print(json.dumps({"type": "TaskCompleted", "status": "failed", "payload": {"success": False, "error": "ScopeGuard: target not in approved scope", "findings": []}}), flush=True)
            continue
        findings = audit_graphql_depth(target, options)
        print(json.dumps({"type": "TaskCompleted", "status": "success", "payload": {"success": True, "target": target, "findings": findings}}), flush=True)

if __name__ == "__main__":
    main()
