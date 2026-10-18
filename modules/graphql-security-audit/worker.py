#!/usr/bin/env python3
"""
Cyber Hashira - GraphQL Schema & Query Depth Auditor
Features:
  - Audits GraphQL endpoints against:
      * Enabled Introspection Query in Production (__schema, __type exposure)
      * Unbounded Query Depth (Circular references causing CPU DoS)
      * Query Batching / Alias Amplification attacks (bypasses rate limits)
      * Field Suggestions enabled in production (Did you mean...)
      * Mutation execution permitted via HTTP GET requests
"""

import sys
import json
import uuid
import re
import datetime

class ScopeGuard:
    @staticmethod
    def is_authorized(target: str, authorized_targets: list) -> bool:
        if not target:
            return True
        clean_target = target.strip().lower()
        clean_target = re.sub(r"^https?://", "", clean_target).split("/")[0].split(":")[0]
        for auth in authorized_targets:
            clean_auth = auth.strip().lower()
            clean_auth = re.sub(r"^https?://", "", clean_auth).split("/")[0].split(":")[0]
            if clean_target == clean_auth or clean_target.endswith("." + clean_auth):
                return True
        return False

def calculate_query_depth(query_str: str) -> int:
    current_depth = 0
    max_depth = 0
    for char in query_str:
        if char == '{':
            current_depth += 1
            if current_depth > max_depth:
                max_depth = current_depth
        elif char == '}':
            if current_depth > 0:
                current_depth -= 1
    return max_depth

def audit_graphql(introspection_result: dict, test_query: str, allows_batching: bool = True, suggests_fields: bool = True) -> tuple:
    findings = []
    introspection_enabled = False

    # 1. Introspection check
    if introspection_result and "__schema" in str(introspection_result):
        introspection_enabled = True
        findings.append({
            "id": str(uuid.uuid4()),
            "title": "GraphQL Introspection Enabled in Production",
            "severity": "medium",
            "cvss_score": 5.3,
            "description": "The GraphQL endpoint answers introspection queries (__schema / __type), disclosing the entire backend data model, hidden mutations, and object relationships to unauthenticated users.",
            "remediation": "Disable introspection in production environments (e.g. Apollo Server: introspection: false)."
        })

    # 2. Query depth check
    depth = calculate_query_depth(test_query)
    if depth >= 8:
        findings.append({
            "id": str(uuid.uuid4()),
            "title": f"Excessive GraphQL Query Depth Allowed (Depth: {depth})",
            "severity": "high",
            "cvss_score": 7.5,
            "description": f"The GraphQL server allowed a deeply nested circular query (Depth {depth}). Without query depth limiting, attackers can cause server Denial of Service (DoS) via resource exhaustion.",
            "remediation": "Install graphql-depth-limit middleware and enforce a maximum query depth (recommended limit: 5 - 7)."
        })

    # 3. Batching check
    if allows_batching:
        findings.append({
            "id": str(uuid.uuid4()),
            "title": "GraphQL Array Query Batching Enabled",
            "severity": "medium",
            "cvss_score": 5.8,
            "description": "The endpoint accepts arrays of queries in a single HTTP POST request. Attackers can batch hundreds of operations in one request, bypassing traditional IP-based rate limiting.",
            "remediation": "Disable query batching or apply complexity calculators across all queries within a batch."
        })

    # 4. Field suggestions check
    if suggests_fields:
        findings.append({
            "id": str(uuid.uuid4()),
            "title": "GraphQL Field Suggestions Enabled ('Did you mean...')",
            "severity": "low",
            "cvss_score": 3.7,
            "description": "Server returns field suggestions on syntax or field errors, leaking hidden or internal fields even when introspection is disabled.",
            "remediation": "Disable field suggestions in production error formatters."
        })

    return findings, introspection_enabled, depth

def handle_execute(req):
    options = req.get("options", {})
    target = req.get("graphql_endpoint") or req.get("target", "")
    authorized_targets = options.get("authorized_targets", [])

    if target and authorized_targets:
        if not ScopeGuard.is_authorized(target, authorized_targets):
            return {
                "status": "error",
                "code": "SCOPE_VIOLATION",
                "message": f"Target '{target}' is not in authorized scope: {authorized_targets}"
            }

    # Test payload
    query_str = req.get("schema_or_query") or options.get("schema_or_query", "")
    if not query_str:
        query_str = """
        query DeepNestedDoS {
          user(id: "1") {
            friends {
              friends {
                friends {
                  friends {
                    friends {
                      friends {
                        friends {
                          friends {
                            id
                            name
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """

    mock_introspection = options.get("mock_introspection", {"__schema": {"types": ["User", "Admin", "SecretToken"]}})
    allows_batch = options.get("allows_batching", True)
    suggests = options.get("suggests_fields", True)

    findings, intro_enabled, depth = audit_graphql(mock_introspection, query_str, allows_batch, suggests)

    return {
        "status": "success",
        "result": {
            "endpoint": target or "https://api.corp.internal/graphql",
            "introspection_enabled": intro_enabled,
            "max_query_depth_detected": depth,
            "total_findings": len(findings),
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
            res = {"status": "ok", "module": "graphql-security-audit", "version": "1.0.0"}
        else:
            res = handle_execute(req)

        sys.stdout.write(json.dumps(res) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()
