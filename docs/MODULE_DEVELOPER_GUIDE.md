# Cyber Hashira — Module Developer & Certification Guide

This document is the authoritative standard for developing, packaging, testing, and certifying security modules in the Cyber Hashira ecosystem.

---

## 1. Module Architecture & Protocol Principles

Cyber Hashira enforces a **strict, language-agnostic modular architecture**:
- **Process Isolation:** Modules execute as independent subprocesses. The host never dynamically links untrusted shared libraries (`.so`, `.dll`, `.dylib`) into its memory space.
- **Stdio JSON-RPC IPC:** Communication between the host orchestrator and module workers takes place exclusively across Standard Input (`stdin`) and Standard Output (`stdout`), using newline-delimited JSON envelopes.
- **ScopeGuard Boundary:** Every active probe against a network, host, or cloud resource must verify target authorization through the ScopeGuard boundary.
- **Deterministic Offline Quality:** Modules must operate offline without mandatory cloud dependencies.

---

## 2. Directory Structure & Naming Conventions

### 2.1 Directory Layout
Every module must reside in its own self-contained directory under `modules/<module-id>/`:

```text
modules/<module-id>/
├── manifest.json       # Formal plugin manifest & contract metadata
├── worker.py           # Executable entry point (Python, Rust, Go, or Node)
└── README.md           # Technical documentation and reference tools
```

### 2.2 Naming Rules
1. **Module ID (`id`):** Must be strictly lowercase **kebab-case** (e.g. `firmware-binary-unpacker`, `modbus-tcp-security-auditor`).
2. **Directory Name Match:** The directory name under `modules/` **must exactly match** the `id` field inside `manifest.json`.
3. **No Aliases or Ambiguous Names:** Single-word generic names (e.g., `forensics` or `vulnerability`) are strictly forbidden. Use specific canonical names (`digital-forensics`, `vulnerability-assessment`).
4. **Mandatory Category:** Every module must declare an official category:
   - `Web Application Security`
   - `API & Microservices`
   - `Network & Infrastructure`
   - `Cloud & Container Security`
   - `Identity & Access Management`
   - `Active Directory & Enterprise`
   - `AI & LLM Security`
   - `IoT & Firmware Security`
   - `ICS & SCADA Security`
   - `Blockchain & Web3`
   - `Supply Chain & DevSecOps`
   - `Purple Team & Adversary Simulation`
   - `Blue Team & Threat Hunting`
   - `Compliance & Governance`

---

## 3. The `manifest.json` Specification

The `manifest.json` file declares the module's identity, capabilities, permissions, execution contract, and configuration schema.

### 3.1 Complete Schema Example

```json
{
  "id": "iot-mqtt-security-auditor",
  "name": "IoT MQTT Broker Security Auditor",
  "description": "Audits MQTT v3.1.1/v5 broker endpoints for anonymous read/write access, wildcards subscription leaks, cleartext transport, and weak credentials.",
  "author": "Cyber Hashira Security Team",
  "version": "1.0.0",
  "min_host_version": "0.1.0",
  "category": "IoT & Firmware Security",
  "supported_os": [
    "windows",
    "linux",
    "macos"
  ],
  "supported_arch": [
    "x86_64",
    "aarch64"
  ],
  "required_permissions": [
    "network:connect",
    "findings:write"
  ],
  "optional_permissions": [
    "evidence:write"
  ],
  "entry_point": {
    "runtime": "python",
    "executable": "worker.py",
    "default_args": []
  },
  "config_schema": {
    "type": "object",
    "properties": {
      "port": {
        "type": "integer",
        "default": 1883,
        "description": "Target MQTT broker TCP port"
      },
      "test_wildcard": {
        "type": "boolean",
        "default": true,
        "description": "Subscribe to '#' and '$SYS/#' topics to identify data leakage"
      }
    }
  },
  "contracts": {
    "input_schema": {
      "type": "object",
      "required": ["task_id", "target"],
      "properties": {
        "task_id": { "type": "string" },
        "target": { "type": "string" },
        "scope_approved": { "type": "boolean" },
        "options": { "type": "object" }
      }
    },
    "output_schema": {
      "type": "object",
      "required": ["task_id", "success", "findings"],
      "properties": {
        "task_id": { "type": "string" },
        "success": { "type": "boolean" },
        "findings": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["title", "severity"],
            "properties": {
              "id": { "type": "string" },
              "title": { "type": "string" },
              "severity": { "type": "string", "enum": ["Critical", "High", "Medium", "Low", "Info"] },
              "description": { "type": "string" },
              "cwe": { "type": "string" },
              "remediation": { "type": "string" }
            }
          }
        }
      }
    }
  }
}
```

### 3.2 Field Definitions
| Field | Type | Required | Description |
|---|---|---|---|
| `id` | String | **Yes** | Unique kebab-case identifier (must match directory name). |
| `name` | String | **Yes** | Human-readable title displayed in dashboards and reports. |
| `description` | String | **Yes** | Technical summary mentioning reference techniques / tools. |
| `author` | String | **Yes** | Author or organization maintaining the module. |
| `version` | String | **Yes** | SemVer version string (e.g. `1.0.0`). |
| `min_host_version` | String | **Yes** | Minimum Cyber Hashira host version required. |
| `category` | String | **Yes** | Official cybersecurity category. |
| `supported_os` | Array | **Yes** | Platforms supported: `["windows", "linux", "macos"]`. |
| `supported_arch`| Array | **Yes** | CPU architectures: `["x86_64", "aarch64"]`. |
| `required_permissions` | Array | **Yes** | Sandbox permissions requested (`network:connect`, `filesystem:read`, etc.). |
| `entry_point` | Object | **Yes** | `runtime` (`python`, `rust`, `node`, `native`) and `executable` path. |
| `config_schema`| Object | **Yes** | JSON-Schema definition of user-configurable module settings. |
| `contracts` | Object | **Yes** | Formal `input_schema` and `output_schema` validation contracts. |

---

## 4. Stdio JSON-RPC Protocol Implementation

Modules communicate via stdin/stdout. Each message is a single-line JSON string followed by `\n`.

### 4.1 Inbound Messages from Host

#### 1. `HealthCheck`
Sent by the host to verify worker availability, dependency readiness, and runtime health.
```json
{"type": "HealthCheck"}
```

#### 2. `RunTask`
Sent by the host to initiate a security audit or probe against an authorized target.
```json
{
  "type": "RunTask",
  "action": "execute",
  "target": "mqtt.target.corp",
  "authorized_targets": ["mqtt.target.corp"],
  "payload": {
    "task_id": "scan-170001",
    "target": "mqtt.target.corp",
    "scope_approved": true,
    "options": {
      "port": 1883,
      "simulate_vulnerabilities": false
    }
  }
}
```

### 4.2 Outbound Messages to Host

#### 1. `HealthCheckResult`
```json
{
  "type": "HealthCheckResult",
  "payload": {
    "healthy": true,
    "version": "1.0.0",
    "message": "Module initialized and ready for execution."
  }
}
```

#### 2. `TaskCompleted` (Success or Scope Guard Rejection)
```json
{
  "type": "TaskCompleted",
  "payload": {
    "task_id": "scan-170001",
    "success": true,
    "findings": [
      {
        "id": "finding-mqtt-anon-01",
        "title": "Unauthenticated Anonymous MQTT Broker Access",
        "severity": "High",
        "description": "The MQTT broker allows anonymous client connections without username or password authentication.",
        "cwe": "CWE-306",
        "remediation": "Configure 'allow_anonymous false' and require client X.509 certificate or SASL credentials."
      }
    ],
    "telemetry": {
      "duration_ms": 142.5,
      "checks_performed": 6
    }
  }
}
```

---

## 5. Reference Implementation (Python Template)

Here is a complete, production-ready `worker.py` demonstrating:
1. Stdio JSON-RPC event loop.
2. Low-level ScopeGuard verification.
3. Health check handling.
4. Structured finding generation.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cyber Hashira — Reference Module Worker
"""

import sys
import json
import time

def handle_health_check():
    """Verify runtime dependencies and readiness."""
    return {
        "type": "HealthCheckResult",
        "payload": {
            "healthy": True,
            "version": "1.0.0",
            "message": "Worker operational"
        }
    }

def handle_run_task(message):
    """Execute target security audit with mandatory ScopeGuard enforcement."""
    payload = message.get("payload", {})
    task_id = payload.get("task_id", "task-default")
    target = payload.get("target", "")
    scope_approved = payload.get("scope_approved", False)
    options = payload.get("options", {})

    # MANDATORY LOWER-LEVEL SCOPEGUARD ENFORCEMENT
    if not scope_approved:
        return {
            "type": "TaskCompleted",
            "payload": {
                "task_id": task_id,
                "success": False,
                "error": "Target authorization denied by ScopeGuard boundary.",
                "findings": []
            }
        }

    start_time = time.time()
    findings = []

    # Real audit logic or safe simulated heuristic
    simulate = options.get("simulate_vulnerabilities", False)
    if simulate:
        findings.append({
            "id": f"{task_id}-f1",
            "title": "Reference Sample Security Finding",
            "severity": "Medium",
            "description": f"Audited target {target} and detected sample issue.",
            "cwe": "CWE-200",
            "remediation": "Apply vendor recommended patch."
        })

    duration_ms = round((time.time() - start_time) * 1000, 2)
    return {
        "type": "TaskCompleted",
        "payload": {
            "task_id": task_id,
            "success": True,
            "findings": findings,
            "telemetry": {
                "duration_ms": duration_ms,
                "target": target
            }
        }
    }

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            req_type = req.get("type", "")

            if req_type == "HealthCheck":
                resp = handle_health_check()
            elif req_type in ("RunTask", "Execute"):
                resp = handle_run_task(req)
            else:
                resp = {"error": f"Unknown request type: {req_type}"}

            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        except Exception as exc:
            err_resp = {"error": str(exc), "healthy": False, "success": False}
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
```

---

## 6. Registering in `registry/v1/modules.json` & Generating Artifact

Once your module directory is created:
1. **Compute SHA-256 Tarball Artifact:**
   Package the module into `registry/artifacts/<id>-<version>.tar.gz`:
   ```bash
   python scripts/package_all_modules.py
   ```
2. **Catalog Metadata:**
   The packaging script automatically scans all `modules/*/manifest.json` files, packages clean reproducible tarballs into `registry/artifacts/`, calculates cryptographic SHA-256 digests, and synchronizes `registry/v1/modules.json`.

---

## 7. The Quality Certification Gates Checklist

Every module must pass all verification gates in `tests/test_all_modules_matrix.py` before a Pull Request can be accepted:

| Gate | Name | Verification Requirement |
|---|---|---|
| **Gate 1** | **Manifest** | `manifest.json` exists, parses valid JSON, specifies mandatory fields (`id`, `version`, `category`, `entry_point`). |
| **Gate 2** | **Artifact** | Packaged tarball exists in `registry/artifacts/` and its SHA-256 hash strictly matches `registry/v1/modules.json`. |
| **Gate 3** | **Health** | Spawns worker process via Stdio IPC and receives a valid `HealthCheckResult` with `healthy: true` within timeout. |
| **Gate 4** | **Scope** | Dispatches task with `scope_approved: false`. The module **must reject** execution without leaking packets. |
| **Gate 5** | **RunTask** | Dispatches valid task with `scope_approved: true`. The module completes execution and returns valid finding structures. |
| **Gate 6** | **Regression** | Evaluates module against known test fixtures and golden outputs for false positive/negative validation. |

### Running the Matrix Test Locally:
```bash
python hashira.py matrix
# Or directly:
python tests/test_all_modules_matrix.py
```
All modules must report `[PASS]` across all gates.
