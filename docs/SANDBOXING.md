# Cyber Hashira — Subprocess Sandboxing & IPC Isolation Specification

This document details the sandboxing, resource containment, and isolation mechanisms enforced when running security module workers.

---

## 1. Threat Model & Sandboxing Objectives

In Cyber Hashira, security modules represent specialized tools executing active probes, payload fuzzing, or static analysis. The IPC Sandboxing Engine (`engine/sandbox.py`) prevents:
1. **Host Secret Exfiltration:** Malicious or compromised third-party plugins cannot read host cloud tokens, SSH keys, or environment secrets.
2. **Resource Exhaustion (Denial of Service):** A runaway module cannot consume infinite CPU or memory to freeze the host workstation.
3. **Privilege Escalation:** Modules are executed under restricted subprocess conditions without superuser permissions.
4. **Scope Violation:** Outbound tasks are strictly screened by the mandatory ScopeGuard boundary before child process dispatch.

---

## 2. Sandboxing Mechanisms

### 2.1 Environment Variable Sanitization
Prior to spawning any module worker subprocess:
- All sensitive environment keys containing `SECRET`, `TOKEN`, `KEY`, `PASSWORD`, `CREDENTIAL`, `AWS`, `AZURE`, `GCP`, or `SSH` are scrubbed.
- Only a minimal whitelist of system paths (`PATH`, `PYTHONPATH`, `SYSTEMROOT`, `TEMP`) is passed to the worker.
- A flag `HASHIRA_SANDBOXED=1` is injected into the worker environment.

### 2.2 POSIX Resource Constraints (rlimits)
On Linux and macOS hosts, the runner invokes `resource.setrlimit` via `preexec_fn`:
- **CPU Time (`RLIMIT_CPU`):** Hard capped at 30 seconds CPU time per single task.
- **Virtual Memory (`RLIMIT_AS`):** Maximum 512 MB virtual memory per worker instance.
- **File Descriptors (`RLIMIT_NOFILE`):** Restricted to 256 open handles.

### 2.3 Strict Mode (`--sandbox-mode strict`)
When launched with `--sandbox-mode strict`, the orchestrator verifies Docker availability and wraps high-risk network tools inside an isolated container with read-only root filesystems and drop-capabilities (`--cap-drop=ALL`).
