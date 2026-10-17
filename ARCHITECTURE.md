# Cyber Hashira Architecture Specification

## 1. High-Level System Architecture

Cyber Hashira is designed from first principles around a three-tier modular architecture:

```
+-----------------------------------------------------------------------------------+
|                        LAYER A -- CYBER HASHIRA HOST                              |
|                                                                                   |
|  +--------------------+  +----------------------+  +---------------------------+  |
|  |     Desktop UI     |  |   Project Manager    |  |        ScopeGuard         |  |
|  |   (Tauri + React)  |  |  (Targets & Scope)   |  | (Strict Auth Boundary)    |  |
|  +--------------------+  +----------------------+  +---------------------------+  |
|  +--------------------+  +----------------------+  +---------------------------+  |
|  |    Module Store    |  |  Findings Database   |  |     Audit Event Log       |  |
|  |  & Package Manager |  |   (SQLite WAL Mode)  |  |   (Cryptographic Trace)   |  |
|  +--------------------+  +----------------------+  +---------------------------+  |
|                                 |                                                 |
|                         Stdio JSON-RPC IPC                                        |
+---------------------------------|-------------------------------------------------+
                                  |
         +------------------------+------------------------+
         |                                                 |
         v                                                 v
+-------------------------------+               +-------------------------------+
|   LAYER B -- SECURITY MODULE  |               |  LAYER C -- GITHUB REGISTRY   |
|                               |               |                               |
|  - Process Isolation          |               |  - registry/v1/modules.json   |
|  - Stdio Worker Protocol      |  <---------   |  - SHA-256 Verified Tarballs  |
|  - Controlled Permissions     |               |  - Zero Server Runtime        |
|  - No Direct Native Linkage   |               |  - On-Demand Delivery         |
+-------------------------------+               +-------------------------------+
```

---

## 2. Layer A: The Lightweight Host

The Host is the core orchestrator and is intentionally kept lean:
- **Desktop Frontend:** React 18, TypeScript, Tailwind CSS, Vite, Zustand.
- **Native Host Shell:** Tauri 2, Rust (Tokio, Rusqlite, Tracing).
- **Embedded Database:** Standalone SQLite with Write-Ahead Logging (`WAL`) mode, storing projects, targets, scope rules, installed modules, findings, and audit logs.
- **Security Boundary (`ScopeGuard`):** A mandatory gatekeeper that intercepts all outbound module tasks. If a target is not explicitly authorized within the active project, the task is denied before any network packet or child process is dispatched.

---

## 3. Layer B: Independently Installable Modules

Modules represent discrete cybersecurity disciplines (e.g. DNS Reconnaissance, Web Application Security, Network Scanning, Vulnerability Assessment, Forensics, Malware Analysis, Threat Intelligence, AI Assistance).

### Key Rules:
1. **Never bundled in base installer:** The Host starts with zero optional security scanners pre-installed.
2. **Process Isolation:** Modules run as subprocesses (Python, standalone binaries, or Node).
3. **No Dynamic Library Injection:** The Host never uses `dlopen` or loads untrusted native `.dll`/`.so` libraries into its memory space.
4. **Communication Contract:** Modules talk to the Host over standard I/O using a versioned JSON-RPC envelope:
   - `HostRequest::HealthCheck` / `ModuleResponse::HealthCheckResult`
   - `HostRequest::RunTask` / `ModuleResponse::TaskCompleted`
5. **Rollback Guarantee:** If a module update or installation fails integrity checks or the post-install health check, the staging directory is immediately purged, leaving no dangling executable remnants.

---

## 4. Layer C: GitHub Distribution Infrastructure

GitHub acts as the decentralized package registry and distribution platform:
- `registry/v1/modules.json`: Contains the machine-readable module manifest catalog, version constraints, permissions list, and artifact download URLs.
- `registry/artifacts/*.tar.gz`: Pre-packaged tarballs with verified SHA-256 hashes.
- Offline support: Users can copy verified archives onto an airgapped system and install them locally without internet connectivity.
