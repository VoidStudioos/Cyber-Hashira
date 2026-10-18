# Implementation Roadmap

Cyber Hashira follows an eight-phase modular roadmap:

## Phase 1 — Foundation (Completed)
- [x] Repository structure and virtual workspaces
- [x] Lightweight Tauri 2 + React + TypeScript Desktop Host
- [x] SQLite database schema (Projects, Targets, Findings, Logs)
- [x] Mandatory ScopeGuard target authorization engine
- [x] Full audit logging system

## Phase 2 — Modular Host & Registry (Completed)
- [x] Official Plugin Manifest standard (`manifest.json`)
- [x] Versioned module registry catalog (`registry/v1/modules.json`)
- [x] Secure installer with SHA-256 integrity verification
- [x] Safe isolated subprocess execution with JSON-RPC IPC contract
- [x] Module Store UI with dynamic category filtering and 1-click install
- [x] First independently packaged sample module (`modules/sample-dns`)
- [x] Automated modular lifecycle verification test suite

## Phase 3 — Web Security Workspace (Completed)
- [x] Intercepting HTTP/S proxy core
- [x] Repeater, Decoder/Encoder & JWT Inspector
- [x] Passive vulnerability analysis engine (CSP, HSTS, Cookies, Banners)
- [x] Integrated Web Security Workspace UI

## Phase 4 — Network & Vulnerability Assessment (Completed)
- [x] Nmap service and port discovery adapter with async socket fallback
- [x] Nuclei template evaluation engine mapping CVEs, CWEs & CVSS v3.1
- [x] Sensitive exposure checks (/.git/HEAD, /.env, /actuator, /server-status)
- [x] Interactive Network & Vulnerability UI Workspaces
- [x] SARIF / JSON export framework

## Phase 5 — Extended Security Disciplines (Completed)
- [x] API Security & Schema Assessment (REST, GraphQL introspection, OpenAPI spec exposure, BOLA)
- [x] TLS & Cryptography Inspector (Certificate profile, cipher suite strength, protocol deprecation)
- [x] Interactive API Security and TLS Cryptography UI Workspaces

## Phase 6 — Forensics & Threat Intelligence (Completed)
- [x] Digital Forensics & Malware Triage (Cryptographic hashes, Shannon entropy, chain-of-custody)
- [x] Binary packing & obfuscation detection (Shannon Entropy > 7.0)
- [x] Threat Intelligence & IOC enrichment (IP, Domain, MD5, SHA-256)
- [x] MITRE ATT&CK Enterprise Matrix v14 technique correlation
- [x] Interactive Forensics and Threat Intelligence UI Workspaces

## Phase 7 — AI & Visual Automation (Completed)
- [x] Hashira AI defensive security assistant with bilingual reasoning (EN & FA)
- [x] Automated secret & credential redaction engine
- [x] Vulnerability explanation & automated remediation patching
- [x] Visual workflow pipeline automation designer & execution engine
- [x] Automated reporting (SARIF, JSON, Executive Summaries)

## Phase 8 — Production Release & Distribution (Configured & Ready)
- [x] Multi-language localization architecture with real-time RTL/LTR layout switching (فارسی / English)
- [x] Multi-platform CI/CD packaging workflows for Windows (MSI/EXE) and Ubuntu (DEB/AppImage)
- [x] Complete automated test regression coverage (9 modules, 39 test cases passing 100%)
