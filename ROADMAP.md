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

## Phase 3 — Web Security Workspace
- [ ] Intercepting HTTP/S proxy core
- [ ] Repeater, Decoder, Request comparison
- [ ] OWASP ZAP adapter integration

## Phase 4 — Network & Vulnerability Assessment
- [ ] Nmap service and port discovery adapter
- [ ] Nuclei vulnerability scanning engine integration
- [ ] SARIF import/export

## Phase 5 — Extended Security Disciplines
- [ ] API Security (OpenAPI, GraphQL, RESTler)
- [ ] TLS & Cryptography inspection (SSLyze, testssl.sh)
- [ ] Cloud Security posture assessment (Prowler, ScoutSuite)
- [ ] Container Security (Trivy, Syft)
- [ ] Source Code Security (Semgrep, Gitleaks)

## Phase 6 — Forensics & Threat Intelligence
- [ ] Digital Forensics (Autopsy, Volatility 3, ExifTool)
- [ ] Malware Analysis (YARA, capa, ClamAV)
- [ ] Threat Intelligence (MISP, OpenCTI, MITRE ATT&CK)

## Phase 7 — AI & Visual Automation
- [ ] Hashira AI defensive security assistant
- [ ] Visual workflow designer (React Flow)
- [ ] Automated reporting (PDF, HTML, SARIF)

## Phase 8 — Production Release & Distribution
- [ ] Signed Windows MSI / EXE installers
- [ ] Signed Ubuntu DEB & AppImage packages
- [ ] Multi-language localization (English, Persian, etc.)
