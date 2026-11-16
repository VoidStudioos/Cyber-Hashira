# Changelog

All notable changes to the **Cyber Hashira** project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.2.0] - 2026-11-16

### 🚀 Added
- **60 New Specialized Security Modules (Reaching 260 Total Modules):**
  - **IoT & Embedded Firmware (6 modules):** `iot-firmware-extractor`, `jtag-uart-pinout-identifier`, `ble-firmware-ota-auditor`, `mqtt-broker-exploit-tester`, `coap-iot-protocol-fuzzer`, `zigbee-zwave-recon`.
  - **ICS & SCADA Security (4 modules):** `modbus-plc-auditor`, `s7comm-siemens-scanner`, `dnp3-outstation-fuzzer`, `opc-ua-security-linter`.
  - **Cloud & Sovereign Infrastructure (10 modules):** `azure-ad-service-principal-auditor`, `gcp-workload-identity-validator`, `oci-iam-policy-linter`, `aws-lambda-runtime-security`, `terraform-drift-detector`, `kubernetes-admission-controller-auditor`, `cilium-ebpf-network-policy-auditor`, `harbor-container-registry-auditor`, `istio-service-mesh-authorization`, `openstack-keystone-policy-checker`.
  - **Identity & Enterprise Directory (4 modules):** `okta-idp-hygiene-auditor`, `ping-identity-federation-auditor`, `azure-entra-conditional-access-auditor`, `active-directory-shadow-admin-finder`.
  - **AI & LLM Adversarial Security (6 modules):** `llm-rag-context-injection-auditor`, `model-inversion-privacy-auditor`, `adversarial-patch-detector`, `ai-agent-sandbox-escape-tester`, `onnx-model-backdoor-scanner`, `huggingface-repo-security-auditor`.
  - **Emerging Tech & Telecom (3 modules):** `5g-telecom-core-security-auditor`, `gnss-gps-spoofing-detector`, `satellite-link-protocol-auditor`.
  - **Web, API & Client Security (6 modules):** `fido2-webauthn-implementation-auditor`, `http-cache-smuggling-auditor`, `quic-tls-handshake-auditor`, `wasm-tamper-memory-protection`, `passkey-credential-binding-auditor`, `jwt-confusion-cross-key-auditor`.
  - **Supply-Chain & Build Security (5 modules):** `slsa-provenance-verifier`, `npm-typosquatting-malware-detector`, `pypi-supply-chain-sentinel`, `docker-bake-multistage-linter`, `gradle-maven-dependency-integrity`.
  - **Purple Team & Detection Engineering (5 modules):** `atomic-red-team-coverage-mapper`, `mitre-attack-navigator-generator`, `threat-hunting-hypothesis-evaluator`, `edr-telemetry-blindspot-detector`, `detection-as-code-rule-validator`.
  - **Compliance & Regulatory Posture (5 modules):** `iso27001-annex-a-posture-auditor`, `soc2-type2-trust-criteria-evaluator`, `hipaa-hitech-security-auditor`, `pci-dss-v4-readiness-scanner`, `nist-sp-800-53-control-assessor`.
  - **Blue Team & Threat Response (6 modules):** `memory-dump-volatility-triager`, `pcap-dns-tunnel-exfiltration-detector`, `windows-event-log-anomaly-detector`, `linux-auditd-syscall-monitor`, `honeypot-telemetry-aggregator`, `compromised-credential-spill-cleaner`.
- **Tool Self-Hardening:**
  - `engine/sandbox.py`: Subprocess execution with environment variable sanitization, POSIX `rlimits` (CPU/memory/file handles), and drop privileges.
  - `engine/audit_log.py`: Append-only cryptographic audit logger with SHA-256 hash chaining for tamper-evident activity tracking.
  - `engine/scopeguard.py`: Kernel-level and subprocess pre-flight target boundary validation.
  - Web panel authentication with `bcrypt` password hashing, sliding-window rate limiter (30 req/min), and CSRF token protection on mutating endpoints.
- **Testing & Quality Assurance:**
  - Extended certification matrix in `tests/test_all_modules_matrix.py` with **Gate 6 (Regression Gate)**.
  - Added automated registry consistency test (`tests/test_registry_consistency.py`).
  - Added bilingual documentation synchronization validator (`tests/test_bilingual_docs_sync.py`).
  - Added GitHub Actions continuous integration workflow (`.github/workflows/ci.yml`).
- **Documentation:**
  - Created `docs/MODULE_DEVELOPER_GUIDE.md` & `docs/MODULE_DEVELOPER_GUIDE.fa.md`.
  - Created `registry/MIGRATIONS.md` & `registry/MIGRATIONS.fa.md`.
  - Created `docs/SANDBOXING.md` & `docs/SANDBOXING.fa.md`.

### 🔄 Changed
- Consolidated module naming alias duplicates:
  - `modules/forensics` renamed to canonical `modules/digital-forensics`.
  - `modules/vulnerability` renamed to canonical `modules/vulnerability-assessment`.
  - Added backwards-compatibility redirection and deprecation notices in `hashira.py` and `ui/web/app.py`.
- Rebuilt distribution packages in `dist/packages/` for all 260 certified modules.
- Updated documentation badges, module counts, and catalogs to 260 across `README.md` and `README.fa.md`.

---

## [1.1.0] - 2026-10-25

### 🚀 Added
- Added 80 modules across API, Cloud, Web3, and Mobile security domains (reaching 200 total modules).
- Implemented 5-gate module verification matrix (`tests/test_all_modules_matrix.py`).
- Standalone multi-platform installers (`scripts/build_installers.py`).
- Full Persian documentation (`README.fa.md`).

---

## [1.0.0] - 2026-10-18

### 🚀 Initial Release
- Unified launcher (`hashira.py`) supporting Web Dashboard, Terminal TUI, and Desktop App (Tauri 2).
- Stdio JSON-RPC modular IPC architecture.
- Core 120 certified modules.
- ScopeGuard authorization boundary enforcement.
- OASIS SARIF v2.1.0 and executive HTML/PDF reporting engine.
