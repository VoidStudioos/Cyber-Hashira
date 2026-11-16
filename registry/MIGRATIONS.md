# Cyber Hashira — Registry Schema & Module ID Migrations

This document tracks all canonical module identity consolidations, deprecations, and schema evolution in the Cyber Hashira registry (`registry/v1/modules.json`).

---

## Migration 2026-11-16: Module ID Canonicalization & Alias Consolidation

### 1. Summary of Identified Dual-Name Aliases

During the registry audit, two historical module naming discrepancies were identified where physical directory names differed from the official manifest and registry catalog IDs:

| Historical / Directory Alias | Canonical Module ID | Category | Artifact Tarball | Decision |
|---|---|---|---|---|
| `forensics` | `digital-forensics` | Digital Forensics | `digital-forensics-1.0.0.tar.gz` | **MERGED & CONSOLIDATED** to `digital-forensics`. Physical directory renamed from `modules/forensics` to `modules/digital-forensics`. |
| `vulnerability` | `vulnerability-assessment` | Vulnerability Assessment | `vulnerability-assessment-1.0.0.tar.gz` | **MERGED & CONSOLIDATED** to `vulnerability-assessment`. Physical directory renamed from `modules/vulnerability` to `modules/vulnerability-assessment`. |

---

### 2. Technical Decision Rationale

Both module pairs were verified to represent the exact same single implementation:
1. **`digital-forensics`**: Implements cryptographic hashing (MD5, SHA-1, SHA-256), binary Shannon entropy calculation for packed malware triage, Win32 API string extraction, and immutable chain-of-custody logging. Its `manifest.json` has always declared `id: "digital-forensics"`. The folder `modules/forensics` was an un-canonicalized folder name.
2. **`vulnerability-assessment`**: Implements template-based vulnerability scanning (Nuclei-compatible) mapping CVEs, CWEs, and CVSS scores. Its `manifest.json` has always declared `id: "vulnerability-assessment"`. The folder `modules/vulnerability` was an un-canonicalized folder name.

---

### 3. Backward Compatibility & Redirect Policy

To ensure zero downtime for legacy automation scripts, CI/CD pipelines, and existing project configurations:
- **Automatic Alias Redirection:** The master launcher (`hashira.py`) and Web Panel API (`ui/web/app.py`) automatically map:
  - `"forensics"` $\rightarrow$ `"digital-forensics"`
  - `"vulnerability"` $\rightarrow$ `"vulnerability-assessment"`
- **Deprecation Notice:** When an alias is passed via CLI or IPC, the runtime emits:
  ```text
  [!] DEPRECATION WARNING: Module alias '{alias}' is deprecated and will be removed in v2.0.0.
      Redirecting seamlessly to canonical module '{canonical_id}'.
  ```
- **Registry Catalog Schema:** `registry/v1/modules.json` defines canonical entries with an optional `"aliases": ["..."]` array for reverse lookups.
