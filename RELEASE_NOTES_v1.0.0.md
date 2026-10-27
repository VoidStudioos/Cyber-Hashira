# Cyber Hashira v1.0.0 — Official Production Release 🚀

Welcome to the first official production release of **Cyber Hashira**, the ultimate modular cybersecurity workstation and penetration testing platform.

---

### 🌟 Key Highlights

- **120 Certified Security Modules:** Independently packageable modules covering Web Applications, API Security, Cloud IAM, Kubernetes Posture, Active Directory, Network Discovery, Hardware/Automotive Security, and Digital Forensics.
- **5-Gate Quality Verification Matrix (120/120 PASS):** Every single module is certified for:
  1. Manifest schema and metadata validity
  2. Artifact presence and SHA-256 integrity
  3. Stdio IPC JSON protocol health checks
  4. ScopeGuard boundary enforcement (unauthorized target rejection)
  5. Authorized scan execution and findings generation
- **3 Presentation Formats (Windows, Linux, macOS):**
  - **Web Security Dashboard:** Modern dark cyberpunk interface powered by Flask + Tailwind CSS (`python hashira.py web`)
  - **Terminal TUI Console:** Zero-dependency, ultra-fast ANSI terminal UI for headless and SSH workflows (`python hashira.py tui`)
  - **Native Desktop App:** Tauri 2 (Rust) + React 18 + Vite visual workstation (`python hashira.py desktop`)
- **Master Unified Launcher (`hashira.py`):** Control the entire platform, run tests, list modules, and trigger scans from a single command.
- **Production Docker & Docker-Compose:** Instant deployment in an isolated container with `docker-compose up -d`.
- **Evidence & Reporting Engine:** Redaction of secrets, deduplication of findings, and export to OASIS SARIF v2.1.0 (GitHub Code Scanning compatible) and executive HTML reports.
- **Bilingual Documentation:** Full English and Persian guides (`README.md` & `README.fa.md`).

---

### 📦 Included Release Packages

| Package | Platform | Architecture | Description |
|---|---|---|---|
| `cyber-hashira-windows-x64-v1.0.0.zip` | Windows 10/11 | x86_64 | Standalone portable bundle with one-click `.bat` launchers |
| `cyber-hashira-linux-x64-v1.0.0.tar.gz` | Linux / Ubuntu | x86_64 | Standalone portable bundle with `.sh` scripts & `.desktop` entry |

---

### 🚀 Quick Start
```bash
# Clone the repository:
git clone https://github.com/VoidStudioos/Cyber-Hashira.git
cd Cyber-Hashira

# Launch Web Dashboard:
python hashira.py web

# Launch Terminal TUI:
python hashira.py tui

# Run full verification matrix:
python hashira.py matrix
```
