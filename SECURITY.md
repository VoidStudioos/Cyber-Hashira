# Security Policy

## 1. Security Philosophy

Cyber Hashira is built for cybersecurity professionals, security teams, and authorized auditors. Because security tools possess high capabilities, security controls are foundational and strictly non-negotiable:

1. **Target Authorization (ScopeGuard):** Scanning outside an authorized scope is strictly disallowed.
2. **Safe Subprocess Invocation:** Cyber Hashira does not execute shell strings (no `cmd.exe /c` or `bash -c`). Commands are constructed with structured argument arrays.
3. **Module Integrity:** All downloaded or locally installed module packages must match verified SHA-256 checksums before unpack or execution.
4. **Offline-First Privacy:** Zero telemetry, no user tracking, and no external reporting of targets or findings.
5. **Least Privilege & Process Isolation:** Modules run in unprivileged child processes.

---

## 2. Reporting Vulnerabilities

If you discover a security vulnerability in Cyber Hashira Host, ScopeGuard, or any official module, please report it privately:

- **Email:** security@cyberhashira.org
- **PGP Key:** Available upon request or published on official website.
- **Response SLA:** Initial acknowledgment within 24 hours; remediation within 7 business days.

Please do not open public GitHub issues for undisclosed security vulnerabilities.
