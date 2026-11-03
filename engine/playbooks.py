# -*- coding: utf-8 -*-
"""
Cyber Hashira — DAG Attack Chaining & Mission Playbooks Engine
Executes ordered or graph-based security campaign playbooks across the 200 modules.
"""

import os
import sys
import json
import time
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULES_DIR = REPO_ROOT / "modules"


@dataclass
class PlaybookStage:
    id: str
    name: str
    module_id: str
    description: str
    depends_on: List[str] = field(default_factory=list)
    options: Dict[str, Any] = field(default_factory=dict)
    timeout_sec: int = 15
    critical: bool = False


@dataclass
class Playbook:
    id: str
    name: str
    category: str
    description: str
    target_type: str
    stages: List[PlaybookStage] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class PlaybookEngine:
    """Orchestrates complex multi-stage attack and audit workflows."""

    def __init__(self, modules_dir: Optional[Path] = None):
        self.modules_dir = modules_dir or MODULES_DIR
        self._playbooks: Dict[str, Playbook] = {}
        self._register_default_playbooks()

    def _register_default_playbooks(self):
        # 1. Enterprise Active Directory Zero-to-Hero
        self.register_playbook(Playbook(
            id="ad-zero-to-hero",
            name="Active Directory Zero-to-Domain-Admin Kill Chain",
            category="Enterprise Infrastructure",
            description="Exposes privilege escalation vectors from unauthenticated AD CS certificates to Kerberos silver ticket forgery and BloodHound shortest path analysis.",
            target_type="Active Directory Domain Controller",
            stages=[
                PlaybookStage(
                    id="stage-1-adcs",
                    name="AD CS Certificate Template Audit",
                    module_id="adcs-esc-template-auditor",
                    description="Identify vulnerable certificate templates (ESC1 through ESC8) allowing client authentication impersonation.",
                    options={"check_esc1_esc8": True}
                ),
                PlaybookStage(
                    id="stage-2-coercion",
                    name="RPC Authentication Coercion & NTLM Relay",
                    module_id="ntlm-relay-coercion-scanner",
                    description="Evaluate MS-EFSR PetitPotam coercion endpoints and SMB signing enforcement.",
                    depends_on=["stage-1-adcs"],
                    options={"protocol": "MS-EFSR", "test_relay": True}
                ),
                PlaybookStage(
                    id="stage-3-kerberos",
                    name="Kerberos SPN & Silver Ticket Audit",
                    module_id="kerberos-silver-ticket-auditor",
                    description="Assess weak RC4 Kerberos encryption on service principal names.",
                    depends_on=["stage-2-coercion"],
                    options={"audit_rc4": True}
                ),
                PlaybookStage(
                    id="stage-4-gpo",
                    name="GPO Drift & SYSVOL Credentials Check",
                    module_id="gpo-security-drift-auditor",
                    description="Scan SYSVOL scripts and Group Policy Preferences for cpassword leaks.",
                    depends_on=["stage-2-coercion"],
                    options={"scan_sysvol": True}
                ),
                PlaybookStage(
                    id="stage-5-bloodhound",
                    name="BloodHound Domain Trust & Path Analysis",
                    module_id="ad-bloodhound-path-analyzer",
                    description="Synthesize graph relationships to map the shortest path to Domain Admins.",
                    depends_on=["stage-1-adcs", "stage-3-kerberos", "stage-4-gpo"],
                    options={"calculate_shortest_path": True}
                )
            ]
        ))

        # 2. OWASP LLM Red Team & AI Safety Suite
        self.register_playbook(Playbook(
            id="owasp-llm-redteam",
            name="OWASP LLM Top 10 Red Teaming Suite",
            category="Artificial Intelligence",
            description="Autonomous multi-vector security assessment for LLMs, GenAI agents, and RAG pipelines.",
            target_type="LLM API / Autonomous Agent Endpoint",
            stages=[
                PlaybookStage(
                    id="stage-1-prompt-injection",
                    name="Prompt Injection & Jailbreak Testing",
                    module_id="llm-prompt-injection-auditor",
                    description="Test direct and indirect prompt injections and multi-turn jailbreak attempts.",
                    options={"test_jailbreaks": True, "heuristics_level": "aggressive"}
                ),
                PlaybookStage(
                    id="stage-2-system-prompt",
                    name="System Prompt & IP Extraction",
                    module_id="llm-system-prompt-extractor",
                    description="Evaluate resistance to cognitive framing and instructions leakage.",
                    depends_on=["stage-1-prompt-injection"],
                    options={"extract_system_prompt": True}
                ),
                PlaybookStage(
                    id="stage-3-rag-poisoning",
                    name="RAG Vector Store & Context Poisoning",
                    module_id="rag-vector-poisoning-scanner",
                    description="Test vector embeddings and cosine similarity index for context poisoning.",
                    options={"fuzz_vector_db": True}
                ),
                PlaybookStage(
                    id="stage-4-insecure-output",
                    name="Insecure Output Handling (Downstream XSS/RCE)",
                    module_id="llm-insecure-output-handling",
                    description="Analyze whether unsanitized LLM output can trigger client or server vulnerabilities.",
                    depends_on=["stage-1-prompt-injection"],
                    options={"test_markdown_render": True, "test_sql_exec": True}
                ),
                PlaybookStage(
                    id="stage-5-agency-audit",
                    name="Autonomous Agent Excessive Agency Audit",
                    module_id="llm-excessive-agency-auditor",
                    description="Verify tool-calling permissions and autonomous execution boundaries.",
                    depends_on=["stage-2-system-prompt", "stage-4-insecure-output"],
                    options={"verify_tool_calling": True}
                )
            ]
        ))

        # 3. Web3 & EVM Smart Contract Audit
        self.register_playbook(Playbook(
            id="smart-contract-defi-audit",
            name="Web3 & DeFi Smart Contract Security Suite",
            category="Blockchain & Web3",
            description="Exhaustive vulnerability and financial risk assessment for Solidity and EVM contracts.",
            target_type="Solidity Smart Contract / DeFi Protocol",
            stages=[
                PlaybookStage(
                    id="stage-1-evm-reentrancy",
                    name="EVM Bytecode & Reentrancy Analysis",
                    module_id="evm-smart-contract-auditor",
                    description="Audit checks-effects-interactions pattern and integer arithmetic bounds.",
                    options={"check_reentrancy": True, "check_overflow": True}
                ),
                PlaybookStage(
                    id="stage-2-flash-loan",
                    name="Flash Loan Arbitrage & Oracle Risk",
                    module_id="flash-loan-arbitrage-risk-scanner",
                    description="Simulate single-block liquidity manipulation and spot AMM price deviations.",
                    depends_on=["stage-1-evm-reentrancy"],
                    options={"simulate_arbitrage": True}
                ),
                PlaybookStage(
                    id="stage-3-erc20-permit",
                    name="ERC-20 Permit & Signature Replay Guard",
                    module_id="erc20-permit-signature-auditor",
                    description="Verify EIP-712 domain separator and cross-chain nonce replay resistance.",
                    options={"verify_eip712": True}
                ),
                PlaybookStage(
                    id="stage-4-access-control",
                    name="UUPS Proxy & Access Control Guard",
                    module_id="smart-contract-access-control-guard",
                    description="Verify admin authorization on upgradeability implementations and selfdestruct opcode.",
                    depends_on=["stage-1-evm-reentrancy"],
                    options={"audit_upgradeability": True}
                )
            ]
        ))

        # 4. Full-Spectrum External Blackbox Pentest
        self.register_playbook(Playbook(
            id="full-external-pentest",
            name="Full-Spectrum External Attack Surface Assessment",
            category="External Perimeter",
            description="Autonomous perimeter enumeration, technology discovery, WAF bypass, and injection fuzzing.",
            target_type="FQDN / Web Domain",
            stages=[
                PlaybookStage(
                    id="stage-1-recon-subdomains",
                    name="Passive Subdomain & Asset Discovery",
                    module_id="subdomain-passive-miner",
                    description="Mine certificate transparency logs and DNS records for subdomains."
                ),
                PlaybookStage(
                    id="stage-2-recon-asn",
                    name="ASN & CIDR IP Range Mapping",
                    module_id="asn-ip-range-mapper",
                    description="Identify organizational IP blocks and autonomous system boundary.",
                    depends_on=["stage-1-recon-subdomains"]
                ),
                PlaybookStage(
                    id="stage-3-tech-fingerprint",
                    name="Web Stack & Framework Fingerprinting",
                    module_id="web-technology-fingerprinter",
                    description="Detect backend framework, server header, CMS, and CDN edge provider.",
                    depends_on=["stage-1-recon-subdomains"]
                ),
                PlaybookStage(
                    id="stage-4-waf-evasion",
                    name="WAF Evasion & Obfuscation Analysis",
                    module_id="waf-evasion-defense",
                    description="Test payload encoding mutations to verify firewall inspection depth.",
                    depends_on=["stage-3-tech-fingerprint"]
                ),
                PlaybookStage(
                    id="stage-5-sql-injection",
                    name="Polymorphic SQL Injection Fuzzing",
                    module_id="sql-injection-fuzzer",
                    description="Test query parameter injection points against blind and error-based heuristics.",
                    depends_on=["stage-4-waf-evasion"]
                ),
                PlaybookStage(
                    id="stage-6-ssrf-guard",
                    name="Server-Side Request Forgery Validation",
                    module_id="ssrf-guard-validator",
                    description="Evaluate cloud metadata (IMDSv1/v2) and internal RFC1918 egress protections.",
                    depends_on=["stage-4-waf-evasion"]
                )
            ]
        ))

        # 5. Cloud & Supply Chain Security Pipeline
        self.register_playbook(Playbook(
            id="cloud-supply-chain-assurance",
            name="Cloud Infrastructure & Supply Chain Assurance",
            category="Cloud & DevSecOps",
            description="Deep inspection of IaC, container images, SBOM components, and CI/CD workflows.",
            target_type="Repository / Cloud Account",
            stages=[
                PlaybookStage(
                    id="stage-1-cloud-iac",
                    name="Terraform & CloudFormation IaC Security",
                    module_id="cloud-iac-security",
                    description="Detect misconfigurations in cloud infrastructure-as-code manifests."
                ),
                PlaybookStage(
                    id="stage-2-s3-exposure",
                    name="S3 Public Bucket & ACL Enumeration",
                    module_id="s3-public-bucket-detector",
                    description="Check object storage permissions, public read/write grants, and encryption."
                ),
                PlaybookStage(
                    id="stage-3-dockerfile-lint",
                    name="Dockerfile Security & Least-Privilege Linter",
                    module_id="dockerfile-security-linter",
                    description="Audit root user usage, unpinned base images, and secret leakage in build steps."
                ),
                PlaybookStage(
                    id="stage-4-sbom-syft",
                    name="SBOM Generation & Component Inventory",
                    module_id="sbom-generator-syft",
                    description="Generate CycloneDX/SPDX software bill of materials.",
                    depends_on=["stage-3-dockerfile-lint"]
                ),
                PlaybookStage(
                    id="stage-5-github-actions",
                    name="GitHub Actions Workflow & Runner Security",
                    module_id="github-actions-security",
                    description="Audit workflow scripts for untrusted PR trigger injection and secret exposure.",
                    depends_on=["stage-1-cloud-iac"]
                )
            ]
        ))

        # 6. Next-Gen Protocols & Realtime Web
        self.register_playbook(Playbook(
            id="nextgen-protocols-audit",
            name="Next-Gen Protocols & Real-Time Web Security",
            category="Advanced Web & Network",
            description="Comprehensive audit of HTTP/2 smuggling, HTTP/3 QUIC fallback, WebSockets, and GraphQL APQ.",
            target_type="Modern Web Gateway / CDN Proxy",
            stages=[
                PlaybookStage(
                    id="stage-1-http2-smuggling",
                    name="HTTP/2 Smuggling & HPACK Bomb Testing",
                    module_id="http2-smuggling-hpack-auditor",
                    description="Analyze HTTP/2 framing desync and decompressor memory pressure."
                ),
                PlaybookStage(
                    id="stage-2-http3-quic",
                    name="HTTP/3 QUIC Downgrade & 0-RTT Replay",
                    module_id="http3-quic-downgrade-tester",
                    description="Verify Alt-Svc header and early data 0-RTT replay defenses."
                ),
                PlaybookStage(
                    id="stage-3-websocket-fuzzer",
                    name="WebSocket Real-Time Binary/Text Protocol Fuzzing",
                    module_id="websocket-realtime-fuzzer",
                    description="Test bidirectional framing, Origin validation, and connection state pollution."
                ),
                PlaybookStage(
                    id="stage-4-graphql-apq",
                    name="GraphQL Persisted Query & APQ Cache Poisoning",
                    module_id="graphql-persisted-query-auditor",
                    description="Verify Automatic Persisted Queries SHA-256 hash validation and depth limits."
                )
            ]
        ))

    def register_playbook(self, playbook: Playbook):
        self._playbooks[playbook.id] = playbook

    def list_playbooks(self) -> List[Dict[str, Any]]:
        result = []
        for p in self._playbooks.values():
            result.append({
                "id": p.id,
                "name": p.name,
                "category": p.category,
                "description": p.description,
                "target_type": p.target_type,
                "stage_count": len(p.stages),
                "stages": [
                    {
                        "id": s.id,
                        "name": s.name,
                        "module_id": s.module_id,
                        "depends_on": s.depends_on
                    } for s in p.stages
                ]
            })
        return result

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        return self._playbooks.get(playbook_id)

    def execute_playbook(
        self,
        playbook_id: str,
        target: str,
        scope_approved: bool = True,
        simulate: bool = True,
        callback: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Executes a playbook sequentially respecting dependencies.
        Returns execution summary with status and gathered findings.
        """
        playbook = self.get_playbook(playbook_id)
        if not playbook:
            raise ValueError(f"Playbook '{playbook_id}' not found.")

        start_time = time.time()
        stage_results: Dict[str, Any] = {}
        all_findings: List[Dict[str, Any]] = []
        overall_success = True

        for stage in playbook.stages:
            stage_start = time.time()
            # Check dependencies
            deps_met = all(stage_results.get(dep, {}).get("success", False) for dep in stage.depends_on)
            if not deps_met and stage.depends_on:
                stage_results[stage.id] = {
                    "stage_id": stage.id,
                    "name": stage.name,
                    "module_id": stage.module_id,
                    "status": "SKIPPED",
                    "success": False,
                    "reason": "Unsatisfied dependencies",
                    "findings": [],
                    "duration_ms": 0
                }
                if stage.critical:
                    overall_success = False
                    break
                continue

            # Execute module via IPC
            module_res = self._run_module_ipc(
                module_id=stage.module_id,
                target=target,
                scope_approved=scope_approved,
                options={**stage.options, "simulate_vulnerabilities": simulate},
                timeout_sec=stage.timeout_sec
            )

            stage_duration = round((time.time() - stage_start) * 1000, 2)
            success = module_res.get("success", False)
            findings = module_res.get("findings", [])
            all_findings.extend(findings)

            stage_results[stage.id] = {
                "stage_id": stage.id,
                "name": stage.name,
                "module_id": stage.module_id,
                "status": "PASSED" if success else "FAILED",
                "success": success,
                "findings_count": len(findings),
                "findings": findings,
                "duration_ms": stage_duration,
                "error": module_res.get("error")
            }

            if callback:
                callback(stage_results[stage.id])

            if not success and stage.critical:
                overall_success = False
                break

        total_duration = round(time.time() - start_time, 2)
        return {
            "playbook_id": playbook.id,
            "playbook_name": playbook.name,
            "target": target,
            "overall_success": overall_success,
            "total_duration_sec": total_duration,
            "stages_executed": len(stage_results),
            "stages": stage_results,
            "total_findings": len(all_findings),
            "findings": all_findings
        }

    def _run_module_ipc(
        self,
        module_id: str,
        target: str,
        scope_approved: bool,
        options: Dict[str, Any],
        timeout_sec: int
    ) -> Dict[str, Any]:
        """Runs the module worker via stdio IPC."""
        mod_dir = self.modules_dir / module_id
        worker_file = mod_dir / "worker.py"
        if not worker_file.is_file():
            return {"success": False, "findings": [], "error": f"Worker script not found: {worker_file}"}

        task_id = f"pb-task-{module_id}-{int(time.time()*1000)}"
        message = {
            "type": "RunTask",
            "action": "execute",
            "target": target,
            "authorized_targets": [target] if scope_approved else [],
            "payload": {
                "task_id": task_id,
                "target": target,
                "scope_approved": scope_approved,
                "options": options
            }
        }

        try:
            proc = subprocess.Popen(
                [sys.executable, str(worker_file)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(mod_dir)
            )
            stdout, stderr = proc.communicate(input=json.dumps(message) + "\n", timeout=timeout_sec)
        except subprocess.TimeoutExpired:
            proc.kill()
            return {"success": False, "findings": [], "error": f"Module {module_id} timed out ({timeout_sec}s)"}
        except Exception as e:
            return {"success": False, "findings": [], "error": str(e)}

        findings = []
        success = False
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                res_json = json.loads(line)
                payload = res_json.get("payload", res_json.get("result", {}))
                if isinstance(payload, dict):
                    findings = payload.get("findings", [])
                    success = payload.get("success", True)
                elif res_json.get("type") == "TaskCompleted":
                    success = True
                break
            except json.JSONDecodeError:
                continue

        return {"success": success or bool(findings), "findings": findings, "raw_stderr": stderr}
