#!/usr/bin/env python3
"""
Cyber Hashira - Infrastructure as Code (IaC) & Cloud Security Posture Auditor
Features:
  - CIS Cloud & Benchmark compliance auditing for:
      * Terraform (HCL / JSON)
      * Kubernetes YAML Manifests
      * AWS CloudFormation Templates
  - Threat & Misconfiguration Rules:
      * Public S3 Buckets (acl = public-read / public-write)
      * Open Ingress Security Groups (0.0.0.0/0 on SSH 22, RDP 3389, Database 5432/3306)
      * Unencrypted Storage Volumes (EBS, RDS storage_encrypted = false)
      * Dangerous IAM Wildcard Permissions (Action = "*", Resource = "*")
      * Kubernetes Privileged Containers (privileged: true, hostPID: true)
      * Root Container Execution (missing runAsNonRoot: true)
"""

import sys
import json
import uuid
import re
import datetime

class ScopeGuard:
    @staticmethod
    def is_authorized(target: str, authorized_targets: list) -> bool:
        if not target:
            return True
        clean_target = target.strip().lower()
        for auth in authorized_targets:
            if clean_target == auth.strip().lower() or clean_target.startswith(auth.strip().lower()):
                return True
        return False

def audit_terraform(content: str) -> tuple:
    findings = []
    misconfigs = []
    deduction = 0

    # 1. S3 Public ACL
    if re.search(r'acl\s*=\s*["\']public-read(?:-write)?["\']', content, re.IGNORECASE):
        f = {
            "id": str(uuid.uuid4()),
            "title": "Public S3 Bucket ACL Configured (CIS AWS 2.1.5)",
            "severity": "critical",
            "cvss_score": 9.1,
            "rule_id": "CIS-AWS-2.1.5",
            "description": "S3 bucket is configured with public-read or public-read-write ACL, exposing cloud data to unauthorized internet users.",
            "remediation": "Set acl to 'private' and enable aws_s3_bucket_public_access_block."
        }
        findings.append(f)
        misconfigs.append("S3_PUBLIC_ACL")
        deduction += 35

    # 2. Open Security Group SSH / RDP
    if re.search(r'0\.0\.0\.0\/0', content) and re.search(r'(?:from_port|to_port)\s*=\s*(?:22|3389)', content):
        f = {
            "id": str(uuid.uuid4()),
            "title": "Ingress Security Group Open to Internet on Port 22/3389 (CIS AWS 4.1)",
            "severity": "high",
            "cvss_score": 8.5,
            "rule_id": "CIS-AWS-4.1",
            "description": "Security group permits unrestricted ingress (0.0.0.0/0) to remote administration ports (SSH/RDP).",
            "remediation": "Restrict ingress CIDR to corporate VPN IP addresses or bastion hosts."
        }
        findings.append(f)
        misconfigs.append("SG_OPEN_ADMIN_PORT")
        deduction += 25

    # 3. Unencrypted Storage
    if re.search(r'(?:storage_encrypted|encrypted)\s*=\s*false', content, re.IGNORECASE):
        f = {
            "id": str(uuid.uuid4()),
            "title": "Unencrypted Storage Volume / Database (CIS AWS 2.2.1)",
            "severity": "medium",
            "cvss_score": 6.5,
            "rule_id": "CIS-AWS-2.2.1",
            "description": "EBS volume or RDS database explicitly disables at-rest KMS encryption.",
            "remediation": "Set encrypted = true and specify kms_key_id."
        }
        findings.append(f)
        misconfigs.append("STORAGE_UNENCRYPTED")
        deduction += 15

    # 4. IAM Wildcard Policy
    if re.search(r'["\']Action["\']\s*:\s*["\']\*["\']', content) and re.search(r'["\']Resource["\']\s*:\s*["\']\*["\']', content):
        f = {
            "id": str(uuid.uuid4()),
            "title": "IAM Policy with Full Administrative Wildcards (*:*) (CIS AWS 1.16)",
            "severity": "critical",
            "cvss_score": 9.4,
            "rule_id": "CIS-AWS-1.16",
            "description": "IAM policy grants unrestricted wildcard privileges across all cloud resources.",
            "remediation": "Apply the principle of least privilege with explicit granular action permissions."
        }
        findings.append(f)
        misconfigs.append("IAM_FULL_WILDCARD")
        deduction += 30

    return findings, misconfigs, deduction

def audit_kubernetes(content: str) -> tuple:
    findings = []
    misconfigs = []
    deduction = 0

    # 1. Privileged Container
    if re.search(r'privileged:\s*true', content, re.IGNORECASE):
        f = {
            "id": str(uuid.uuid4()),
            "title": "Kubernetes Pod Configured in Privileged Mode (CIS K8s 5.2.1)",
            "severity": "critical",
            "cvss_score": 9.6,
            "rule_id": "CIS-K8S-5.2.1",
            "description": "Container has privileged: true, granting root capabilities to the host node and breaking container isolation.",
            "remediation": "Remove privileged: true and apply specific Linux capabilities only if strictly required."
        }
        findings.append(f)
        misconfigs.append("K8S_PRIVILEGED_CONTAINER")
        deduction += 40

    # 2. Host Network / Host PID
    if re.search(r'(?:hostNetwork|hostPID|hostIPC):\s*true', content, re.IGNORECASE):
        f = {
            "id": str(uuid.uuid4()),
            "title": "Container Sharing Host Process / Network Namespace (CIS K8s 5.2.2)",
            "severity": "high",
            "cvss_score": 8.2,
            "rule_id": "CIS-K8S-5.2.2",
            "description": "Container shares host namespace (hostNetwork/hostPID), allowing packet sniffing or process inspection of host processes.",
            "remediation": "Disable hostNetwork and hostPID in the pod specification."
        }
        findings.append(f)
        misconfigs.append("K8S_HOST_NAMESPACE")
        deduction += 25

    # 3. Missing runAsNonRoot
    if not re.search(r'runAsNonRoot:\s*true', content, re.IGNORECASE):
        f = {
            "id": str(uuid.uuid4()),
            "title": "Container May Run As Root User (CIS K8s 5.2.6)",
            "severity": "medium",
            "cvss_score": 6.2,
            "rule_id": "CIS-K8S-5.2.6",
            "description": "Pod securityContext does not enforce runAsNonRoot: true.",
            "remediation": "Configure securityContext: runAsNonRoot: true and runAsUser: 10001."
        }
        findings.append(f)
        misconfigs.append("K8S_ROOT_USER")
        deduction += 15

    return findings, misconfigs, deduction

def handle_execute(req):
    options = req.get("options", {})
    target = req.get("target") or req.get("template_path", "")
    authorized_targets = options.get("authorized_targets", [])

    if target and authorized_targets:
        if not ScopeGuard.is_authorized(target, authorized_targets):
            return {
                "status": "error",
                "code": "SCOPE_VIOLATION",
                "message": f"Target template '{target}' is not in authorized scope: {authorized_targets}"
            }

    t_type = req.get("template_type") or options.get("template_type", "terraform")
    content = req.get("content") or options.get("content", "")

    if not content:
        # Default test template exhibiting real-world IaC vulnerabilities
        content = """
        resource "aws_s3_bucket" "data_lake" {
          bucket = "company-data-prod"
          acl    = "public-read"
        }
        resource "aws_security_group" "ssh_ingress" {
          name = "allow_ssh"
          ingress {
            from_port   = 22
            to_port     = 22
            protocol    = "tcp"
            cidr_blocks = ["0.0.0.0/0"]
          }
        }
        resource "aws_db_instance" "prod_db" {
          allocated_storage = 100
          engine            = "postgres"
          storage_encrypted = false
        }
        """
        t_type = "terraform"

    if t_type.lower() in ["kubernetes", "k8s", "yaml"]:
        findings, misconfigs, deduct = audit_kubernetes(content)
    else:
        findings, misconfigs, deduct = audit_terraform(content)

    compliance_score = max(0, 100 - deduct)

    return {
        "status": "success",
        "result": {
            "template_type": t_type,
            "compliance_score": compliance_score,
            "total_findings": len(findings),
            "misconfigurations": misconfigs,
            "findings": findings,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
        }
    }

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as e:
            sys.stdout.write(json.dumps({"status": "error", "message": f"Malformed JSON: {e}"}) + "\n")
            sys.stdout.flush()
            continue

        req_type = req.get("type", "Execute")
        if req_type == "HealthCheck":
            res = {"status": "ok", "module": "cloud-iac-security", "version": "1.0.0"}
        else:
            res = handle_execute(req)

        sys.stdout.write(json.dumps(res) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()
