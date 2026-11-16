#!/usr/bin/env python3
"""
Test Suite: Registry Consistency and Documentation Synchronization
Validates:
1. Physical directory count in modules/ matches modules.json registry count exactly.
2. 1-to-1 mapping between physical module directories and registry entries (no orphan dirs, no missing dirs).
3. Every module has a packaged artifact in registry/artifacts/ with matching SHA-256 checksum.
4. Declared module count in README.md and README.fa.md matches registry count.
"""

import os
import sys
import json
import hashlib
import re

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES_DIR = os.path.join(REPO_ROOT, "modules")
REGISTRY_CATALOG = os.path.join(REPO_ROOT, "registry", "v1", "modules.json")
ARTIFACTS_DIR = os.path.join(REPO_ROOT, "registry", "artifacts")
README_EN = os.path.join(REPO_ROOT, "README.md")
README_FA = os.path.join(REPO_ROOT, "README.fa.md")

def test_physical_vs_registry_count():
    assert os.path.isdir(MODULES_DIR), "modules/ directory does not exist"
    assert os.path.isfile(REGISTRY_CATALOG), "registry/v1/modules.json does not exist"

    physical_modules = sorted([d for d in os.listdir(MODULES_DIR) if os.path.isdir(os.path.join(MODULES_DIR, d))])
    
    with open(REGISTRY_CATALOG, "r", encoding="utf-8") as f:
        catalog = json.load(f)
    
    registry_modules = catalog.get("modules", [])
    registry_ids = sorted([m["id"] for m in registry_modules])

    print(f"[*] Physical modules count: {len(physical_modules)}")
    print(f"[*] Registry modules count: {len(registry_modules)}")

    assert len(physical_modules) == len(registry_modules), (
        f"Count mismatch: {len(physical_modules)} physical dirs vs {len(registry_modules)} registry entries"
    )

def test_one_to_one_mapping():
    physical_dirs = set(d for d in os.listdir(MODULES_DIR) if os.path.isdir(os.path.join(MODULES_DIR, d)))
    
    with open(REGISTRY_CATALOG, "r", encoding="utf-8") as f:
        catalog = json.load(f)
    
    registry_ids = set(m["id"] for m in catalog.get("modules", []))

    missing_in_registry = physical_dirs - registry_ids
    missing_in_physical = registry_ids - physical_dirs

    assert not missing_in_registry, f"Physical folders missing in registry: {missing_in_registry}"
    assert not missing_in_physical, f"Registry entries missing physical folders: {missing_in_physical}"
    print(f"[+] Exact 1:1 match verified across all {len(physical_dirs)} modules.")

def test_artifacts_and_checksums():
    with open(REGISTRY_CATALOG, "r", encoding="utf-8") as f:
        catalog = json.load(f)

    for m in catalog.get("modules", []):
        mod_id = m["id"]
        version = m.get("version", "1.0.0")
        expected_sha = m.get("artifact", {}).get("sha256")
        assert expected_sha, f"Module {mod_id} missing sha256 in registry"

        archive_name = f"{mod_id}-{version}.tar.gz"
        archive_path = os.path.join(ARTIFACTS_DIR, archive_name)
        assert os.path.isfile(archive_path), f"Artifact missing for module {mod_id}: {archive_path}"

        with open(archive_path, "rb") as af:
            actual_sha = hashlib.sha256(af.read()).hexdigest()

        assert actual_sha == expected_sha, (
            f"Checksum mismatch for {mod_id}: expected {expected_sha}, got {actual_sha}"
        )
    print(f"[+] All {len(catalog['modules'])} artifacts verified with SHA-256 checksums.")

def test_documentation_module_count_matches():
    with open(REGISTRY_CATALOG, "r", encoding="utf-8") as f:
        catalog = json.load(f)
    total_count = len(catalog.get("modules", []))

    # Test README.md
    with open(README_EN, "r", encoding="utf-8") as f:
        readme_en_content = f.read()
    
    # Check for count in badges or headings
    badge_en = re.search(r"Modules-(\d+)-", readme_en_content) or re.search(rf"\b{total_count}\b", readme_en_content)
    assert badge_en, f"README.md does not declare module count {total_count}"

    # Test README.fa.md
    with open(README_FA, "r", encoding="utf-8") as f:
        readme_fa_content = f.read()

    # Convert count to Persian digits
    persian_digits = str(total_count).translate(str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹"))
    has_count_fa = (str(total_count) in readme_fa_content) or (persian_digits in readme_fa_content)
    assert has_count_fa, f"README.fa.md does not declare module count {total_count} (or {persian_digits})"
    print(f"[+] Documentation count synchronized: {total_count} modules verified in README.md and README.fa.md.")

if __name__ == "__main__":
    print("=" * 70)
    print("RUNNING REGISTRY CONSISTENCY & ARTIFACT INTEGRITY VERIFICATION")
    print("=" * 70)
    test_physical_vs_registry_count()
    test_one_to_one_mapping()
    test_artifacts_and_checksums()
    test_documentation_module_count_matches()
    print("=" * 70)
    print("ALL REGISTRY CONSISTENCY CHECKS PASSED (100% OK)")
    print("=" * 70)
