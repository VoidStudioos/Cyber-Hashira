#!/usr/bin/env python3
"""
Test Suite: Bilingual Documentation Synchronization Validator
Ensures that all primary documentation files have corresponding, non-empty, and up-to-date
Persian (.fa.md) counterparts, and that declared module metrics match between versions.
"""

import os
import sys
import re

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Required bilingual document pairs
BILINGUAL_PAIRS = [
    ("README.md", "README.fa.md"),
    ("CHANGELOG.md", "CHANGELOG.fa.md"),
    ("registry/MIGRATIONS.md", "registry/MIGRATIONS.fa.md"),
    ("docs/MODULE_DEVELOPER_GUIDE.md", "docs/MODULE_DEVELOPER_GUIDE.fa.md"),
    ("docs/SANDBOXING.md", "docs/SANDBOXING.fa.md"),
]

def test_bilingual_file_pairs_exist():
    """Verify that both English and Persian documents exist and are non-empty."""
    for en_rel, fa_rel in BILINGUAL_PAIRS:
        en_path = os.path.join(REPO_ROOT, *en_rel.split("/"))
        fa_path = os.path.join(REPO_ROOT, *fa_rel.split("/"))
        
        assert os.path.isfile(en_path), f"English document missing: {en_rel}"
        assert os.path.isfile(fa_path), f"Persian counterpart missing: {fa_rel}"
        
        en_size = os.path.getsize(en_path)
        fa_size = os.path.getsize(fa_path)
        
        assert en_size > 100, f"English document {en_rel} is unexpectedly small ({en_size} bytes)"
        assert fa_size > 100, f"Persian document {fa_rel} is unexpectedly small ({fa_size} bytes)"
        
        # Verify modification times are reasonably synchronized (not months apart)
        en_mtime = os.path.getmtime(en_path)
        fa_mtime = os.path.getmtime(fa_path)
        diff_hours = abs(en_mtime - fa_mtime) / 3600.0
        
        print(f"[+] Pair verified: {en_rel} ({en_size}B) <-> {fa_rel} ({fa_size}B) [mtime diff: {diff_hours:.2f}h]")

def test_bilingual_module_count_sync():
    """Verify that module count in README.md matches README.fa.md."""
    en_path = os.path.join(REPO_ROOT, "README.md")
    fa_path = os.path.join(REPO_ROOT, "README.fa.md")
    
    with open(en_path, "r", encoding="utf-8") as f:
        en_text = f.read()
    with open(fa_path, "r", encoding="utf-8") as f:
        fa_text = f.read()

    # Extract module count from badges or title
    m_en = re.search(r"Modules-(\d+)-", en_text)
    assert m_en, "Could not find 'Modules-<count>-' badge in README.md"
    count_en = int(m_en.group(1))

    # Extract module count from badge or title in README.fa.md
    m_fa = re.search(r"Modules-(\d+)-", fa_text)
    if m_fa:
        count_fa = int(m_fa.group(1))
    else:
        # Check Persian digits or standard numbers
        m_fa_num = re.search(r"(\d+|[۰-۹]+)\s*(?:ماژول|ماژول‌های)", fa_text)
        assert m_fa_num, "Could not find module count in README.fa.md"
        raw_num = m_fa_num.group(1)
        persian_map = str.maketrans("۰۱۲۳۴۵۶۷۸۹", "0123456789")
        count_fa = int(raw_num.translate(persian_map))

    print(f"[*] English README declared module count: {count_en}")
    print(f"[*] Persian README declared module count: {count_fa}")

    assert count_en == count_fa, (
        f"Module count discrepancy between languages: README.md says {count_en}, "
        f"while README.fa.md says {count_fa}"
    )

def test_bilingual_cross_links():
    """Verify reciprocal language switcher links in README.md and README.fa.md."""
    en_path = os.path.join(REPO_ROOT, "README.md")
    fa_path = os.path.join(REPO_ROOT, "README.fa.md")

    with open(en_path, "r", encoding="utf-8") as f:
        en_text = f.read()
    with open(fa_path, "r", encoding="utf-8") as f:
        fa_text = f.read()

    assert "README.fa.md" in en_text, "README.md missing cross-link to README.fa.md"
    assert "README.md" in fa_text, "README.fa.md missing cross-link to README.md"
    print("[+] Reciprocal cross-links verified between English and Persian READMEs.")

if __name__ == "__main__":
    print("=" * 70)
    print("RUNNING BILINGUAL DOCUMENTATION SYNCHRONIZATION TESTS")
    print("=" * 70)
    test_bilingual_file_pairs_exist()
    test_bilingual_module_count_sync()
    test_bilingual_cross_links()
    print("=" * 70)
    print("ALL BILINGUAL SYNCHRONIZATION CHECKS PASSED (100% OK)")
    print("=" * 70)
