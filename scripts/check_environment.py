#!/usr/bin/env python3
"""
Cyber Hashira - Pre-Flight Environment & System Requirements Doctor
Verifies minimum system, hardware, runtime, and development requirements for running Cyber Hashira.
"""

import sys
import os
import platform
import shutil
import subprocess

def get_size_format(b):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"

def check_requirements():
    print("=" * 75)
    print("CYBER HASHIRA - SYSTEM & RUNTIME PRE-FLIGHT DOCTOR")
    print("=" * 75)

    all_passed = True
    warnings = []

    # 1. Operating System & Architecture
    os_name = platform.system()
    os_release = platform.release()
    arch = platform.machine()
    is_supported_os = os_name.lower() in ["windows", "linux", "darwin"]
    is_supported_arch = arch.lower() in ["x86_64", "amd64", "arm64", "aarch64"]

    status_os = "PASS" if is_supported_os and is_supported_arch else "FAIL"
    print(f"[*] OS & Architecture: {os_name} {os_release} ({arch}) ... [{status_os}]")
    if not is_supported_os or not is_supported_arch:
        all_passed = False
        warnings.append(f"Operating system {os_name} ({arch}) is not in official Tier 1/2 support list.")

    # 2. Hardware: CPU Cores
    cpu_count = os.cpu_count() or 1
    status_cpu = "PASS" if cpu_count >= 2 else "WARN"
    print(f"[*] CPU Cores: {cpu_count} cores (Min: 2 cores) ... [{status_cpu}]")
    if cpu_count < 2:
        warnings.append("Low CPU core count (< 2). Scans may be slower.")

    # 3. Hardware: Free Disk Space
    try:
        usage = shutil.disk_usage(os.path.abspath(os.sep))
        free_gb = usage.free / (1024 ** 3)
        status_disk = "PASS" if free_gb >= 1.0 else "FAIL"
        print(f"[*] Free Disk Space: {free_gb:.1f} GB available (Min: 1.0 GB) ... [{status_disk}]")
        if free_gb < 1.0:
            all_passed = False
            warnings.append(f"Insufficient disk space ({free_gb:.1f} GB). At least 1.0 GB required.")
    except Exception:
        print("[*] Free Disk Space: Unknown ... [SKIP]")

    # 4. Runtime: Python Version
    py_ver = sys.version_info
    py_str = f"{py_ver.major}.{py_ver.minor}.{py_ver.micro}"
    status_py = "PASS" if py_ver >= (3, 10) else "FAIL"
    print(f"[*] Python Runtime: v{py_str} (Min: v3.10) ... [{status_py}]")
    if py_ver < (3, 10):
        all_passed = False
        warnings.append(f"Python version {py_str} is outdated. Cyber Hashira modules require Python 3.10+.")

    # 5. Windows Specific: WebView2 Runtime
    if os_name == "Windows":
        webview2_found = False
        # Check common registry or program files paths
        paths_to_check = [
            os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\EdgeWebView\Application"),
            os.path.expandvars(r"%ProgramFiles%\Microsoft\EdgeWebView\Application"),
            os.path.expandvars(r"%LocalAppData%\Microsoft\EdgeWebView\Application")
        ]
        for p in paths_to_check:
            if os.path.isdir(p):
                webview2_found = True
                break
        status_wv = "PASS" if webview2_found else "WARN"
        print(f"[*] Microsoft WebView2 Runtime: {'Installed' if webview2_found else 'Not detected in standard path'} ... [{status_wv}]")
        if not webview2_found:
            warnings.append("WebView2 runtime was not detected. Tauri desktop GUI requires Microsoft Edge WebView2 on Windows.")

    # 6. Development Tools: Node.js & pnpm
    node_path = shutil.which("node")
    pnpm_path = shutil.which("pnpm")
    node_str = "Not installed"
    pnpm_str = "Not installed"
    if node_path:
        try:
            out = subprocess.check_output(["node", "--version"], text=True).strip()
            node_str = out
        except Exception:
            node_str = "Found"
    if pnpm_path:
        try:
            out = subprocess.check_output(["pnpm", "--version"], text=True).strip()
            pnpm_str = f"v{out}"
        except Exception:
            pnpm_str = "Found"
    print(f"[*] Frontend Toolchain: Node.js {node_str}, pnpm {pnpm_str} ... [{'PASS' if node_path and pnpm_path else 'OPTIONAL'}]")

    # 7. Development Tools: Rust & Cargo
    cargo_path = shutil.which("cargo")
    cargo_str = "Not in PATH"
    if not cargo_path:
        default_cargo = os.path.expanduser("~/.cargo/bin/cargo.exe" if os_name == "Windows" else "~/.cargo/bin/cargo")
        if os.path.isfile(default_cargo):
            cargo_path = default_cargo
    if cargo_path:
        try:
            out = subprocess.check_output([cargo_path, "--version"], text=True).strip()
            cargo_str = out.split()[1] if len(out.split()) > 1 else out
        except Exception:
            cargo_str = "Found"
    print(f"[*] Rust Core Toolchain: Cargo {cargo_str} ... [{'PASS' if cargo_path else 'OPTIONAL'}]")

    print("=" * 75)
    if all_passed:
        print("[RESULT] ALL MINIMUM SYSTEM REQUIREMENTS ARE MET! [OK]")
        print("Your machine is ready to run Cyber Hashira modules, CLI, and desktop client.")
    else:
        print("[RESULT] SOME CRITICAL REQUIREMENTS ARE MISSING! [FAIL]")
        for w in warnings:
            print(f"  - {w}")

    if warnings and all_passed:
        print("\n[ADVISORIES & RECOMMENDATIONS]:")
        for w in warnings:
            print(f"  * {w}")
    print("=" * 75)

if __name__ == "__main__":
    check_requirements()
