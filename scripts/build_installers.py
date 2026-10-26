#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cyber Hashira — Standalone Installer & Distribution Packaging Engine
Generates standalone packages, portable bundles, and installers for Windows & Linux.

Outputs:
  dist/packages/
    ├── cyber-hashira-windows-x64-v1.0.0.zip
    ├── cyber-hashira-linux-x64-v1.0.0.tar.gz
    └── install.sh / install.bat
"""

import os
import sys
import shutil
import zipfile
import tarfile
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = REPO_ROOT / "dist"
PACKAGES_DIR = DIST_DIR / "packages"
DESKTOP_DIR = REPO_ROOT / "apps" / "desktop"


def ensure_frontend_built():
    """Ensure desktop/web dist frontend assets are built."""
    frontend_dist = DESKTOP_DIR / "dist"
    if not frontend_dist.is_dir() or not (frontend_dist / "index.html").is_file():
        print("[*] Building frontend assets (Vite / React)...")
        npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
        res = os.system(f"{npm_cmd} --prefix \"{DESKTOP_DIR}\" run build")
        if res != 0:
            print("[!] Warning: npm build returned non-zero code. Checking if dist exists...")
    else:
        print("[OK] Frontend assets verified in apps/desktop/dist")


def create_windows_bundle(version="1.0.0"):
    """Package standalone portable bundle for Windows."""
    print("\n" + "=" * 60)
    print(f"[*] Packaging Windows x64 Standalone Bundle v{version}...")
    print("=" * 60)

    win_stage = DIST_DIR / "cyber-hashira-windows-x64"
    if win_stage.is_dir():
        shutil.rmtree(win_stage)
    win_stage.mkdir(parents=True, exist_ok=True)

    # 1. Copy core directories
    items_to_copy = ["modules", "registry", "ui", "scripts", "tests"]
    for item in items_to_copy:
        src = REPO_ROOT / item
        dst = win_stage / item
        if src.is_dir():
            print(f"  -> Copying {item}/")
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.git*"))

    # 2. Copy root launcher
    shutil.copy2(REPO_ROOT / "hashira.py", win_stage / "hashira.py")

    # 3. Copy frontend web assets
    dst_dist = win_stage / "web_dist"
    if (DESKTOP_DIR / "dist").is_dir():
        print("  -> Copying frontend web assets...")
        shutil.copytree(DESKTOP_DIR / "dist", dst_dist)

    # 4. Create one-click Windows Launchers (.bat & .vbs)
    launch_web_bat = win_stage / "Launch-Web-Panel.bat"
    launch_web_bat.write_text(
        "@echo off\r\n"
        "title Cyber Hashira - Web Security Dashboard\r\n"
        "echo Launching Cyber Hashira Web Dashboard on http://localhost:8080...\r\n"
        "python hashira.py web --port 8080\r\n"
        "pause\r\n",
        encoding="utf-8"
    )

    launch_tui_bat = win_stage / "Launch-Terminal-TUI.bat"
    launch_tui_bat.write_text(
        "@echo off\r\n"
        "title Cyber Hashira - Terminal TUI Console\r\n"
        "python hashira.py tui\r\n"
        "pause\r\n",
        encoding="utf-8"
    )

    run_tests_bat = win_stage / "Verify-All-120-Modules.bat"
    run_tests_bat.write_text(
        "@echo off\r\n"
        "title Cyber Hashira - Verification Matrix\r\n"
        "python hashira.py matrix\r\n"
        "pause\r\n",
        encoding="utf-8"
    )

    # 5. Create Windows Installer / Setup Script
    install_bat = win_stage / "install-windows.bat"
    install_bat.write_text(
        "@echo off\r\n"
        "echo ====================================================\r\n"
        "echo   CYBER HASHIRA - WINDOWS WORKSTATION SETUP\r\n"
        "echo ====================================================\r\n"
        "echo Checking Python installation...\r\n"
        "python --version >nul 2>&1\r\n"
        "if %errorlevel% neq 0 (\r\n"
        "    echo [!] Error: Python is not installed or not in PATH.\r\n"
        "    echo Please install Python 3.10+ from python.org\r\n"
        "    pause\r\n"
        "    exit /b 1\r\n"
        ")\r\n"
        "echo Installing required dependencies (Flask, Cryptography, Rich)...\r\n"
        "python -m pip install flask flask-cors cryptography rich\r\n"
        "echo.\r\n"
        "echo [✓] Installation complete! You can now launch:\r\n"
        "echo   - Launch-Web-Panel.bat\r\n"
        "echo   - Launch-Terminal-TUI.bat\r\n"
        "pause\r\n",
        encoding="utf-8"
    )

    # 6. Compress into ZIP
    PACKAGES_DIR.mkdir(parents=True, exist_ok=True)
    zip_path = PACKAGES_DIR / f"cyber-hashira-windows-x64-v{version}.zip"
    print(f"[*] Compressing Windows package -> {zip_path.name}...")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(win_stage):
            for file in files:
                full_path = Path(root) / file
                arcname = full_path.relative_to(DIST_DIR)
                zf.write(full_path, arcname)

    print(f"[OK] Windows bundle created: {zip_path.name} ({round(zip_path.stat().st_size / (1024*1024), 2)} MB)")
    return zip_path


def create_linux_bundle(version="1.0.0"):
    """Package standalone portable bundle for Linux."""
    print("\n" + "=" * 60)
    print(f"[*] Packaging Linux x64 Standalone Bundle v{version}...")
    print("=" * 60)

    linux_stage = DIST_DIR / "cyber-hashira-linux-x64"
    if linux_stage.is_dir():
        shutil.rmtree(linux_stage)
    linux_stage.mkdir(parents=True, exist_ok=True)

    # 1. Copy core directories
    items_to_copy = ["modules", "registry", "ui", "scripts", "tests"]
    for item in items_to_copy:
        src = REPO_ROOT / item
        dst = linux_stage / item
        if src.is_dir():
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.git*"))

    # 2. Copy root launcher
    shutil.copy2(REPO_ROOT / "hashira.py", linux_stage / "hashira.py")

    # 3. Copy frontend web assets
    dst_dist = linux_stage / "web_dist"
    if (DESKTOP_DIR / "dist").is_dir():
        shutil.copytree(DESKTOP_DIR / "dist", dst_dist)

    # 4. Linux Shell Launchers
    web_sh = linux_stage / "launch-web.sh"
    web_sh.write_text(
        "#!/usr/bin/env bash\n"
        "echo \"⚔️  Starting Cyber Hashira Web Dashboard on http://localhost:8080...\"\n"
        "python3 hashira.py web --port 8080\n",
        encoding="utf-8"
    )

    tui_sh = linux_stage / "launch-tui.sh"
    tui_sh.write_text(
        "#!/usr/bin/env bash\n"
        "python3 hashira.py tui\n",
        encoding="utf-8"
    )

    matrix_sh = linux_stage / "verify-matrix.sh"
    matrix_sh.write_text(
        "#!/usr/bin/env bash\n"
        "python3 hashira.py matrix\n",
        encoding="utf-8"
    )

    # 5. Linux .desktop Entry (App Menu)
    desktop_entry = linux_stage / "cyber-hashira.desktop"
    desktop_entry.write_text(
        "[Desktop Entry]\n"
        "Name=Cyber Hashira\n"
        "Comment=Advanced Cybersecurity & Penetration Testing Platform\n"
        "Exec=bash -c 'cd \"$(dirname \"%k\")\" && ./launch-web.sh'\n"
        "Icon=utilities-terminal\n"
        "Terminal=true\n"
        "Type=Application\n"
        "Categories=Security;Development;System;\n",
        encoding="utf-8"
    )

    # 6. Linux One-Click Installer
    install_sh = linux_stage / "install-linux.sh"
    install_sh.write_text(
        "#!/usr/bin/env bash\n"
        "set -e\n"
        "echo \"====================================================\"\n"
        "echo \"  CYBER HASHIRA — LINUX WORKSTATION INSTALLER\"\n"
        "echo \"====================================================\"\n"
        "\n"
        "chmod +x launch-web.sh launch-tui.sh verify-matrix.sh || true\n"
        "\n"
        "echo \"[*] Checking Python 3...\"\n"
        "if ! command -v python3 &> /dev/null; then\n"
        "    echo \"[!] Python 3 not found. Please install python3 & python3-pip\"\n"
        "    exit 1\n"
        "fi\n"
        "\n"
        "echo \"[*] Installing Python dependencies...\"\n"
        "python3 -m pip install --upgrade flask flask-cors cryptography rich || true\n"
        "\n"
        "echo \"[✓] Setup complete! You can run:\"\n"
        "echo \"    ./launch-web.sh    (Web Dashboard)\"\n"
        "echo \"    ./launch-tui.sh    (Terminal Interface)\"\n",
        encoding="utf-8"
    )

    # 7. Compress into tar.gz
    PACKAGES_DIR.mkdir(parents=True, exist_ok=True)
    tar_path = PACKAGES_DIR / f"cyber-hashira-linux-x64-v{version}.tar.gz"
    print(f"[*] Compressing Linux package -> {tar_path.name}...")
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(linux_stage, arcname="cyber-hashira-linux-x64")

    print(f"[OK] Linux bundle created: {tar_path.name} ({round(tar_path.stat().st_size / (1024*1024), 2)} MB)")
    return tar_path


def main():
    print("======================================================================")
    print("CYBER HASHIRA - BUILD & DISTRIBUTION PACKAGING ENGINE")
    print("======================================================================")

    ensure_frontend_built()
    win_pkg = create_windows_bundle()
    linux_pkg = create_linux_bundle()

    print("\n======================================================================")
    print("[SUCCESS] ALL STANDALONE INSTALLER PACKAGES GENERATED SUCCESSFULLY!")
    print("======================================================================")
    print(f"  Windows Package: {win_pkg}")
    print(f"  Linux Package:   {linux_pkg}")
    print("=" * 70)


if __name__ == "__main__":
    main()
