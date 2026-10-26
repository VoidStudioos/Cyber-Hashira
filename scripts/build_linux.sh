#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/.."

echo "======================================================"
echo "  CYBER HASHIRA — LINUX DISTRIBUTION PACKAGER"
echo "======================================================"

python3 scripts/build_installers.py

echo ""
echo "Standalone packages generated in dist/packages/"
