import os
import tarfile
import hashlib
import json
import shutil

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE_DIR = os.path.join(BASE_DIR, "modules", "sample-dns")
REGISTRY_DIR = os.path.join(BASE_DIR, "registry", "v1")
ARTIFACTS_DIR = os.path.join(BASE_DIR, "registry", "artifacts")

os.makedirs(REGISTRY_DIR, exist_ok=True)
os.makedirs(ARTIFACTS_DIR, exist_ok=True)

# 1. Read manifest
manifest_path = os.path.join(MODULE_DIR, "manifest.json")
with open(manifest_path, "r", encoding="utf-8") as f:
    manifest = json.load(f)

tar_name = f"{manifest['id']}-{manifest['version']}.tar.gz"
tar_path = os.path.join(ARTIFACTS_DIR, tar_name)

# 2. Create tar.gz package containing manifest.json and worker.py
with tarfile.open(tar_path, "w:gz") as tar:
    tar.add(os.path.join(MODULE_DIR, "manifest.json"), arcname="manifest.json")
    tar.add(os.path.join(MODULE_DIR, "worker.py"), arcname="worker.py")

# 3. Compute SHA-256
with open(tar_path, "rb") as f:
    sha256 = hashlib.sha256(f.read()).hexdigest()

file_size = os.path.getsize(tar_path)
print(f"Generated {tar_name}: size={file_size} bytes, sha256={sha256}")

# 4. Update manifest.json with real SHA-256 and size
manifest["artifact"]["sha256"] = sha256
manifest["artifact"]["size_bytes"] = file_size

with open(manifest_path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)

# Re-add updated manifest to tar.gz
with tarfile.open(tar_path, "w:gz") as tar:
    tar.add(os.path.join(MODULE_DIR, "manifest.json"), arcname="manifest.json")
    tar.add(os.path.join(MODULE_DIR, "worker.py"), arcname="worker.py")

# Recompute final sha256
with open(tar_path, "rb") as f:
    final_sha256 = hashlib.sha256(f.read()).hexdigest()
final_size = os.path.getsize(tar_path)

manifest["artifact"]["sha256"] = final_sha256
manifest["artifact"]["size_bytes"] = final_size

with open(manifest_path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)

# Re-pack with final manifest
with tarfile.open(tar_path, "w:gz") as tar:
    tar.add(os.path.join(MODULE_DIR, "manifest.json"), arcname="manifest.json")
    tar.add(os.path.join(MODULE_DIR, "worker.py"), arcname="worker.py")

with open(tar_path, "rb") as f:
    verified_sha256 = hashlib.sha256(f.read()).hexdigest()

manifest["artifact"]["sha256"] = verified_sha256
manifest["artifact"]["size_bytes"] = os.path.getsize(tar_path)

with open(manifest_path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)

# 5. Generate registry/v1/modules.json
registry_catalog = {
    "schema_version": "1.0.0",
    "generated_at": "2026-10-17T12:00:00Z",
    "modules": [
        manifest
    ]
}

registry_catalog_path = os.path.join(REGISTRY_DIR, "modules.json")
with open(registry_catalog_path, "w", encoding="utf-8") as f:
    json.dump(registry_catalog, f, indent=2)

print(f"Registry catalog generated at {registry_catalog_path}")
