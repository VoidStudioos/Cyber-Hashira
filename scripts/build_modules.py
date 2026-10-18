import os
import tarfile
import hashlib
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES_DIR = os.path.join(BASE_DIR, "modules")
REGISTRY_DIR = os.path.join(BASE_DIR, "registry", "v1")
ARTIFACTS_DIR = os.path.join(BASE_DIR, "registry", "artifacts")

os.makedirs(REGISTRY_DIR, exist_ok=True)
os.makedirs(ARTIFACTS_DIR, exist_ok=True)

def package_module(module_folder_name):
    mod_dir = os.path.join(MODULES_DIR, module_folder_name)
    manifest_path = os.path.join(mod_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        return None

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    tar_name = f"{manifest['id']}-{manifest['version']}.tar.gz"
    tar_path = os.path.join(ARTIFACTS_DIR, tar_name)

    # Add all files in module directory
    files_to_pack = [f for f in os.listdir(mod_dir) if f != "__pycache__" and not f.endswith(".pyc")]

    # First pass
    with tarfile.open(tar_path, "w:gz") as tar:
        for fname in sorted(files_to_pack):
            tar.add(os.path.join(mod_dir, fname), arcname=fname)

    # Compute hash
    with open(tar_path, "rb") as f:
        sha256 = hashlib.sha256(f.read()).hexdigest()

    if "artifact" not in manifest:
        manifest["artifact"] = {
            "url": f"https://github.com/VoidStudioos/Cyber-Hashira/releases/download/v{manifest['version']}/{tar_name}",
            "sha256": "",
            "size_bytes": 0
        }

    manifest["artifact"]["sha256"] = sha256
    manifest["artifact"]["size_bytes"] = os.path.getsize(tar_path)

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    # Re-pack with updated manifest
    with tarfile.open(tar_path, "w:gz") as tar:
        for fname in sorted(files_to_pack):
            tar.add(os.path.join(mod_dir, fname), arcname=fname)

    with open(tar_path, "rb") as f:
        final_sha256 = hashlib.sha256(f.read()).hexdigest()

    manifest["artifact"]["sha256"] = final_sha256
    manifest["artifact"]["size_bytes"] = os.path.getsize(tar_path)

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    # Final archive
    with tarfile.open(tar_path, "w:gz") as tar:
        for fname in sorted(files_to_pack):
            tar.add(os.path.join(mod_dir, fname), arcname=fname)

    with open(tar_path, "rb") as f:
        verified_sha256 = hashlib.sha256(f.read()).hexdigest()

    manifest["artifact"]["sha256"] = verified_sha256
    manifest["artifact"]["size_bytes"] = os.path.getsize(tar_path)

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"[+] Packaged {manifest['id']} v{manifest['version']} -> {tar_name} (sha256: {verified_sha256[:16]}...)")
    return manifest

def main():
    modules = []
    for entry in sorted(os.listdir(MODULES_DIR)):
        full_p = os.path.join(MODULES_DIR, entry)
        if os.path.isdir(full_p):
            manifest = package_module(entry)
            if manifest:
                modules.append(manifest)

    catalog = {
        "schema_version": "1.0.0",
        "generated_at": "2026-10-17T12:00:00Z",
        "modules": modules
    }

    catalog_path = os.path.join(REGISTRY_DIR, "modules.json")
    with open(catalog_path, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2)

    print(f"[*] Updated registry catalog with {len(modules)} modules at {catalog_path}")

if __name__ == "__main__":
    main()
