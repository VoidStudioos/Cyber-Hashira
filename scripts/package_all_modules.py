#!/usr/bin/env python3
"""
Cyber Hashira - Module Packaging & Registry Synchronizer
Packages all modules in modules/ to registry/artifacts/ and updates registry/v1/modules.json.
"""

import os
import json
import hashlib
import tarfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES_DIR = os.path.join(REPO_ROOT, "modules")
ARTIFACTS_DIR = os.path.join(REPO_ROOT, "registry", "artifacts")
REGISTRY_PATH = os.path.join(REPO_ROOT, "registry", "v1", "modules.json")

def main():
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    
    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        catalog = json.load(f)

    existing_modules = {m["id"]: m for m in catalog.get("modules", [])}

    for mod_name in sorted(os.listdir(MODULES_DIR)):
        mod_dir = os.path.join(MODULES_DIR, mod_name)
        if not os.path.isdir(mod_dir):
            continue
            
        manifest_path = os.path.join(mod_dir, "manifest.json")
        if not os.path.isfile(manifest_path):
            continue
            
        with open(manifest_path, "r", encoding="utf-8") as mf:
            manifest = json.load(mf)
            
        mod_id = manifest["id"]
        version = manifest["version"]
        tar_name = f"{mod_id}-{version}.tar.gz"
        tar_path = os.path.join(ARTIFACTS_DIR, tar_name)
        
        # Build clean tar.gz archive
        with tarfile.open(tar_path, "w:gz") as tar:
            for item in sorted(os.listdir(mod_dir)):
                item_path = os.path.join(mod_dir, item)
                tar.add(item_path, arcname=item)
                
        # Calculate SHA256 & size
        with open(tar_path, "rb") as tf:
            data = tf.read()
            sha256 = hashlib.sha256(data).hexdigest()
            size = len(data)
            
        entry = {
            "id": manifest["id"],
            "name": manifest["name"],
            "description": manifest["description"],
            "author": manifest["author"],
            "version": manifest["version"],
            "min_host_version": manifest["min_host_version"],
            "category": manifest["category"],
            "icon": manifest.get("icon", "shield"),
            "banner_url": manifest.get("banner_url", ""),
            "supported_os": manifest["supported_os"],
            "supported_arch": manifest["supported_arch"],
            "required_dependencies": manifest.get("required_dependencies", {}),
            "optional_dependencies": manifest.get("optional_dependencies", {}),
            "required_permissions": manifest.get("required_permissions", []),
            "entry_point": manifest["entry_point"],
            "config_schema": manifest.get("config_schema", {}),
            "contracts": manifest.get("contracts", {}),
            "artifact": {
                "url": f"https://github.com/VoidStudioos/Cyber-Hashira/releases/download/v{version}/{tar_name}",
                "sha256": sha256,
                "size_bytes": size
            }
        }
        existing_modules[mod_id] = entry
        print(f"Packaged [{mod_id} v{version}] -> {tar_name} (sha256: {sha256[:12]}..., {size} B)")

    catalog["modules"] = [existing_modules[k] for k in sorted(existing_modules.keys())]
    
    with open(REGISTRY_PATH, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2)
        
    print(f"\nSuccessfully synchronized {len(catalog['modules'])} modules in registry/v1/modules.json.")

if __name__ == "__main__":
    main()
