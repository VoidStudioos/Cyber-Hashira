# Contributing to Cyber Hashira

Thank you for contributing to Cyber Hashira!

## 1. Development Guidelines

1. **Keep the Host Lightweight:** Never bundle third-party tools or scanning engines directly into the Host. Build an independent module instead.
2. **Adhere to the Manifest Standard:** All modules must declare a valid `manifest.json` with permissions, checksum, entrypoint, and version compatibility.
3. **Respect ScopeGuard:** Modules must never bypass or ignore scope validation.
4. **No Shell Invocations:** Use direct process execution with argument arrays.
5. **Write Automated Tests:** Every new capability must include automated tests in `tests/`.

## 2. Module Development Quickstart

1. Create a directory under `modules/<your-module-name>`.
2. Implement your worker script or binary conforming to the `HostRequest` and `ModuleResponse` IPC contract.
3. Package the module using `scripts/build_sample_module.py` as a reference.
4. Add the module to `registry/v1/modules.json`.
5. Run `python tests/test_modular_lifecycle.py` to ensure all checks pass.
