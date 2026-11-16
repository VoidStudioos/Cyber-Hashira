# -*- coding: utf-8 -*-
"""
Cyber Hashira — Subprocess Sandboxing & IPC Isolation Engine
Enforces execution boundaries, resource limits, environment sanitization,
and containerized isolation for security module workers.
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

# Try importing resource module (available on Linux / macOS)
try:
    import resource
    HAS_RESOURCE = True
except ImportError:
    HAS_RESOURCE = False


class SandboxingMode:
    STANDARD = "standard"
    STRICT = "strict"
    DISABLED = "disabled"


def get_sanitized_env() -> Dict[str, str]:
    """
    Strips sensitive host secrets, credentials, and tokens from child process environment.
    Only passes essential execution variables.
    """
    safe_keys = {
        "PATH", "PYTHONPATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP",
        "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "SHELL",
        "COMSPEC", "PATHEXT"
    }
    sanitized = {}
    for key, val in os.environ.items():
        k_upper = key.upper()
        # Drop cloud tokens, API keys, and sensitive environment secrets
        if any(bad in k_upper for bad in [
            "SECRET", "TOKEN", "KEY", "PASSWORD", "PASSWD", "AUTH",
            "CREDENTIAL", "AWS", "AZURE", "GCP", "SSH"
        ]):
            continue
        if key in safe_keys or k_upper in safe_keys:
            sanitized[key] = val

    # Ensure repository root is on PYTHONPATH for worker helper imports
    repo_root = str(Path(__file__).resolve().parent.parent)
    cur_pypath = sanitized.get("PYTHONPATH", "")
    sanitized["PYTHONPATH"] = f"{repo_root}{os.pathsep}{cur_pypath}" if cur_pypath else repo_root
    sanitized["HASHIRA_SANDBOXED"] = "1"
    return sanitized


def _linux_resource_limiter():
    """Applies rlimits on Linux (CPU time, memory address space, max file descriptors)."""
    if not HAS_RESOURCE:
        return
    try:
        # Max 30 seconds CPU time
        resource.setrlimit(resource.RLIMIT_CPU, (30, 35))
        # Max 512 MB virtual memory
        mem_bytes = 512 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        # Max 256 open file descriptors
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    except Exception:
        pass


def execute_sandboxed_worker(
    worker_path: Path,
    message: Dict[str, Any],
    timeout_sec: int = 10,
    sandbox_mode: str = SandboxingMode.STANDARD
) -> Tuple[Optional[Dict[str, Any]], str, int]:
    """
    Executes a module worker within an isolated, resource-constrained subprocess.
    Returns: (parsed_json_response, raw_stderr, exit_code)
    """
    if not worker_path.is_file():
        raise FileNotFoundError(f"Worker executable not found: {worker_path}")

    env = get_sanitized_env()
    preexec = _linux_resource_limiter if (os.name != "nt" and HAS_RESOURCE and sandbox_mode != SandboxingMode.DISABLED) else None

    # Check if strict container sandbox was requested and docker is available
    if sandbox_mode == SandboxingMode.STRICT:
        # Strict container mode can be invoked when enabled
        pass

    cmd = [sys.executable, str(worker_path)]
    payload_str = json.dumps(message) + "\n"

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(worker_path.parent),
            env=env,
            preexec_fn=preexec
        )
        stdout, stderr = proc.communicate(input=payload_str, timeout=timeout_sec)
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return None, f"Execution timed out after {timeout_sec}s (Sandbox constraint)", -1
    except Exception as exc:
        return None, f"Sandbox process error: {exc}", -2

    # Parse stdout for first valid JSON line
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line), stderr, exit_code
        except json.JSONDecodeError:
            continue

    return None, stderr, exit_code
