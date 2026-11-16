# -*- coding: utf-8 -*-
"""
Cyber Hashira — Low-Level ScopeGuard Verification Subsystem
Prevents unauthorized active network and host operations by validating
target authorization boundaries at the innermost execution layer.
"""

import ipaddress
import urllib.parse
from typing import List, Optional, Set


class ScopeViolationError(PermissionError):
    """Raised when an operation targets an unauthorized asset."""
    pass


def normalize_target(target: str) -> str:
    """Extracts canonical hostname/IP from target string or URL."""
    if not target:
        return ""
    target = target.strip()
    if "://" in target:
        try:
            parsed = urllib.parse.urlparse(target)
            return (parsed.hostname or target).lower()
        except Exception:
            pass
    # Strip port if present
    if ":" in target and not target.startswith("["):
        parts = target.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0].lower()
    return target.lower()


def is_prohibited_infrastructure(host: str) -> bool:
    """Checks if target is sensitive metadata or loopback without explicit grant."""
    prohibited_exact = {"169.254.169.254", "metadata.google.internal", "instance-data"}
    if host.lower() in prohibited_exact:
        return True
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_link_local:
            return True
    except ValueError:
        pass
    return False


def verify(
    target: str,
    authorized_targets: Optional[List[str]] = None,
    scope_approved: bool = True,
    allow_metadata_probes: bool = False
) -> bool:
    """
    Mandatory lower-level verification function.
    Must be called before executing any active probe.
    Raises ScopeViolationError if boundary check fails.
    """
    if not scope_approved:
        raise ScopeViolationError(f"Scope approval flag is False for target '{target}'. Task execution blocked.")

    norm_target = normalize_target(target)
    if not norm_target:
        raise ScopeViolationError("Target is empty or invalid.")

    if not allow_metadata_probes and is_prohibited_infrastructure(norm_target):
        raise ScopeViolationError(f"Access to prohibited infrastructure metadata target '{norm_target}' is blocked.")

    if authorized_targets is not None:
        norm_authorized = {normalize_target(t) for t in authorized_targets if t}
        if norm_target not in norm_authorized and not any(norm_target.endswith(f".{auth}") for auth in norm_authorized if not auth.startswith(".")):
            raise ScopeViolationError(f"Target '{target}' is not in authorized scope whitelist: {list(norm_authorized)}")

    return True
