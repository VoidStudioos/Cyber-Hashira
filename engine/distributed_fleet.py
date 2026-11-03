# -*- coding: utf-8 -*-
"""
Cyber Hashira — Distributed Node Fleet & Proxy Mesh
Manages remote scanner worker daemons, heartbeat telemetry, and rotating proxy chains.
"""

import time
import uuid
import random
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class ScannerNode:
    node_id: str
    hostname: str
    ip_address: str
    region: str
    status: str  # ONLINE, BUSY, OFFLINE
    capabilities: List[str]
    active_tasks: int = 0
    total_scans_completed: int = 0
    last_heartbeat: float = field(default_factory=time.time)


@dataclass
class ProxyNode:
    proxy_url: str  # socks5://..., http://...
    protocol: str
    latency_ms: float
    success_count: int = 0
    failure_count: int = 0
    banned: bool = False
    last_used: float = 0.0


class ProxyRotator:
    """Manages an intelligent rotating pool of proxies."""

    def __init__(self, proxies: Optional[List[str]] = None):
        self._pool: List[ProxyNode] = []
        if proxies:
            for p in proxies:
                self.add_proxy(p)
        else:
            # Default internal simulated resilient egress mesh
            self.add_proxy("socks5://127.0.0.1:9050")  # Tor local daemon
            self.add_proxy("http://proxy-us-east.internal:8080")
            self.add_proxy("http://proxy-eu-central.internal:8080")
            self.add_proxy("http://proxy-ap-southeast.internal:8080")

    def add_proxy(self, proxy_url: str):
        proto = proxy_url.split("://")[0] if "://" in proxy_url else "http"
        self._pool.append(ProxyNode(
            proxy_url=proxy_url,
            protocol=proto,
            latency_ms=round(random.uniform(40.0, 180.0), 1)
        ))

    def get_proxy(self) -> Optional[str]:
        """Returns the healthiest, least recently used proxy."""
        available = [p for p in self._pool if not p.banned]
        if not available:
            # Reset temporary bans if exhausted
            for p in self._pool:
                p.banned = False
            available = self._pool

        selected = min(available, key=lambda p: (p.last_used, p.latency_ms))
        selected.last_used = time.time()
        return selected.proxy_url

    def report_result(self, proxy_url: str, success: bool, status_code: Optional[int] = None):
        for p in self._pool:
            if p.proxy_url == proxy_url:
                if success:
                    p.success_count += 1
                else:
                    p.failure_count += 1
                    if status_code in [403, 429] or p.failure_count >= 5:
                        p.banned = True
                break

    def list_proxies(self) -> List[Dict[str, Any]]:
        return [
            {
                "proxy_url": p.proxy_url,
                "protocol": p.protocol,
                "latency_ms": p.latency_ms,
                "success_count": p.success_count,
                "failure_count": p.failure_count,
                "banned": p.banned
            } for p in self._pool
        ]


class FleetManager:
    """Coordinates remote Cyber-Hashira scanner agents."""

    def __init__(self):
        self._nodes: Dict[str, ScannerNode] = {}
        self.proxy_rotator = ProxyRotator()
        self._register_default_cluster()

    def _register_default_cluster(self):
        # Register local master node and simulated high-speed edge nodes
        self.register_node(ScannerNode(
            node_id="node-master-local",
            hostname="localhost-primary",
            ip_address="127.0.0.1",
            region="local-workstation",
            status="ONLINE",
            capabilities=["all-200-modules", "stdio-ipc", "raw-socket"]
        ))
        self.register_node(ScannerNode(
            node_id="node-cloud-us-east",
            hostname="scanner-worker-us01.hashira.corp",
            ip_address="198.51.100.14",
            region="us-east-1",
            status="ONLINE",
            capabilities=["external-recon", "port-scan", "waf-evasion"]
        ))
        self.register_node(ScannerNode(
            node_id="node-cloud-eu-frankfurt",
            hostname="scanner-worker-eu02.hashira.corp",
            ip_address="203.0.113.88",
            region="eu-central-1",
            status="ONLINE",
            capabilities=["external-recon", "api-fuzzing", "web3-audit"]
        ))

    def register_node(self, node: ScannerNode):
        self._nodes[node.node_id] = node

    def list_nodes(self) -> List[Dict[str, Any]]:
        return [
            {
                "node_id": n.node_id,
                "hostname": n.hostname,
                "ip_address": n.ip_address,
                "region": n.region,
                "status": n.status,
                "capabilities": n.capabilities,
                "active_tasks": n.active_tasks,
                "total_scans_completed": n.total_scans_completed
            } for n in self._nodes.values()
        ]

    def dispatch_task(self, module_id: str, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Selects the best suited online node and routes scan execution."""
        online_nodes = [n for n in self._nodes.values() if n.status == "ONLINE"]
        if not online_nodes:
            raise RuntimeError("No scanner nodes online in fleet.")

        # Choose least busy node
        chosen = min(online_nodes, key=lambda n: n.active_tasks)
        chosen.active_tasks += 1
        chosen.total_scans_completed += 1

        proxy = self.proxy_rotator.get_proxy()
        return {
            "dispatched": True,
            "assigned_node": chosen.node_id,
            "node_hostname": chosen.hostname,
            "region": chosen.region,
            "proxy_used": proxy,
            "module_id": module_id,
            "target": target
        }
