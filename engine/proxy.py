# -*- coding: utf-8 -*-
"""
Cyber Hashira — Local HTTP Traffic Inspection Proxy Subsystem
Captures and logs live HTTP/HTTPS traffic from browsers and client tools
into an in-memory ring buffer for manual review, inspection, and "Send to Repeater" workflows.
"""

import os
import sys
import socket
import select
import threading
import datetime
import uuid
import time
from typing import Dict, Any, List, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import urllib.request
import ssl

TRAFFIC_BUFFER: List[Dict[str, Any]] = []
BUFFER_LOCK = threading.Lock()
MAX_BUFFER_SIZE = 500

GLOBAL_PROXY_SERVER = None
PROXY_THREAD = None
PROXY_RUNNING = False
PROXY_CONFIG = {"host": "127.0.0.1", "port": 8081}


class HashiraProxyHandler(BaseHTTPRequestHandler):
    """Handles HTTP proxy requests and captures live telemetry."""

    def log_message(self, format, *args):
        """Suppress default stderr request logging."""
        pass

    def do_CONNECT(self):
        """Handle HTTPS CONNECT tunneling."""
        host_port = self.path.split(":")
        target_host = host_port[0]
        target_port = int(host_port[1]) if len(host_port) > 1 else 443

        start_time = time.perf_counter()
        try:
            target_sock = socket.create_connection((target_host, target_port), timeout=10)
            self.send_response(200, "Connection Established")
            self.end_headers()

            # Record CONNECT initiation in traffic log
            entry = {
                "id": str(uuid.uuid4())[:8],
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "method": "CONNECT",
                "url": f"https://{self.path}",
                "host": target_host,
                "status_code": 200,
                "type": "HTTPS_TUNNEL",
                "request_headers": dict(self.headers),
                "response_headers": {"Connection": "Established"},
                "request_body": "",
                "response_body": "[Encrypted TLS Tunnel]",
                "elapsed_ms": 0.0
            }
            with BUFFER_LOCK:
                TRAFFIC_BUFFER.append(entry)
                if len(TRAFFIC_BUFFER) > MAX_BUFFER_SIZE:
                    TRAFFIC_BUFFER.pop(0)

            # Bi-directional stream forwarding
            conns = [self.connection, target_sock]
            while True:
                rlist, _, xlist = select.select(conns, [], conns, 10)
                if xlist or not rlist:
                    break
                for s in rlist:
                    other = target_sock if s is self.connection else self.connection
                    data = s.recv(8192)
                    if not data:
                        return
                    other.sendall(data)
        except Exception:
            try:
                self.send_error(502, "Bad Gateway")
            except Exception:
                pass
        finally:
            try:
                target_sock.close()
            except Exception:
                pass

    def do_GET(self):
        self._forward_http("GET")

    def do_POST(self):
        self._forward_http("POST")

    def do_PUT(self):
        self._forward_http("PUT")

    def do_DELETE(self):
        self._forward_http("DELETE")

    def do_PATCH(self):
        self._forward_http("PATCH")

    def do_HEAD(self):
        self._forward_http("HEAD")

    def do_OPTIONS(self):
        self._forward_http("OPTIONS")

    def _forward_http(self, method: str):
        """Forwards standard HTTP request and records full payload telemetry."""
        url = self.path
        if not url.startswith("http://") and not url.startswith("https://"):
            host_hdr = self.headers.get("Host", "localhost")
            url = f"http://{host_hdr}{url}"

        parsed_url = urllib.parse.urlparse(url)
        host = parsed_url.hostname or self.headers.get("Host", "unknown")

        content_length = int(self.headers.get("Content-Length", 0))
        req_body = self.rfile.read(content_length) if content_length > 0 else b""
        req_body_str = req_body.decode("utf-8", errors="replace") if req_body else ""

        headers_dict = dict(self.headers)
        headers_dict.pop("Proxy-Connection", None)

        start_time = time.perf_counter()
        status_code = 502
        resp_headers = {}
        resp_body_str = ""

        try:
            req = urllib.request.Request(
                url=url,
                data=req_body if req_body else None,
                headers=headers_dict,
                method=method
            )
            # Create unverified SSL context for self-signed certificates
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, timeout=12, context=ctx) as response:
                status_code = response.status
                resp_headers = dict(response.headers)
                resp_content = response.read()
                try:
                    resp_body_str = resp_content.decode("utf-8")
                except Exception:
                    resp_body_str = f"[Binary data: {len(resp_content)} bytes]"

                elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

                # Send back to client
                self.send_response(status_code)
                for k, v in resp_headers.items():
                    if k.lower() not in ["transfer-encoding", "content-encoding"]:
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(resp_content)

        except urllib.error.HTTPError as he:
            status_code = he.code
            resp_headers = dict(he.headers)
            err_content = he.read()
            resp_body_str = err_content.decode("utf-8", errors="replace")
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

            self.send_response(status_code)
            for k, v in resp_headers.items():
                if k.lower() not in ["transfer-encoding", "content-encoding"]:
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(err_content)

        except Exception as e:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            resp_body_str = f"[Proxy Error: {str(e)}]"
            try:
                self.send_error(502, f"Proxy Error: {e}")
            except Exception:
                pass

        # Record captured transaction
        entry = {
            "id": str(uuid.uuid4())[:8],
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "method": method,
            "url": url,
            "host": host,
            "status_code": status_code,
            "type": "HTTP",
            "request_headers": headers_dict,
            "response_headers": resp_headers,
            "request_body": req_body_str,
            "response_body": resp_body_str,
            "elapsed_ms": elapsed_ms
        }
        with BUFFER_LOCK:
            TRAFFIC_BUFFER.append(entry)
            if len(TRAFFIC_BUFFER) > MAX_BUFFER_SIZE:
                TRAFFIC_BUFFER.pop(0)


def start_proxy(host: str = "127.0.0.1", port: int = 8081) -> bool:
    """Starts the inspection proxy listener in a background daemon thread."""
    global GLOBAL_PROXY_SERVER, PROXY_THREAD, PROXY_RUNNING, PROXY_CONFIG
    if PROXY_RUNNING:
        return True

    try:
        GLOBAL_PROXY_SERVER = HTTPServer((host, port), HashiraProxyHandler)
        PROXY_THREAD = threading.Thread(target=GLOBAL_PROXY_SERVER.serve_forever, daemon=True)
        PROXY_THREAD.start()
        PROXY_RUNNING = True
        PROXY_CONFIG = {"host": host, "port": port}
        print(f"[+] Cyber Hashira Inspection Proxy active on {host}:{port}")
        return True
    except Exception as e:
        print(f"[!] Failed to bind proxy server on {host}:{port}: {e}")
        PROXY_RUNNING = False
        return False


def stop_proxy():
    """Stops the proxy listener."""
    global GLOBAL_PROXY_SERVER, PROXY_RUNNING
    if GLOBAL_PROXY_SERVER and PROXY_RUNNING:
        try:
            GLOBAL_PROXY_SERVER.shutdown()
            GLOBAL_PROXY_SERVER.server_close()
        except Exception:
            pass
        PROXY_RUNNING = False
        print("[*] Cyber Hashira Inspection Proxy stopped.")


def get_proxy_status() -> Dict[str, Any]:
    """Returns current proxy operational state."""
    return {
        "running": PROXY_RUNNING,
        "host": PROXY_CONFIG["host"],
        "port": PROXY_CONFIG["port"],
        "captured_count": len(TRAFFIC_BUFFER)
    }


def get_traffic_history(limit: int = 100, filter_host: Optional[str] = None) -> List[Dict[str, Any]]:
    """Returns recently captured HTTP/S transactions."""
    with BUFFER_LOCK:
        items = list(TRAFFIC_BUFFER)

    if filter_host:
        items = [i for i in items if filter_host.lower() in i.get("host", "").lower()]

    return list(reversed(items[-limit:]))


def clear_traffic_history():
    """Clears captured traffic buffer."""
    with BUFFER_LOCK:
        TRAFFIC_BUFFER.clear()
