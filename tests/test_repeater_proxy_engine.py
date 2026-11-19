# -*- coding: utf-8 -*-
"""
Cyber Hashira — Tests for Interactive Repeater and Traffic Proxy Subsystems
Verifies ScopeGuard enforcement, history persistence, proxy lifecycle, and Flask API routes.
"""

import os
import sys
import json
import secrets
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.repeater import RepeaterEngine
from engine.proxy import (
    start_proxy,
    stop_proxy,
    get_proxy_status,
    get_traffic_history,
    clear_traffic_history,
    TRAFFIC_BUFFER,
    BUFFER_LOCK
)
from ui.web.app import app


@pytest.fixture
def temp_history_file(tmp_path):
    return tmp_path / "test_repeater_history.json"


@pytest.fixture
def repeater_engine(temp_history_file):
    return RepeaterEngine(history_file=temp_history_file)


class TestRepeaterEngine:
    """Test suite for RepeaterEngine core functionality and ScopeGuard boundary."""

    def test_scopeguard_blocks_unauthorized_target(self, repeater_engine):
        """Verify that ScopeGuard actively blocks targets outside authorized scope."""
        res = repeater_engine.send_request(
            method="GET",
            url="https://unauthorized-evil-target.com/api",
            authorized_targets=["target.internal", "localhost"]
        )
        assert res["success"] is False
        assert res["scope_blocked"] is True
        assert "ScopeGuard Violation" in res["error"]
        assert res["status_code"] == 403

    def test_scopeguard_blocks_cloud_metadata(self, repeater_engine):
        """Verify that cloud metadata IPs (169.254.169.254) are strictly blocked."""
        res = repeater_engine.send_request(
            method="GET",
            url="http://169.254.169.254/latest/meta-data/",
            authorized_targets=["169.254.169.254"]
        )
        assert res["success"] is False
        assert res["scope_blocked"] is True
        assert res["status_code"] == 403

    @patch("requests.request")
    def test_send_request_authorized_success(self, mock_requests, repeater_engine):
        """Verify that authorized requests dispatch cleanly and format response telemetry."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.reason = "OK"
        mock_resp.headers = {"Content-Type": "application/json", "Server": "HashiraShield/1.0"}
        mock_resp.text = '{"status": "healthy", "service": "auditor"}'
        mock_resp.content = b'{"status": "healthy", "service": "auditor"}'
        mock_requests.return_value = mock_resp

        res = repeater_engine.send_request(
            method="POST",
            url="http://127.0.0.1:8080/api/status",
            headers={"X-Security-Scan": "CyberHashira"},
            body='{"probe": true}',
            authorized_targets=["127.0.0.1"]
        )

        assert res["success"] is True
        assert res["response"]["status_code"] == 200
        assert res["response"]["reason"] == "OK"
        assert "Content-Type" in res["response"]["headers"]
        assert '{"status": "healthy"' in res["response"]["body"]
        assert "elapsed_ms" in res["response"]
        assert res["request"]["method"] == "POST"

        # Verify entry was saved to history
        history = repeater_engine.get_history()
        assert len(history) == 1
        assert history[0]["request"]["url"] == "http://127.0.0.1:8080/api/status"
        assert history[0]["request"]["method"] == "POST"

    def test_clear_history(self, repeater_engine):
        """Verify that clear_history empties the cache and persists empty history."""
        repeater_engine._history = [{"id": "abc"}]
        repeater_engine._save_history()
        assert repeater_engine.history_file.is_file()

        repeater_engine.clear_history()
        assert len(repeater_engine.get_history()) == 0
        with open(repeater_engine.history_file, "r", encoding="utf-8") as f:
            saved = json.load(f)
            assert saved == []


class TestProxyEngine:
    """Test suite for local HTTP inspection proxy server."""

    def test_proxy_lifecycle(self):
        """Test proxy start and stop controls."""
        status_before = get_proxy_status()
        assert isinstance(status_before, dict)
        assert "running" in status_before
        assert "port" in status_before

        # Start proxy on an ephemeral port
        started = start_proxy(host="127.0.0.1", port=18081)
        assert started is True
        status_running = get_proxy_status()
        assert status_running["running"] is True

        # Stop proxy
        stop_proxy()
        status_stopped = get_proxy_status()
        assert status_stopped["running"] is False

    def test_traffic_buffer_operations(self):
        """Test traffic buffer recording, querying, and clearing."""
        clear_traffic_history()
        assert len(get_traffic_history()) == 0

        # Simulate adding entries
        with BUFFER_LOCK:
            TRAFFIC_BUFFER.append({
                "id": "test-req-1",
                "method": "GET",
                "url": "http://target.internal/test",
                "host": "target.internal",
                "status_code": 200,
                "type": "HTTP",
                "request_headers": {},
                "response_headers": {},
                "request_body": "",
                "response_body": "OK",
                "elapsed_ms": 12.5,
                "timestamp": "2026-11-18 12:00:00"
            })

        traffic = get_traffic_history()
        assert len(traffic) == 1
        assert traffic[0]["id"] == "test-req-1"

        clear_traffic_history()
        assert len(get_traffic_history()) == 0


class TestWebAPIEndpoints:
    """Test suite for Flask API routes connecting Web Dashboard to Repeater and Proxy."""

    CSRF_TEST_TOKEN = secrets.token_hex(24)

    @pytest.fixture
    def client(self):
        app.config["TESTING"] = True
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess["authenticated"] = True
                sess["csrf_token"] = self.CSRF_TEST_TOKEN
            yield client

    def test_proxy_status_api(self, client):
        """GET /api/proxy/status returns JSON status."""
        resp = client.get("/api/proxy/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "port" in data

    def test_proxy_traffic_api(self, client):
        """GET /api/proxy/traffic and POST /api/proxy/clear."""
        resp = client.get("/api/proxy/traffic")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "traffic" in data
        assert isinstance(data["traffic"], list)

        resp_clear = client.post(
            "/api/proxy/clear",
            headers={"X-CSRF-Token": self.CSRF_TEST_TOKEN}
        )
        assert resp_clear.status_code == 200
        data_clear = resp_clear.get_json()
        assert data_clear["success"] is True

    def test_repeater_send_blocked_by_scopeguard_api(self, client):
        """POST /api/repeater/send blocks targets outside scope."""
        payload = {
            "method": "GET",
            "url": "https://unauthorized-domain.com",
            "authorized_targets": ["internal.company.com"]
        }
        resp = client.post(
            "/api/repeater/send",
            json=payload,
            headers={"X-CSRF-Token": self.CSRF_TEST_TOKEN}
        )
        data = resp.get_json()
        assert data["success"] is False
        assert data.get("scope_blocked") is True
        assert "ScopeGuard" in data.get("error", "")

    def test_repeater_history_api(self, client):
        """GET /api/repeater/history returns session history."""
        resp = client.get("/api/repeater/history")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "history" in data
        assert isinstance(data["history"], list)
