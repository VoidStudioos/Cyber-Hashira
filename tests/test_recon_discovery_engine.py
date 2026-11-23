# -*- coding: utf-8 -*-
"""
Cyber Hashira — Tests for Target Recon, Web Spidering, and Fuzzing Subsystems
Verifies ScopeGuard enforcement, recursive crawling, endpoint fuzzing, tech fingerprinting, and Flask APIs.
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

from engine.crawler import WebCrawler
from engine.fuzzer import EndpointFuzzer
from engine.fingerprint import TechFingerprinter
from ui.web.app import app


@pytest.fixture
def crawler():
    return WebCrawler()


@pytest.fixture
def fuzzer():
    return EndpointFuzzer()


@pytest.fixture
def fingerprinter():
    return TechFingerprinter()


class TestWebCrawler:
    """Test suite for WebCrawler ScopeGuard boundaries and endpoint extraction."""

    def test_crawler_blocks_unauthorized_scope(self, crawler):
        """Crawler strictly blocks targets not in authorized scope."""
        res = crawler.crawl(
            start_url="https://unauthorized-bank.com",
            authorized_targets=["internal.lab"]
        )
        assert res["success"] is False
        assert res["scope_blocked"] is True
        assert "ScopeGuard Violation" in res["error"]

    def test_crawler_blocks_metadata_probes(self, crawler):
        """Crawler strictly blocks cloud metadata targets."""
        res = crawler.crawl(
            start_url="http://169.254.169.254/latest/meta-data/",
            authorized_targets=["169.254.169.254"]
        )
        assert res["success"] is False
        assert res["scope_blocked"] is True

    @patch("requests.Session.get")
    def test_crawler_extracts_links_and_forms(self, mock_get, crawler):
        """Crawler extracts links, query params, HTML forms, and API routes."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
        mock_resp.text = """
        <html>
            <head><title>Test Portal</title></head>
            <body>
                <a href="/dashboard">Dashboard</a>
                <a href="/profile?user_id=42&action=view">Profile</a>
                <form action="/login" method="POST">
                    <input type="text" name="username">
                    <input type="password" name="password">
                </form>
                <script>
                    fetch('/api/v1/metrics');
                </script>
            </body>
        </html>
        """
        mock_get.return_value = mock_resp

        res = crawler.crawl(
            start_url="http://target.internal",
            max_depth=1,
            max_pages=5,
            authorized_targets=["target.internal"]
        )

        assert res["success"] is True
        assert res["target"] == "target.internal"
        assert "/dashboard" in res["endpoints"]
        assert "/profile" in res["endpoints"]
        assert "user_id" in res["parameters"]
        assert "action" in res["parameters"]
        assert "username" in res["parameters"]
        assert len(res["forms"]) == 1
        assert res["forms"][0]["method"] == "POST"


class TestEndpointFuzzer:
    """Test suite for high-speed concurrent endpoint fuzzer."""

    def test_fuzzer_blocks_unauthorized_scope(self, fuzzer):
        """Fuzzer strictly blocks unauthorized domains."""
        res = fuzzer.fuzz(
            target_url="https://external-target.com",
            authorized_targets=["internal.lab"]
        )
        assert res["success"] is False
        assert res["scope_blocked"] is True
        assert "ScopeGuard Violation" in res["error"]

    @patch("requests.get")
    def test_fuzzer_concurrent_discovery(self, mock_get, fuzzer):
        """Fuzzer tests probes and records status codes and response metrics."""
        def side_effect(url, **kwargs):
            m = MagicMock()
            if "admin" in url:
                m.status_code = 403
                m.content = b"Forbidden"
                m.text = "Forbidden"
                m.headers = {}
            elif "robots.txt" in url:
                m.status_code = 200
                m.content = b"User-agent: *\nDisallow: /admin"
                m.text = "User-agent: *\nDisallow: /admin"
                m.headers = {}
            else:
                m.status_code = 404
                m.content = b"Not Found"
                m.text = "Not Found"
                m.headers = {}
            return m

        mock_get.side_effect = side_effect

        res = fuzzer.fuzz(
            target_url="http://127.0.0.1",
            wordlist=["admin", "robots.txt", "nonexistent_file"],
            threads=2,
            authorized_targets=["127.0.0.1"]
        )

        assert res["success"] is True
        assert res["probes_count"] == 3
        # Both admin (403) and robots.txt (200) should be recorded
        assert res["hits_count"] == 2
        paths = [hit["path"] for hit in res["results"]]
        assert "/robots.txt" in paths
        assert "/admin" in paths


class TestTechFingerprinter:
    """Test suite for technology detection and security header posture evaluation."""

    def test_fingerprint_blocks_unauthorized_scope(self, fingerprinter):
        """Fingerprinter respects ScopeGuard boundaries."""
        res = fingerprinter.fingerprint(
            target_url="https://secret-service.gov",
            authorized_targets=["target.internal"]
        )
        assert res["success"] is False
        assert res["scope_blocked"] is True

    @patch("requests.get")
    def test_fingerprint_identifies_stack_and_security_headers(self, mock_get, fingerprinter):
        """Detects headers, technologies, and calculates posture score."""
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Server": "nginx/1.22.0",
            "X-Powered-By": "PHP/8.1",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff"
        }
        mock_resp.text = """
        <html>
            <head>
                <meta name="generator" content="WordPress 6.4">
                <link rel="stylesheet" href="/wp-content/themes/style.css">
            </head>
            <body>Hello World</body>
        </html>
        """
        mock_get.return_value = mock_resp

        res = fingerprinter.fingerprint(
            target_url="http://127.0.0.1:8080",
            authorized_targets=["127.0.0.1"]
        )

        assert res["success"] is True
        assert any("nginx" in t.lower() for t in res["technologies"])
        assert any("php" in t.lower() for t in res["technologies"])
        assert any("wordpress" in t.lower() for t in res["technologies"])
        assert res["posture_score"] > 0

        # Check security header status
        header_statuses = {h["header"]: h["status"] for h in res["security_headers"]}
        assert header_statuses["Strict-Transport-Security"] == "PASS"
        assert header_statuses["X-Frame-Options"] == "PASS"
        assert header_statuses["Content-Security-Policy"] == "MISSING"


class TestReconWebAPI:
    """Test suite for Flask API routes handling recon & discovery."""

    CSRF_TEST_TOKEN = secrets.token_hex(24)

    @pytest.fixture
    def client(self):
        app.config["TESTING"] = True
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess["authenticated"] = True
                sess["csrf_token"] = self.CSRF_TEST_TOKEN
            yield client

    def test_recon_crawl_api_scope_blocked(self, client):
        """POST /api/recon/crawl returns 200 with scope_blocked on unauthorized targets."""
        payload = {
            "url": "https://unauthorized-domain.com",
            "authorized_targets": ["internal.company.com"]
        }
        resp = client.post(
            "/api/recon/crawl",
            json=payload,
            headers={"X-CSRF-Token": self.CSRF_TEST_TOKEN}
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is False
        assert data.get("scope_blocked") is True

    def test_recon_fuzz_api_scope_blocked(self, client):
        """POST /api/recon/fuzz returns scope_blocked on unauthorized targets."""
        payload = {
            "url": "https://unauthorized-domain.com",
            "authorized_targets": ["internal.company.com"]
        }
        resp = client.post(
            "/api/recon/fuzz",
            json=payload,
            headers={"X-CSRF-Token": self.CSRF_TEST_TOKEN}
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is False
        assert data.get("scope_blocked") is True

    def test_recon_fingerprint_api_scope_blocked(self, client):
        """POST /api/recon/fingerprint returns scope_blocked on unauthorized targets."""
        payload = {
            "url": "https://unauthorized-domain.com",
            "authorized_targets": ["internal.company.com"]
        }
        resp = client.post(
            "/api/recon/fingerprint",
            json=payload,
            headers={"X-CSRF-Token": self.CSRF_TEST_TOKEN}
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is False
        assert data.get("scope_blocked") is True
