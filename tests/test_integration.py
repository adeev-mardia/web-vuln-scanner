"""End-to-end integration test.

Starts the real vulnerable-app Flask server as a subprocess on localhost,
runs the real vulnscan engine against it (no mocking of HTTP calls), and
asserts that all six vulnerability classes are genuinely detected.
"""
import os
import socket
import subprocess
import sys
import time

import pytest
import requests

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_DIR = os.path.join(REPO_ROOT, "vulnerable-app")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def vulnerable_app_url():
    db_path = os.path.join(APP_DIR, "vulnbank.db")
    if os.path.exists(db_path):
        os.remove(db_path)

    port = _free_port()
    env = dict(os.environ)
    env["PORT"] = str(port)

    proc = subprocess.Popen(
        [sys.executable, "app.py"],
        cwd=APP_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    base_url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 20
    up = False
    while time.time() < deadline:
        try:
            r = requests.get(base_url + "/", timeout=1)
            if r.status_code == 200:
                up = True
                break
        except requests.RequestException:
            pass
        if proc.poll() is not None:
            break
        time.sleep(0.3)

    if not up:
        out = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
        proc.terminate()
        pytest.fail(f"vulnerable-app failed to start on {base_url}:\n{out}")

    yield base_url

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    if os.path.exists(db_path):
        os.remove(db_path)


@pytest.fixture(scope="module")
def scan_result(vulnerable_app_url):
    # Import here so the test also verifies the installed console entry
    # point's underlying engine works, without requiring package install
    # order relative to pytest collection.
    from vulnscan.engine import ScanEngine

    engine = ScanEngine(vulnerable_app_url, max_pages=40, timeout=15.0)
    return engine.run()


def _types_found(scan_result):
    return {f.vuln_type for f in scan_result["findings"]}


def test_scan_completes_and_crawls_pages(scan_result):
    assert scan_result["pages_crawled"] > 0
    assert scan_result["forms_found"] >= 1


def test_detects_sql_injection(scan_result):
    assert "sql_injection" in _types_found(scan_result)


def test_detects_reflected_xss(scan_result):
    assert "reflected_xss" in _types_found(scan_result)


def test_detects_command_injection(scan_result):
    assert "command_injection" in _types_found(scan_result)


def test_detects_path_traversal(scan_result):
    assert "path_traversal" in _types_found(scan_result)


def test_detects_idor(scan_result):
    assert "idor" in _types_found(scan_result)


def test_detects_open_redirect(scan_result):
    assert "open_redirect" in _types_found(scan_result)


def test_all_six_vuln_classes_detected_with_evidence(scan_result):
    expected = {
        "sql_injection",
        "reflected_xss",
        "command_injection",
        "path_traversal",
        "idor",
        "open_redirect",
    }
    found = _types_found(scan_result)
    missing = expected - found
    assert not missing, f"Missing vulnerability classes: {missing}"

    # Every finding must carry real evidence, not just a bare assertion.
    for finding in scan_result["findings"]:
        assert finding.url
        assert finding.evidence, f"Finding {finding.vuln_type} has no evidence"


def test_cli_module_is_importable_and_wired():
    from vulnscan.cli import main, build_parser

    parser = build_parser()
    args = parser.parse_args(["http://example.invalid"])
    assert args.url == "http://example.invalid"
    assert callable(main)
