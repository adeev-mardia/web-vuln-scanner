"""Open redirect detection: check whether a parameter that looks like a
redirect target sends the browser to an attacker-controlled external host,
verified via the Location header (not just a body string match)."""
from __future__ import annotations

import urllib.parse

import requests

from ..finding import Finding
from .util import set_query_param, query_params, snippet

REDIRECT_PARAM_HINTS = ("next", "url", "redirect", "return", "target", "dest", "continue", "goto")
EVIL_HOST = "vulnscan-evil.example.org"
PAYLOAD = f"https://{EVIL_HOST}/pwned"


def check_url_params(session: requests.Session, url: str, timeout: float = 10.0) -> list:
    findings = []
    for param in query_params(url):
        if not any(hint in param.lower() for hint in REDIRECT_PARAM_HINTS):
            continue
        probe_url = set_query_param(url, param, PAYLOAD)
        try:
            resp = session.get(probe_url, timeout=timeout, allow_redirects=False)
        except requests.RequestException:
            continue
        location = resp.headers.get("Location", "")
        if resp.status_code in (301, 302, 303, 307, 308) and EVIL_HOST in urllib.parse.urlsplit(location).netloc:
            findings.append(Finding(
                vuln_type="open_redirect",
                severity="medium",
                url=url,
                parameter=param,
                method="GET",
                evidence={
                    "payload": PAYLOAD,
                    "request_url": probe_url,
                    "response_status": resp.status_code,
                    "location_header": location,
                },
                description=(
                    f"Parameter '{param}' redirects to an arbitrary attacker-supplied external "
                    f"host via the Location header, with no allowlist check."
                ),
            ))
    return findings
