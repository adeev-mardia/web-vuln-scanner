"""Reflected XSS detection: inject a unique marker wrapped in an HTML tag
and check whether it survives unescaped in the response (i.e. actually
parses as an element, not just as literal text)."""
from __future__ import annotations

import uuid

import requests
from bs4 import BeautifulSoup

from ..finding import Finding
from .util import set_query_param, query_params, snippet


def _marker_payload(marker: str) -> str:
    return f'<vulnscan id="{marker}">XSS</vulnscan>'


def _reflected_unescaped(html: str, marker: str) -> bool:
    """True only if the marker appears as a real parsed element (i.e. the
    HTML wasn't escaped), not merely as literal text like &lt;vulnscan..."""
    if f'id="{marker}"' not in html and f"id='{marker}'" not in html:
        return False
    soup = BeautifulSoup(html, "html.parser")
    tag = soup.find(attrs={"id": marker})
    return tag is not None


def check_url_params(session: requests.Session, url: str, timeout: float = 10.0) -> list:
    findings = []
    for param in query_params(url):
        marker = "xssmark" + uuid.uuid4().hex[:8]
        payload = _marker_payload(marker)
        probe_url = set_query_param(url, param, payload)
        try:
            resp = session.get(probe_url, timeout=timeout)
        except requests.RequestException:
            continue
        if resp.status_code == 200 and _reflected_unescaped(resp.text, marker):
            findings.append(Finding(
                vuln_type="reflected_xss",
                severity="high",
                url=url,
                parameter=param,
                method="GET",
                evidence={
                    "payload": payload,
                    "request_url": probe_url,
                    "marker": marker,
                    "response_snippet": snippet(resp.text),
                },
                description=(
                    f"Parameter '{param}' reflects attacker-controlled markup unescaped into the "
                    f"HTML response body (a custom element with our marker id parses successfully)."
                ),
            ))
    return findings


def check_form(session: requests.Session, form, timeout: float = 10.0) -> list:
    findings = []
    text_inputs = [i for i in form.inputs if i.get("type") in ("text", "search", "email", None, "")]

    def submit(data):
        if form.method == "post":
            return session.post(form.action, data=data, timeout=timeout)
        return session.get(form.action, params=data, timeout=timeout)

    baseline_data = {i["name"]: (i.get("value") or "vulnscan_probe") for i in form.inputs}

    for target in text_inputs:
        marker = "xssmark" + uuid.uuid4().hex[:8]
        payload = _marker_payload(marker)
        data = dict(baseline_data)
        data[target["name"]] = payload
        try:
            resp = submit(data)
        except requests.RequestException:
            continue
        if resp.status_code == 200 and _reflected_unescaped(resp.text, marker):
            findings.append(Finding(
                vuln_type="reflected_xss",
                severity="high",
                url=form.action,
                parameter=target["name"],
                method=form.method.upper(),
                evidence={
                    "payload": payload,
                    "form_source": form.source_url,
                    "request_data": data,
                    "marker": marker,
                    "response_snippet": snippet(resp.text),
                },
                description=(
                    f"Form field '{target['name']}' on {form.action} reflects attacker-controlled "
                    f"markup unescaped into the HTML response."
                ),
            ))
    return findings
