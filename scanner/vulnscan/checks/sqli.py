"""SQL injection detection: error-based signatures + boolean-based
differential testing, against both GET query parameters and POST forms.
"""
from __future__ import annotations

import urllib.parse

import requests

from ..finding import Finding
from .util import set_query_param, query_params, snippet

SQL_ERROR_SIGNATURES = [
    "sql syntax",
    "sqlite3.operationalerror",
    "sqlite3.warning",
    "unrecognized token",
    "sqlite error",
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "syntax error in sql",
    "ora-00933",
    "pg_query",
    "psql:",
]

# A single quote is the classic SQLi probe; a doubled quote should behave
# like a literal apostrophe again if the app is vulnerable but "fixes"
# itself, so we always pair a broken payload with a balanced one.
ERROR_PAYLOAD = "vulnscan'\""

# Boolean pair for authentication-style bypass (used against forms that look
# like a login form) and for generic differential testing on GET params.
TRUE_PAYLOAD = "' OR '1'='1"
FALSE_PAYLOAD = "' AND '1'='2"

AUTH_SUCCESS_MARKERS = ["welcome", "logged in", "admin=true", "admin=1"]


def _looks_like_sql_error(body: str) -> bool:
    low = body.lower()
    return any(sig in low for sig in SQL_ERROR_SIGNATURES)


def check_url_params(session: requests.Session, url: str, timeout: float = 10.0) -> list:
    findings = []
    params = query_params(url)
    for param in params:
        # --- error-based ---
        probe_url = set_query_param(url, param, ERROR_PAYLOAD)
        try:
            resp = session.get(probe_url, timeout=timeout)
        except requests.RequestException:
            continue
        if _looks_like_sql_error(resp.text):
            findings.append(Finding(
                vuln_type="sql_injection",
                severity="critical",
                url=url,
                parameter=param,
                method="GET",
                evidence={
                    "technique": "error-based",
                    "payload": ERROR_PAYLOAD,
                    "request_url": probe_url,
                    "response_status": resp.status_code,
                    "response_snippet": snippet(resp.text),
                },
                description=(
                    f"Parameter '{param}' returned a database error signature when sent "
                    f"a single-quote payload, indicating unsanitized SQL string concatenation."
                ),
            ))
            continue  # no need to also boolean-test this param

        # --- boolean-based differential ---
        true_url = set_query_param(url, param, TRUE_PAYLOAD)
        false_url = set_query_param(url, param, FALSE_PAYLOAD)
        try:
            true_resp = session.get(true_url, timeout=timeout)
            false_resp = session.get(false_url, timeout=timeout)
        except requests.RequestException:
            continue
        if (
            true_resp.status_code == 200
            and len(true_resp.text) != len(false_resp.text)
            and abs(len(true_resp.text) - len(false_resp.text)) > 5
        ):
            findings.append(Finding(
                vuln_type="sql_injection",
                severity="critical",
                url=url,
                parameter=param,
                method="GET",
                evidence={
                    "technique": "boolean-based differential",
                    "true_payload": TRUE_PAYLOAD,
                    "false_payload": FALSE_PAYLOAD,
                    "true_response_len": len(true_resp.text),
                    "false_response_len": len(false_resp.text),
                    "true_response_snippet": snippet(true_resp.text),
                    "false_response_snippet": snippet(false_resp.text),
                },
                description=(
                    f"Parameter '{param}' produces a different response for an always-true vs "
                    f"always-false SQL condition, indicating boolean-based SQL injection."
                ),
            ))
    return findings


def check_form(session: requests.Session, form, timeout: float = 10.0) -> list:
    findings = []
    text_inputs = [i for i in form.inputs if i.get("type") in ("text", "password", "search", "email", None, "")]
    if not text_inputs:
        return findings

    def submit(data):
        if form.method == "post":
            return session.post(form.action, data=data, timeout=timeout)
        return session.get(form.action, params=data, timeout=timeout)

    baseline_data = {i["name"]: (i.get("value") or "vulnscan_probe") for i in form.inputs}

    for target in text_inputs:
        # --- error-based ---
        data = dict(baseline_data)
        data[target["name"]] = ERROR_PAYLOAD
        try:
            resp = submit(data)
        except requests.RequestException:
            continue
        if _looks_like_sql_error(resp.text):
            findings.append(Finding(
                vuln_type="sql_injection",
                severity="critical",
                url=form.action,
                parameter=target["name"],
                method=form.method.upper(),
                evidence={
                    "technique": "error-based",
                    "payload": ERROR_PAYLOAD,
                    "form_source": form.source_url,
                    "request_data": data,
                    "response_status": resp.status_code,
                    "response_snippet": snippet(resp.text),
                },
                description=(
                    f"Form field '{target['name']}' on {form.action} returned a database error "
                    f"signature when sent a single-quote payload."
                ),
            ))
            continue

        # --- boolean-based auth bypass (classic ' OR '1'='1) ---
        data_true = dict(baseline_data)
        data_true[target["name"]] = TRUE_PAYLOAD
        try:
            true_resp = submit(data_true)
        except requests.RequestException:
            continue
        low = true_resp.text.lower()
        if true_resp.status_code == 200 and any(marker in low for marker in AUTH_SUCCESS_MARKERS):
            findings.append(Finding(
                vuln_type="sql_injection",
                severity="critical",
                url=form.action,
                parameter=target["name"],
                method=form.method.upper(),
                evidence={
                    "technique": "boolean-based auth bypass",
                    "payload": TRUE_PAYLOAD,
                    "form_source": form.source_url,
                    "request_data": data_true,
                    "response_status": true_resp.status_code,
                    "response_snippet": snippet(true_resp.text),
                },
                description=(
                    f"Submitting \"{TRUE_PAYLOAD}\" in field '{target['name']}' on {form.action} "
                    f"bypassed authentication logic, indicating SQL injection."
                ),
            ))
    return findings
