"""Command injection detection.

Uses two independent signals so the check works even on flaky/sandboxed
hosts where `sleep` might be restricted:
  1. Time-based: appending `; sleep N ;` measurably delays the response.
  2. Output-based: appending a command whose output is distinctive (e.g.
     `echo` a unique marker, or reading a well-known file) shows up in
     the response body.
"""
from __future__ import annotations

import random
import time
import uuid

import requests

from ..finding import Finding
from .util import set_query_param, query_params, snippet

TIME_DELAY_SECONDS = 3
TIME_TOLERANCE_SECONDS = 1.5  # baseline must be well under this delta


def _time_based_payloads(delay: int) -> list:
    return [
        f"; sleep {delay} ;",
        f"| sleep {delay}",
        f"` sleep {delay} `",
        f"$(sleep {delay})",
        f"127.0.0.1; sleep {delay}",
    ]


def _output_based_payload(marker: str):
    """Build a payload whose expected output only appears if the shell
    actually EVALUATES it. We ask the shell to add two random numbers
    inside an arithmetic expansion: a naively-reflected (not executed)
    parameter would show the literal, unevaluated `$(( a + b ))` text,
    never the computed sum — so matching on the computed value (and not
    the raw payload substring) rules out simple HTML-reflection false
    positives such as XSS-style echoing of the input.
    """
    a = random.randint(1000, 8999)
    b = random.randint(1000, 8999)
    expected = f"{marker}_{a + b}_end"
    payload = f"; echo {marker}_$(( {a} + {b} ))_end ;"
    return payload, expected


def check_url_params(session: requests.Session, url: str, timeout: float = 15.0) -> list:
    findings = []
    for param in query_params(url):
        # --- baseline timing ---
        try:
            t0 = time.monotonic()
            baseline_resp = session.get(url, timeout=timeout)
            baseline_elapsed = time.monotonic() - t0
        except requests.RequestException:
            continue

        # --- output-based (cheap, try first) ---
        marker = "cmdimark" + uuid.uuid4().hex[:8]
        payload, expected = _output_based_payload(marker)
        probe_url = set_query_param(url, param, payload)
        try:
            resp = session.get(probe_url, timeout=timeout)
        except requests.RequestException:
            resp = None
        # Require the *computed* value, not the raw payload text, so a page
        # that merely reflects our input (e.g. an XSS-style echo) without
        # ever passing it to a shell cannot trigger a false positive here.
        if resp is not None and expected in resp.text and payload not in resp.text:
            findings.append(Finding(
                vuln_type="command_injection",
                severity="critical",
                url=url,
                parameter=param,
                method="GET",
                evidence={
                    "technique": "output-based (arithmetic evaluation)",
                    "payload": payload,
                    "request_url": probe_url,
                    "expected_evaluated_output": expected,
                    "response_snippet": snippet(resp.text),
                },
                description=(
                    f"Parameter '{param}' executed an injected shell command: the arithmetic "
                    f"expression in our payload was evaluated by the shell and the computed "
                    f"result ('{expected}') appeared in the response body — not merely the raw, "
                    f"unevaluated payload text."
                ),
            ))
            continue

        # --- time-based ---
        found_time_based = False
        for delay_payload in _time_based_payloads(TIME_DELAY_SECONDS):
            probe_url = set_query_param(url, param, delay_payload)
            try:
                t0 = time.monotonic()
                resp = session.get(probe_url, timeout=timeout)
                elapsed = time.monotonic() - t0
            except requests.exceptions.Timeout:
                elapsed = timeout
            except requests.RequestException:
                continue
            if elapsed - baseline_elapsed >= (TIME_DELAY_SECONDS - TIME_TOLERANCE_SECONDS):
                findings.append(Finding(
                    vuln_type="command_injection",
                    severity="critical",
                    url=url,
                    parameter=param,
                    method="GET",
                    evidence={
                        "technique": "time-based",
                        "payload": delay_payload,
                        "request_url": probe_url,
                        "baseline_elapsed_sec": round(baseline_elapsed, 2),
                        "delayed_elapsed_sec": round(elapsed, 2),
                        "expected_delay_sec": TIME_DELAY_SECONDS,
                    },
                    description=(
                        f"Parameter '{param}' caused a ~{TIME_DELAY_SECONDS}s response delay when sent a "
                        f"`sleep {TIME_DELAY_SECONDS}` shell payload (baseline "
                        f"{baseline_elapsed:.2f}s vs {elapsed:.2f}s), indicating command injection."
                    ),
                ))
                found_time_based = True
                break
        if found_time_based:
            continue
    return findings
