"""Renders scan results as JSON or a human-readable text report."""
from __future__ import annotations

import json
from datetime import datetime, timezone

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def to_json(result: dict) -> str:
    payload = dict(result)
    payload["findings"] = [f.to_dict() if hasattr(f, "to_dict") else f for f in result["findings"]]
    payload["generated_at"] = datetime.now(timezone.utc).isoformat()
    return json.dumps(payload, indent=2, default=str)


def to_text(result: dict) -> str:
    findings = sorted(result["findings"], key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    lines = []
    lines.append("=" * 72)
    lines.append(f"vulnscan report for {result['base_url']}")
    lines.append("=" * 72)
    lines.append(f"Pages crawled:            {result['pages_crawled']}")
    lines.append(f"Forms found:              {result['forms_found']}")
    lines.append(f"URLs with params tested:  {result['urls_with_params_tested']}")
    lines.append(f"Scan duration:            {result['elapsed_seconds']}s")
    lines.append(f"Findings:                 {len(findings)}")
    lines.append("")

    if not findings:
        lines.append("No vulnerabilities detected.")
        return "\n".join(lines)

    by_type = {}
    for f in findings:
        by_type.setdefault(f.vuln_type, []).append(f)

    lines.append("Summary by type:")
    for vuln_type, items in sorted(by_type.items()):
        lines.append(f"  - {vuln_type}: {len(items)}")
    lines.append("")
    lines.append("-" * 72)

    for i, f in enumerate(findings, 1):
        lines.append(f"[{i}] {f.vuln_type.upper()}  (severity: {f.severity})")
        lines.append(f"    URL:        {f.url}")
        lines.append(f"    Method:     {f.method}")
        lines.append(f"    Parameter:  {f.parameter}")
        lines.append(f"    Details:    {f.description}")
        for k, v in f.evidence.items():
            v_str = str(v)
            if len(v_str) > 300:
                v_str = v_str[:300] + "... [truncated]"
            lines.append(f"    Evidence.{k}: {v_str}")
        lines.append("-" * 72)

    return "\n".join(lines)
