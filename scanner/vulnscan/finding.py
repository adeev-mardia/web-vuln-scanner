"""Shared Finding data structure used by all checks and the reporter."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict


@dataclass
class Finding:
    vuln_type: str          # e.g. "sql_injection"
    severity: str            # "critical" | "high" | "medium" | "low"
    url: str                 # the URL/endpoint that was found vulnerable
    parameter: str            # the parameter or field name that was injected
    method: str = "GET"
    evidence: dict = field(default_factory=dict)   # request/response snippets, timings, etc.
    description: str = ""

    def to_dict(self) -> dict:
        return asdict(self)
