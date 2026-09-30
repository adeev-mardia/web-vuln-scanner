"""Small shared helpers for the vuln checks."""
from __future__ import annotations

import urllib.parse


def set_query_param(url: str, name: str, value: str) -> str:
    """Return a copy of url with a single query parameter replaced/added."""
    parsed = urllib.parse.urlsplit(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    params[name] = [value]
    new_query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))


def query_params(url: str) -> list:
    parsed = urllib.parse.urlsplit(url)
    return list(urllib.parse.parse_qs(parsed.query, keep_blank_values=True).keys())


def snippet(text: str, length: int = 400) -> str:
    if text is None:
        return ""
    text = text.strip()
    return text[:length] + ("... [truncated]" if len(text) > length else "")
