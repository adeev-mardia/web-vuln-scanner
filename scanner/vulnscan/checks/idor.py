"""IDOR (Insecure Direct Object Reference) detection via sequential ID
probing. Heuristic: if a URL's last path segment is a numeric object id,
try adjacent ids with the *same unauthenticated* request. If several
different ids all return 200 with visibly different owner-specific
content, the endpoint is handing out other users' objects with no
ownership check.
"""
from __future__ import annotations

import re
import urllib.parse

import requests

from ..finding import Finding
from .util import snippet

ID_SEGMENT_RE = re.compile(r"^(.*/)(\d+)$")

# Rough heuristic for "this looks like per-owner content" -- looks for a
# labeled field such as "Owner: alice" / "owner_username" etc.
OWNER_FIELD_RE = re.compile(r"(owner|user|username|account)[^a-zA-Z0-9]{0,3}[:=]\s*([A-Za-z0-9_\-\.@]+)", re.IGNORECASE)


def check_url(session: requests.Session, url: str, timeout: float = 10.0) -> list:
    match = ID_SEGMENT_RE.match(urllib.parse.urlsplit(url).path)
    if not match:
        return []
    prefix, id_str = match.groups()
    base_id = int(id_str)
    scheme_netloc = urllib.parse.urlsplit(url)
    candidate_ids = sorted({base_id, base_id + 1, base_id + 2, max(base_id - 1, 0)})

    owners_seen = {}
    responses = {}
    for cid in candidate_ids:
        probe_path = f"{prefix}{cid}"
        probe_url = urllib.parse.urlunsplit((scheme_netloc.scheme, scheme_netloc.netloc, probe_path, "", ""))
        try:
            resp = session.get(probe_url, timeout=timeout)
        except requests.RequestException:
            continue
        if resp.status_code != 200:
            continue
        responses[cid] = (probe_url, resp)
        m = OWNER_FIELD_RE.search(resp.text)
        if m:
            owners_seen[cid] = m.group(2)

    distinct_owners = set(owners_seen.values())
    if len(responses) >= 2 and len(distinct_owners) >= 2:
        evidence_ids = {cid: {"url": u, "owner": owners_seen.get(cid), "snippet": snippet(r.text)}
                         for cid, (u, r) in responses.items()}
        return [Finding(
            vuln_type="idor",
            severity="high",
            url=url,
            parameter="id (path segment)",
            method="GET",
            evidence={
                "technique": "sequential id probing",
                "candidate_ids_tried": candidate_ids,
                "distinct_owners_found": sorted(distinct_owners),
                "responses": evidence_ids,
            },
            description=(
                f"Sequentially probing nearby numeric ids on {prefix}<id> returned objects "
                f"belonging to different owners ({sorted(distinct_owners)}) to the same "
                f"unauthenticated client, with no ownership check."
            ),
        )]
    return []
