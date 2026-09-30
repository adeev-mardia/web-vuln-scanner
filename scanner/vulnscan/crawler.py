"""A small same-origin crawler that discovers pages, links, and forms."""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field

import requests
from bs4 import BeautifulSoup


@dataclass
class FormInfo:
    action: str          # absolute URL the form submits to
    method: str           # "get" or "post"
    inputs: list          # list of {"name": ..., "type": ..., "value": ...}
    source_url: str       # page the form was found on


@dataclass
class PageInfo:
    url: str
    status_code: int
    forms: list = field(default_factory=list)
    links: list = field(default_factory=list)          # discovered absolute URLs
    query_param_urls: list = field(default_factory=list)  # URLs with ?params


class Crawler:
    """Breadth-first, same-origin crawler using requests + BeautifulSoup."""

    def __init__(self, base_url: str, session: requests.Session, max_pages: int = 40, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.origin = urllib.parse.urlparse(self.base_url)
        self.session = session
        self.max_pages = max_pages
        self.timeout = timeout
        self.visited = set()
        self.pages: list = []

    def _same_origin(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        return (parsed.scheme, parsed.netloc) == (self.origin.scheme, self.origin.netloc)

    def _normalize(self, url: str) -> str:
        parsed = urllib.parse.urlsplit(url)
        # Drop fragments; keep query string since it's meaningful for us.
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))

    def crawl(self) -> list:
        queue = [self.base_url + "/"]
        while queue and len(self.visited) < self.max_pages:
            url = queue.pop(0)
            norm = self._normalize(url)
            if norm in self.visited:
                continue
            self.visited.add(norm)

            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            except requests.RequestException:
                continue

            page = PageInfo(url=url, status_code=resp.status_code)
            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                self.pages.append(page)
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            # Links
            for a in soup.find_all("a", href=True):
                abs_url = urllib.parse.urljoin(url, a["href"])
                if not self._same_origin(abs_url):
                    continue
                page.links.append(abs_url)
                if urllib.parse.urlparse(abs_url).query:
                    page.query_param_urls.append(abs_url)
                norm_link = self._normalize(abs_url)
                if norm_link not in self.visited and len(self.visited) + len(queue) < self.max_pages:
                    queue.append(abs_url)

            # Forms
            for form in soup.find_all("form"):
                action = form.get("action") or url
                abs_action = urllib.parse.urljoin(url, action)
                method = (form.get("method") or "get").lower()
                inputs = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if not name:
                        continue
                    inputs.append({
                        "name": name,
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", ""),
                    })
                page.forms.append(FormInfo(action=abs_action, method=method, inputs=inputs, source_url=url))

            self.pages.append(page)

        return self.pages
