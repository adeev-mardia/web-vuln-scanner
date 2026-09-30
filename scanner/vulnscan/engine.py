"""Orchestrates crawling + all vulnerability checks into one findings list."""
from __future__ import annotations

import time

import requests

from .crawler import Crawler
from .checks import sqli, xss, cmdi, traversal, idor, redirect


class ScanEngine:
    def __init__(self, base_url: str, max_pages: int = 40, timeout: float = 10.0, verbose=None):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "vulnscan/0.1 (authorized-testing)"})
        self.max_pages = max_pages
        self.timeout = timeout
        self.verbose = verbose or (lambda msg: None)

    def run(self) -> dict:
        start = time.time()
        self.verbose(f"Crawling {self.base_url} ...")
        crawler = Crawler(self.base_url, self.session, max_pages=self.max_pages, timeout=self.timeout)
        pages = crawler.crawl()
        self.verbose(f"Discovered {len(pages)} page(s).")

        all_urls_with_params = set()
        all_forms = []
        all_page_urls = set()
        for page in pages:
            all_page_urls.add(page.url)
            for u in page.query_param_urls:
                all_urls_with_params.add(u)
            for f in page.forms:
                all_forms.append(f)
            all_page_urls |= set(page.links)

        findings = []

        for url in sorted(all_urls_with_params):
            self.verbose(f"Testing params on {url}")
            findings += sqli.check_url_params(self.session, url, timeout=self.timeout)
            findings += xss.check_url_params(self.session, url, timeout=self.timeout)
            findings += cmdi.check_url_params(self.session, url, timeout=self.timeout)
            findings += traversal.check_url_params(self.session, url, timeout=self.timeout)
            findings += redirect.check_url_params(self.session, url, timeout=self.timeout)

        for form in all_forms:
            self.verbose(f"Testing form at {form.action} ({form.method.upper()})")
            findings += sqli.check_form(self.session, form, timeout=self.timeout)
            findings += xss.check_form(self.session, form, timeout=self.timeout)

        for url in sorted(all_page_urls):
            findings += idor.check_url(self.session, url, timeout=self.timeout)

        elapsed = time.time() - start
        self.verbose(f"Scan finished in {elapsed:.1f}s — {len(findings)} finding(s).")

        return {
            "base_url": self.base_url,
            "pages_crawled": len(pages),
            "forms_found": len(all_forms),
            "urls_with_params_tested": len(all_urls_with_params),
            "elapsed_seconds": round(elapsed, 2),
            "findings": findings,
        }
