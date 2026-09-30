# web-vuln-scanner

A real, working web application vulnerability scanner (`scanner/`, a real
installable Python CLI) plus a real, deliberately-vulnerable target
application (`vulnerable-app/`, a real Flask + SQLite app) that it scans.
I built both sides so I could actually exercise and prove out the scanner's
detection logic end to end, and there's a pytest integration test that
spins the vulnerable app up as a real local subprocess, runs the real
scanner against it over HTTP, and asserts each vulnerability class is
genuinely found — see [Results](#results) below for real scanner output.

Nothing here is mocked or simulated: the scanner sends real HTTP requests
with crafted payloads and makes its detection decisions from real response
analysis (status codes, headers, timing, and response-body diffs); the
target app has real, exploitable bugs (string-concatenated SQL, unescaped
HTML output, `shell=True` subprocess calls, unsanitized path joins, missing
ownership checks, and unsanitized redirects).

## ⚠️ Ethical use disclaimer

**Only scan applications you own or that you have explicit written
permission to test.** Scanning systems you don't own or don't have
authorization for is illegal in most jurisdictions and a violation of
Anthropic's and most hosting providers' usage policies. `vulnerable-app/`
in this repo is provided specifically so you have a legal, local target to
practice against. The scanner's CLI requires an explicit
`--i-have-permission` flag before it will send a single request, as a
speed bump against pointing it at something you don't own.

## Repository layout

```
web-vuln-scanner/
├── vulnerable-app/        # Deliberately vulnerable Flask + SQLite app
│   ├── app.py
│   └── requirements.txt
├── scanner/                # Installable Python CLI vulnerability scanner
│   ├── pyproject.toml
│   └── vulnscan/
│       ├── cli.py           # argparse entry point (`vulnscan` command)
│       ├── engine.py        # orchestrates crawl + all checks
│       ├── crawler.py       # same-origin crawler (requests + BeautifulSoup)
│       ├── finding.py        # Finding dataclass (evidence-carrying result)
│       ├── report.py         # JSON + human-readable report rendering
│       └── checks/           # one module per vulnerability class
│           ├── sqli.py
│           ├── xss.py
│           ├── cmdi.py
│           ├── traversal.py
│           ├── idor.py
│           └── redirect.py
├── tests/
│   └── test_integration.py  # starts vulnerable-app, runs the scanner, asserts findings
├── pytest.ini
├── LICENSE
└── README.md
```

## Architecture overview

**`vulnerable-app/`** is a single-file Flask app backed by SQLite
(`vulnbank.db`, seeded on first run with 3 fake users and 3 fake
invoices). It deliberately implements six classic, independently
exploitable web vulnerabilities — see the docstring at the top of
`app.py` for the full list and the code comments marking each one
(`# VULNERABLE: ...`).

**`scanner/vulnscan`** is a real CLI tool, installable with
`pip install -e .`, exposing a `vulnscan` command (`project.scripts` entry
point in `pyproject.toml`). At a high level:

1. **`crawler.py`** does a breadth-first, same-origin crawl of the target
   starting from `/`, using `requests` for HTTP and `BeautifulSoup` to
   parse HTML, discovering links (including ones with query parameters)
   and `<form>`s (action, method, and every named input).
2. **`engine.py`** takes the crawl output and runs each vulnerability
   check module against every discovered query-parameter URL, every form,
   and (for IDOR) every discovered URL with a numeric path segment.
3. Each module under **`checks/`** implements real detection logic against
   real HTTP responses — no canned "vulnerable: true" — described in
   [Detection techniques](#detection-techniques) below.
4. **`report.py`** renders the collected `Finding` objects (each one
   carrying the exact payload, request URL/data, and a response snippet as
   evidence) as JSON and as a human-readable text report.
5. **`cli.py`** wires it together behind `argparse`, requires
   `--i-have-permission`, and writes reports to stdout and optionally to
   files (`-o report.json`, `--text-output report.txt`). It exits `1` if
   any vulnerability was found (useful in CI) and `0` if the target came
   back clean.

## Detection techniques

| Vulnerability | Technique |
|---|---|
| SQL injection | Error-based: send a bare `'` (and a variant) and match known DB error signatures in the response. Boolean-based differential: compare response length/content between an always-true (`' OR '1'='1`) and always-false (`' AND '1'='2`) payload. For login-style forms, also checks whether the true-payload response shows auth-success markers (e.g. "Welcome"). |
| Reflected XSS | Inject a payload wrapping a unique random marker in a custom HTML tag (`<vulnscan id="...">`), then parse the response with BeautifulSoup and confirm the marker exists as a real, parsed *element* (not merely escaped text) — this proves it would execute/render as markup in a browser DOM, not just appear as an HTML-escaped string. |
| Command injection | Two independent signals. Output-based: inject `; echo MARKER_$(( a + b ))_end ;` and require the shell-*computed* sum to appear in the response (not the raw, unevaluated payload text) — this specifically rules out false positives from pages that merely echo/reflect their input without ever passing it to a shell. Time-based: measure response latency for several shell metacharacter + `sleep N` payload variants against a timed baseline request. |
| Path traversal | Try several `../` (and URL-encoded / doubled-slash) traversal depths against known targets (`/etc/passwd`, the app's own `.py` source) and match content signatures (`root:.*:0:0:` for passwd, Python/Flask import markers for source disclosure). |
| IDOR | Sequential ID probing: for any discovered URL ending in a numeric path segment, request several nearby IDs with the *same unauthenticated client* and check whether distinct owner-labeled records (matched via a generic `owner/user/username/account: value` pattern) come back for different IDs — if so, there's no ownership check. |
| Open redirect | For any query parameter whose name looks redirect-related (`next`, `url`, `redirect`, `return`, `target`, `dest`, `continue`, `goto`), send an attacker-controlled external URL and confirm via the actual `Location` response header (redirects not followed) that the browser would be sent to that external host. |

Every finding carries real evidence: the exact payload sent, the request
URL/form data, response status, and a response-body snippet — not just a
boolean.

## Running the vulnerable app

```bash
cd vulnerable-app
pip install -r requirements.txt
python app.py
# Flask app now listening on http://127.0.0.1:5000
# (set PORT=xxxx env var to use a different port)
```

The SQLite DB (`vulnbank.db`) and a public `files/` directory (holding a
`sentinel.txt` used by the path-traversal demo) are created automatically
on first run.

## Running the scanner

```bash
cd scanner
pip install -e .
# with the vulnerable-app running locally on port 5000:
vulnscan http://127.0.0.1:5000 --i-have-permission
# write a JSON report too:
vulnscan http://127.0.0.1:5000 --i-have-permission -o report.json
```

Run `vulnscan --help` for all options (`--max-pages`, `--timeout`,
`--text-output`, `--quiet`).

## Running the test suite

From the repository root:

```bash
pip install -e "scanner[dev]" --break-system-packages   # omit the flag inside a venv
pytest -v
```

`tests/test_integration.py` starts `vulnerable-app/app.py` as a real
subprocess on a free localhost port (no external network involved), runs
the real `vulnscan` engine against it over HTTP, and asserts that all six
vulnerability classes are genuinely detected — with evidence attached to
every finding. This is the real, non-mocked proof that both sides of this
repo actually work together.

## Results

Actual output from running `vulnscan http://127.0.0.1:5000 --i-have-permission`
against a freshly-started `vulnerable-app` instance (unedited, only
trimmed for length in a couple of evidence blocks):

```
[*] Crawling http://127.0.0.1:5000 ...
[*] Discovered 7 page(s).
[*] Testing params on http://127.0.0.1:5000/download?file=sentinel.txt
[*] Testing params on http://127.0.0.1:5000/goto?next=/
[*] Testing params on http://127.0.0.1:5000/ping?host=127.0.0.1
[*] Testing params on http://127.0.0.1:5000/search?q=test
[*] Testing form at http://127.0.0.1:5000/login (POST)
[*] Scan finished in 0.2s — 7 finding(s).
========================================================================
vulnscan report for http://127.0.0.1:5000
========================================================================
Pages crawled:            7
Forms found:              1
URLs with params tested:  4
Scan duration:            0.23s
Findings:                 7

Summary by type:
  - command_injection: 1
  - idor: 1
  - open_redirect: 1
  - path_traversal: 1
  - reflected_xss: 1
  - sql_injection: 2

------------------------------------------------------------------------
[1] COMMAND_INJECTION  (severity: critical)
    URL:        http://127.0.0.1:5000/ping?host=127.0.0.1
    Method:     GET
    Parameter:  host
    Details:    Parameter 'host' executed an injected shell command: the arithmetic
                expression in our payload was evaluated by the shell and the computed
                result ('cmdimarke4d48afa_15037_end') appeared in the response body —
                not merely the raw, unevaluated payload text.
    Evidence.payload: ; echo cmdimarke4d48afa_$(( 8567 + 6470 ))_end ;
    Evidence.response_snippet: <pre>cmdimarke4d48afa_15037_end
    /bin/sh: 1: ping: not found
    </pre>
------------------------------------------------------------------------
[2] SQL_INJECTION  (severity: critical)
    URL:        http://127.0.0.1:5000/login
    Method:     POST
    Parameter:  username
    Details:    Form field 'username' on http://127.0.0.1:5000/login returned a
                database error signature when sent a single-quote payload.
    Evidence.payload: vulnscan'"
    Evidence.response_snippet: <p>Database error: unrecognized token:
                "\"' AND password = 'vulnscan_probe'\""</p>
------------------------------------------------------------------------
[3] SQL_INJECTION  (severity: critical)
    URL:        http://127.0.0.1:5000/login
    Method:     POST
    Parameter:  password
    ... (single-quote payload also breaks the password field's query)
------------------------------------------------------------------------
[4] PATH_TRAVERSAL  (severity: high)
    URL:        http://127.0.0.1:5000/download?file=sentinel.txt
    Method:     GET
    Parameter:  file
    Details:    Parameter 'file' allowed reading a file outside the intended
                directory using a '../' traversal payload.
    Evidence.payload: ../../../../../../etc/passwd
    Evidence.response_snippet: root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin ...
------------------------------------------------------------------------
[5] REFLECTED_XSS  (severity: high)
    URL:        http://127.0.0.1:5000/search?q=test
    Method:     GET
    Parameter:  q
    Details:    Parameter 'q' reflects attacker-controlled markup unescaped
                into the HTML response body (a custom element with our marker
                id parses successfully).
    Evidence.payload: <vulnscan id="xssmark04ab88f5">XSS</vulnscan>
------------------------------------------------------------------------
[6] IDOR  (severity: high)
    URL:        http://127.0.0.1:5000/invoice/1
    Method:     GET
    Parameter:  id (path segment)
    Details:    Sequentially probing nearby numeric ids on /invoice/<id> returned
                objects belonging to different owners (['admin', 'alice', 'bob'])
                to the same unauthenticated client, with no ownership check.
------------------------------------------------------------------------
[7] OPEN_REDIRECT  (severity: medium)
    URL:        http://127.0.0.1:5000/goto?next=/
    Method:     GET
    Parameter:  next
    Details:    Parameter 'next' redirects to an arbitrary attacker-supplied
                external host via the Location header, with no allowlist check.
    Evidence.payload: https://vulnscan-evil.example.org/pwned
    Evidence.location_header: https://vulnscan-evil.example.org/pwned
------------------------------------------------------------------------
```

And the integration test suite, run from the repo root:

```
$ pytest -v
collected 9 items

tests/test_integration.py::test_scan_completes_and_crawls_pages PASSED   [ 11%]
tests/test_integration.py::test_detects_sql_injection PASSED             [ 22%]
tests/test_integration.py::test_detects_reflected_xss PASSED             [ 33%]
tests/test_integration.py::test_detects_command_injection PASSED         [ 44%]
tests/test_integration.py::test_detects_path_traversal PASSED            [ 55%]
tests/test_integration.py::test_detects_idor PASSED                      [ 66%]
tests/test_integration.py::test_detects_open_redirect PASSED             [ 77%]
tests/test_integration.py::test_all_six_vuln_classes_detected_with_evidence PASSED [ 88%]
tests/test_integration.py::test_cli_module_is_importable_and_wired PASSED [100%]

============================== 9 passed in 0.73s ===============================
```

### A real bug I hit and fixed while building this

The first version of the command-injection check flagged a hit purely by
checking whether a unique marker string appeared anywhere in the response.
That produced **false positives** on `/search` and `/download`, both of
which simply reflect the raw input back in an error/results message
without ever running it in a shell — so the marker showed up whether or
not the command actually executed. I fixed it by making the payload
compute something (`echo MARKER_$(( a + b ))_end`) and only accepting a
match on the *computed* result while rejecting it if the raw, unevaluated
payload text is also present — which a plain reflection would always show
and a real shell evaluation never would. This is exactly the kind of bug
the integration test suite (which asserts against a real running target,
not mocked responses) is meant to catch.

## License

MIT — see [LICENSE](LICENSE).
