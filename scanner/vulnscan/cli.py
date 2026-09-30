"""vulnscan CLI entry point."""
from __future__ import annotations

import argparse
import sys

from .engine import ScanEngine
from . import report

DISCLAIMER = (
    "vulnscan sends live attack payloads (SQL injection, XSS, command "
    "injection, path traversal, IDOR probing, open-redirect probing) to the "
    "target. Only scan applications you own or have explicit written "
    "permission to test."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description="A real HTTP-based web vulnerability scanner. " + DISCLAIMER,
    )
    parser.add_argument("url", help="Base URL of the target application, e.g. http://127.0.0.1:5000")
    parser.add_argument("-o", "--output", help="Path to write the JSON report to")
    parser.add_argument("--text-output", help="Path to write the human-readable text report to")
    parser.add_argument("--max-pages", type=int, default=40, help="Maximum pages to crawl (default: 40)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds (default: 10)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output")
    parser.add_argument(
        "--i-have-permission",
        action="store_true",
        help="Acknowledge you have authorization to scan this target (skips the interactive prompt)",
    )
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.i_have_permission:
        sys.stderr.write(DISCLAIMER + "\n")
        sys.stderr.write(
            "Re-run with --i-have-permission once you've confirmed you're authorized "
            "to scan this target.\n"
        )
        return 2

    verbose = (lambda msg: None) if args.quiet else (lambda msg: print(f"[*] {msg}", file=sys.stderr))

    engine = ScanEngine(args.url, max_pages=args.max_pages, timeout=args.timeout, verbose=verbose)
    result = engine.run()

    text_report = report.to_text(result)
    print(text_report)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report.to_json(result))
        if not args.quiet:
            print(f"\nJSON report written to {args.output}", file=sys.stderr)

    if args.text_output:
        with open(args.text_output, "w") as f:
            f.write(text_report)

    return 1 if result["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
