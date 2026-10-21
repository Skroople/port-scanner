"""Command-line interface: python -m portscanner <target> [options]"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import List, Optional

from . import __version__
from .scanner import CLOSED, FILTERED, OPEN, PortResult, ScanReport, parse_ports, scan

DISCLAIMER = "Only scan hosts you own or have explicit permission to test."


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portscanner",
        description="Multithreaded TCP connect port scanner. " + DISCLAIMER,
    )
    parser.add_argument("target", help="hostname or IPv4 address to scan")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="ports to scan, e.g. 22,80,443 or 1-1024 or top (default: 1-1024)",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=0.5,
        help="seconds to wait per connection (default: 0.5)",
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=200,
        help="number of concurrent threads (default: 200)",
    )
    parser.add_argument(
        "-b", "--banner", action="store_true",
        help="try to read a service banner from open ports",
    )
    parser.add_argument(
        "-a", "--all", action="store_true",
        help="also list closed and filtered ports",
    )
    parser.add_argument("-o", "--output", help="write results to a JSON file")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def format_table(results: List[PortResult], show_banner: bool) -> str:
    header = f"{'PORT':<9}{'STATE':<10}{'SERVICE':<16}"
    if show_banner:
        header += "BANNER"
    header = header.rstrip()
    lines = [header, "-" * len(header)]
    for r in results:
        line = f"{str(r.port) + '/tcp':<9}{r.state:<10}{r.service:<16}"
        if show_banner and r.banner:
            line += r.banner
        lines.append(line.rstrip())
    return "\n".join(lines)


def to_json(report: ScanReport, ports_spec: str) -> dict:
    return {
        "target": report.target,
        "ip": report.ip,
        "ports": ports_spec,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "elapsed_seconds": round(report.elapsed, 3),
        "summary": {
            state: sum(1 for r in report.results if r.state == state)
            for state in (OPEN, CLOSED, FILTERED)
        },
        "open_ports": [
            {"port": r.port, "service": r.service, "banner": r.banner}
            for r in report.open_ports
        ],
    }


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.timeout <= 0 or args.workers < 1:
        print("error: timeout must be > 0 and workers >= 1", file=sys.stderr)
        return 2

    noun = "port" if len(ports) == 1 else "ports"
    print(f"Scanning {args.target} ({len(ports)} {noun}, {args.workers} threads)")
    print(DISCLAIMER + "\n")

    done = 0

    def progress(_: PortResult) -> None:
        nonlocal done
        done += 1
        if sys.stderr.isatty():
            print(f"\r  {done}/{len(ports)} ports checked", end="", file=sys.stderr)

    try:
        report = scan(
            args.target, ports, timeout=args.timeout, workers=args.workers,
            banner=args.banner, on_result=progress,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nScan interrupted.", file=sys.stderr)
        return 130
    if sys.stderr.isatty():
        print("\r" + " " * 40 + "\r", end="", file=sys.stderr)

    shown = report.results if args.all else report.open_ports
    if shown:
        print(format_table(shown, args.banner))
    else:
        print("No open ports found.")

    counts = to_json(report, args.ports)["summary"]
    print(
        f"\n{report.target} ({report.ip}): {counts[OPEN]} open, "
        f"{counts[CLOSED]} closed, {counts[FILTERED]} filtered "
        f"in {report.elapsed:.2f}s"
    )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(to_json(report, args.ports), fh, indent=2)
        print(f"Results saved to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
