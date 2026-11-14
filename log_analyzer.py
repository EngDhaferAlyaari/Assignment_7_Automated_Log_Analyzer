"""Assignment 7 - Automated Log Analyzer.

Reads a text log line by line and prints alerts for common suspicious patterns.
"""

import argparse
import ipaddress
import re
import sys
from pathlib import Path
from urllib.parse import unquote_plus


SQL_PATTERNS = [
    re.compile(r"\bUNION\s+(?:ALL\s+)?SELECT\b", re.IGNORECASE),
    re.compile(r"\b(?:OR|AND)\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?(?=\W|$)", re.IGNORECASE),
]

TRAVERSAL_PATTERNS = [
    re.compile(r"(?:\.\.[/\\])+(?:etc[/\\]passwd|windows[/\\]win\.ini)\b", re.IGNORECASE),
    re.compile(r"(?:\.\.[/\\]){2,}", re.IGNORECASE),
]

IPV4_PATTERN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def extract_ip(line):
    """Return the first valid IPv4 address found in a log line."""
    for match in IPV4_PATTERN.finditer(line):
        try:
            return str(ipaddress.IPv4Address(match.group()))
        except ipaddress.AddressValueError:
            pass
    return "Unknown"


def detect_attacks(line):
    """Return the names of all matching indicators for one line."""
    text = line
    # URL-encoded input is common in web server logs.
    for _ in range(2):
        text = unquote_plus(text)

    findings = []
    if any(re.search(pattern, text) for pattern in SQL_PATTERNS):
        findings.append("SQL Injection")
    if any(re.search(pattern, text) for pattern in TRAVERSAL_PATTERNS):
        findings.append("Path Traversal")
    return findings


def analyze_log(path, output):
    """Read without loading the whole file, then print findings and summary."""
    total_lines = 0
    suspicious_lines = 0
    sql_count = 0
    traversal_count = 0

    print("Assignment 7 - Automated Log Analyzer", file=output)
    print("Log file:", Path(path).name, file=output)
    print("-" * 48, file=output)

    with open(path, "r", encoding="utf-8", errors="replace") as log_file:
        for line_number, raw_line in enumerate(log_file, start=1):
            total_lines += 1
            findings = detect_attacks(raw_line)
            if not findings:
                continue

            suspicious_lines += 1
            sql_count += "SQL Injection" in findings
            traversal_count += "Path Traversal" in findings
            log_line = raw_line.rstrip("\r\n")
            print(
                f"[ALERT] Line {line_number} | IP: {extract_ip(raw_line)} | "
                f"Type: {', '.join(findings)}",
                file=output,
            )
            print("  " + log_line, file=output)

    print("-" * 48, file=output)
    print("Summary", file=output)
    print(f"Total lines: {total_lines}", file=output)
    print(f"Suspicious lines: {suspicious_lines}", file=output)
    print(f"Normal lines: {total_lines - suspicious_lines}", file=output)
    print(f"SQL Injection: {sql_count}", file=output)
    print(f"Path Traversal: {traversal_count}", file=output)
    return suspicious_lines


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Find common SQL Injection and Path Traversal indicators in text logs."
    )
    parser.add_argument(
        "logfile", nargs="?", default="sample_security.log",
        help="Text log file to inspect (default: sample_security.log)",
    )
    parser.add_argument(
        "--report", metavar="FILE", help="Save the report to a text file"
    )
    args = parser.parse_args(argv)

    try:
        if args.report:
            with open(args.report, "w", encoding="utf-8") as report_file:
                analyze_log(args.logfile, report_file)
            print("Report saved to:", args.report)
        else:
            analyze_log(args.logfile, sys.stdout)
    except OSError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
