#!/usr/bin/env python3
"""Fail on npm advisories except reviewed, constrained upstream exceptions."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
CONTAINER_RUNTIME = ROOT / "deploy/container"
EXPECTED_ADVISORY_URLS = {
    "extract-zip": {"https://github.com/advisories/GHSA-jmr9-qjv8-65gv"},
    "fast-uri": {
        "https://github.com/advisories/GHSA-5jgf-p345-68v8",
        "https://github.com/advisories/GHSA-f65p-4m7j-42xc",
        "https://github.com/advisories/GHSA-fph4-wmhf-6fwf",
        "https://github.com/advisories/GHSA-jqff-g426-hqxp",
    },
    "fflate": {"https://github.com/advisories/GHSA-px8p-9vwx-vf98"},
    "@openai/codex-security": set(),
}
EXPECTED_SEVERITIES = {
    "@openai/codex-security": "high",
    "extract-zip": "high",
    "fast-uri": "high",
    "fflate": "moderate",
}


def main() -> int:
    completed = subprocess.run(
        ["npm", "audit", "--omit=dev", "--json"],
        cwd=CONTAINER_RUNTIME,
        check=False,
        capture_output=True,
        text=True,
    )
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError:
        print(completed.stdout, file=sys.stderr)
        print(completed.stderr, file=sys.stderr)
        print("npm audit did not return JSON", file=sys.stderr)
        return 1

    if report.get("auditReportVersion") != 2 or "metadata" not in report:
        print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
        print("npm audit returned an unexpected report schema", file=sys.stderr)
        return 1

    vulnerabilities = report.get("vulnerabilities", {})
    if not vulnerabilities:
        if completed.returncode != 0:
            print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
            print("npm audit failed without a vulnerability report", file=sys.stderr)
            return 1
        print("npm audit: no production dependency advisories")
        return 0

    package_names = set(vulnerabilities)
    advisory_urls = {
        name: {
            item.get("url")
            for item in vulnerability.get("via", [])
            if isinstance(item, dict)
        }
        for name, vulnerability in vulnerabilities.items()
    }
    accepted = (
        package_names == set(EXPECTED_ADVISORY_URLS)
        and advisory_urls == EXPECTED_ADVISORY_URLS
        and {
            name: vulnerability.get("severity")
            for name, vulnerability in vulnerabilities.items()
        } == EXPECTED_SEVERITIES
        and all(
            vulnerability.get("fixAvailable") is False
            for vulnerability in vulnerabilities.values()
        )
        and completed.returncode == 1
    )
    if not accepted:
        print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
        print("npm audit found an unreviewed production advisory", file=sys.stderr)
        return 1

    print(
        "npm audit: accepted exact temporary upstream exceptions for "
        "extract-zip, fast-uri and fflate; see docs/dependency-risk.md"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
