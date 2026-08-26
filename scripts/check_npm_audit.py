#!/usr/bin/env python3
"""Fail on npm advisories except one reviewed, constrained upstream exception."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
CONTAINER_RUNTIME = ROOT / "deploy/container"
EXPECTED_VULNERABLE_PACKAGES = {"@openai/codex-security", "extract-zip"}
EXPECTED_ADVISORY_URL = "https://github.com/advisories/GHSA-jmr9-qjv8-65gv"


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
        item.get("url")
        for vulnerability in vulnerabilities.values()
        for item in vulnerability.get("via", [])
        if isinstance(item, dict)
    }
    severities = {
        vulnerability.get("severity") for vulnerability in vulnerabilities.values()
    }
    accepted = (
        package_names == EXPECTED_VULNERABLE_PACKAGES
        and advisory_urls == {EXPECTED_ADVISORY_URL}
        and severities == {"high"}
        and vulnerabilities["extract-zip"].get("fixAvailable") is False
        and completed.returncode == 1
    )
    if not accepted:
        print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
        print("npm audit found an unreviewed production advisory", file=sys.stderr)
        return 1

    print(
        "npm audit: accepted temporary upstream exception "
        "GHSA-jmr9-qjv8-65gv; see docs/dependency-risk.md"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
