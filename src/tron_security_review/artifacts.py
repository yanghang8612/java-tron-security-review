from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
import json
from pathlib import Path
import os
import tempfile
from typing import Any, Iterable


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Readers (including the portal) must never see a half-written progress record.
    fd, temporary = tempfile.mkstemp(prefix=".jtsr-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True, ensure_ascii=False)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def finding_list(document: Any) -> list[dict[str, Any]]:
    if isinstance(document, list):
        return [item for item in document if isinstance(item, dict)]
    if not isinstance(document, dict):
        return []
    for key in ("findings", "items", "results"):
        value = document.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = finding_list(value)
            if nested:
                return nested
    return []


def _first(item: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = item.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def finding_fingerprint(item: dict[str, Any]) -> str:
    native = _first(item, "fingerprint", "finding_id", "findingId", "id", "candidateId")
    if native:
        return f"native:{native}"
    basis = {
        "title": _first(item, "title", "name", "summary"),
        "severity": _first(item, "severity", "level"),
        "location": _first(item, "location", "locations", "path", "file"),
        "root_cause": _first(item, "root_cause", "rootCause", "cause"),
    }
    encoded = json.dumps(basis, sort_keys=True, default=str).encode("utf-8")
    return "derived:" + sha256(encoded).hexdigest()


def read_findings(path: Path) -> list[dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    return finding_list(document)


def aggregate_run(
    run_dir: Path, excluded_scan_dirs: Iterable[Path] = ()
) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    unreadable: list[str] = []
    excluded = {path.resolve() for path in excluded_scan_dirs}
    for findings_path in sorted(run_dir.glob("**/results/findings.json")):
        if findings_path.parent.resolve() in excluded:
            continue
        relative = findings_path.relative_to(run_dir)
        profile = relative.parts[0]
        try:
            document = json.loads(findings_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            unreadable.append(str(findings_path))
            continue
        for item in finding_list(document):
            grouped[finding_fingerprint(item)].append(
                {
                    "profile": profile,
                    "native_id": _first(
                        item, "finding_id", "findingId", "id", "fingerprint"
                    ),
                    "title": _first(item, "title", "name", "summary"),
                    "severity": _first(item, "severity", "level"),
                    "source": str(findings_path),
                }
            )

    findings = []
    for fingerprint, occurrences in sorted(grouped.items()):
        profiles = sorted({occurrence["profile"] for occurrence in occurrences})
        findings.append(
            {
                "fingerprint": fingerprint,
                "profiles": profiles,
                "corroborated_by_multiple_profiles": len(profiles) > 1,
                "occurrences": occurrences,
            }
        )
    return {
        "finding_groups": findings,
        "finding_group_count": len(findings),
        "unreadable_artifacts": unreadable,
        "note": (
            "Cross-profile agreement is corroboration only. Root-cause validation and "
            "human review remain required."
        ),
    }
