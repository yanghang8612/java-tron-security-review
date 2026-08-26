from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
import json
from pathlib import Path
from typing import Any


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _finding_list(document: Any) -> list[dict[str, Any]]:
    if isinstance(document, list):
        return [item for item in document if isinstance(item, dict)]
    if not isinstance(document, dict):
        return []
    for key in ("findings", "items", "results"):
        value = document.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = _finding_list(value)
            if nested:
                return nested
    return []


def _first(item: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = item.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def _fingerprint(item: dict[str, Any]) -> str:
    native = _first(item, "fingerprint", "finding_id", "findingId", "id")
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


def aggregate_run(run_dir: Path) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    unreadable: list[str] = []
    for findings_path in sorted(run_dir.glob("*/results/findings.json")):
        profile = findings_path.parents[1].name
        try:
            document = json.loads(findings_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            unreadable.append(str(findings_path))
            continue
        for item in _finding_list(document):
            grouped[_fingerprint(item)].append(
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
