"""Deterministic inventory and evidence accounting for the daily TVM campaign."""
from __future__ import annotations

from collections.abc import Iterable
import json
from pathlib import Path
import re
from typing import Any


CAMPAIGN_ID = "daily-tvm-full-vm"
VM_SOURCE_ROOTS = (
    "actuator/src/main/java/org/tron/core/vm",
    "common/src/main/java/org/tron/core/vm",
)
SHARD_ORDER = (
    "core-dispatch",
    "program-runtime",
    "repository-state",
    "native-contracts",
    "trace-utils",
)
SHARD_LABELS = {
    "core-dispatch": "VM core dispatch, precompiles and configuration",
    "program-runtime": "Program execution, memory, stack, storage and invocation",
    "repository-state": "Repository isolation, caching, commit and rollback",
    "native-contracts": "Native-contract processors and their parameter boundaries",
    "trace-utils": "Execution tracing, listeners and VM utility accounting",
}


def inventory_vm_sources(target: Path) -> tuple[str, ...]:
    """Return every checked-out production Java source under the two VM roots."""
    target = target.resolve()
    files: list[str] = []
    for relative_root in VM_SOURCE_ROOTS:
        root = target / relative_root
        if not root.is_dir():
            continue
        files.extend(
            path.relative_to(target).as_posix()
            for path in root.rglob("*.java")
            if path.is_file() and not path.is_symlink()
        )
    return tuple(sorted(set(files)))


def shard_for_path(path: str) -> str:
    normalized = "/" + path.replace("\\", "/")
    if "/vm/nativecontract/" in normalized:
        return "native-contracts"
    if "/vm/program/" in normalized:
        return "program-runtime"
    if "/vm/repository/" in normalized:
        return "repository-state"
    if "/vm/trace/" in normalized or "/vm/utils/" in normalized:
        return "trace-utils"
    return "core-dispatch"


def shard_vm_sources(target: Path) -> dict[str, tuple[str, ...]]:
    grouped: dict[str, list[str]] = {name: [] for name in SHARD_ORDER}
    for path in inventory_vm_sources(target):
        grouped[shard_for_path(path)].append(path)
    return {name: tuple(grouped[name]) for name in SHARD_ORDER if grouped[name]}


def cross_module_context(paths: Iterable[str], target: Path) -> tuple[str, ...]:
    """Keep selected-facet callers/sinks without reintroducing broad VM directories."""
    selected: list[str] = []
    for path in paths:
        normalized = path.rstrip("/")
        if any(
            normalized == root or normalized.startswith(root + "/")
            for root in VM_SOURCE_ROOTS
        ):
            continue
        if (target / normalized).exists() and normalized not in selected:
            selected.append(normalized)
    return tuple(selected)


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)


def _canonical_evidence_text(scan_dir: Path) -> str:
    """Read semantic results only; commands/includePaths are not review evidence."""
    chunks: list[str] = []
    coverage_path = scan_dir / "coverage.json"
    try:
        coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        coverage = {}
    if isinstance(coverage, dict):
        for key in ("surfaces", "deferred", "openQuestions"):
            chunks.extend(_strings(coverage.get(key)))
    for name in ("architecture-review.json", "findings.json"):
        try:
            document = json.loads((scan_dir / name).read_text(encoding="utf-8"))
        except (OSError, ValueError, RecursionError):
            continue
        chunks.extend(_strings(document))
    try:
        chunks.append((scan_dir / "report.md").read_text(encoding="utf-8"))
    except OSError:
        pass
    return "\n".join(chunks)


def evidenced_paths(
    scan_dir: Path,
    assigned: tuple[str, ...],
    inventory: tuple[str, ...] = (),
) -> tuple[str, ...]:
    evidence = _canonical_evidence_text(scan_dir)
    basenames: dict[str, int] = {}
    for path in inventory or assigned:
        name = Path(path).name
        basenames[name] = basenames.get(name, 0) + 1
    found: list[str] = []
    for path in assigned:
        name = Path(path).name
        if path in evidence or (
            basenames[name] == 1
            and re.search(r"(?<![A-Za-z0-9_.-])" + re.escape(name) + r"(?![A-Za-z0-9_.-])", evidence)
        ):
            found.append(path)
    return tuple(found)


def build_coverage_manifest(plan, results, target: Path, dry_run: bool) -> dict[str, Any] | None:
    jobs = [job for job in plan.jobs if job.campaign_shard and job.coverage_paths]
    if plan.run_mode != "daily-tvm" or not jobs:
        return None
    expected = inventory_vm_sources(target)
    assignments: dict[str, list[str]] = {}
    for job in jobs:
        for path in job.coverage_paths:
            assignments.setdefault(path, []).append(job.id)
    unassigned = sorted(set(expected) - set(assignments))
    duplicates = sorted(path for path, owners in assignments.items() if len(owners) != 1)
    unexpected = sorted(set(assignments) - set(expected))
    result_index = {
        result.job_id: result
        for result in results
        if result.counts_toward_exit
    }
    records = []
    evidenced: set[str] = set()
    failed_jobs: list[str] = []
    for job in jobs:
        result = result_index.get(job.id)
        if dry_run:
            reviewed: tuple[str, ...] = ()
        elif result and result.returncode == 0:
            reviewed = evidenced_paths(Path(result.scan_dir), job.coverage_paths, expected)
        else:
            reviewed = ()
        missing = sorted(set(job.coverage_paths) - set(reviewed))
        evidenced.update(reviewed)
        if not dry_run and (
            result is None
            or result.returncode != 0
            or result.export_returncode not in (None, 0)
        ):
            failed_jobs.append(job.id)
        records.append({
            "job_id": job.id,
            "shard": job.campaign_shard,
            "label": SHARD_LABELS.get(job.campaign_shard, job.campaign_shard),
            "assigned_count": len(job.coverage_paths),
            "evidenced_count": len(reviewed),
            "missing_count": len(missing),
            "assigned_files": list(job.coverage_paths),
            "evidenced_files": list(reviewed),
            "missing_files": missing,
            "returncode": result.returncode if result else None,
        })
    missing = sorted(set(expected) - evidenced)
    complete = not dry_run and not any((unassigned, duplicates, unexpected, failed_jobs, missing))
    return {
        "schema_version": 1,
        "campaign": CAMPAIGN_ID,
        "completeness": "not_evaluated" if dry_run else "complete" if complete else "partial",
        "summary": (
            "Dry run; source evidence was not evaluated."
            if dry_run
            else f"Evidence references {len(evidenced)} of {len(expected)} inventoried VM Java files."
        ),
        "expected_count": len(expected),
        "assigned_count": len(assignments),
        "evidenced_count": len(evidenced),
        "missing_count": len(missing),
        "expected_files": list(expected),
        "evidenced_files": sorted(evidenced),
        "missing_files": missing,
        "unassigned_files": unassigned,
        "duplicate_assignments": duplicates,
        "unexpected_assignments": unexpected,
        "failed_jobs": failed_jobs,
        "shards": records,
    }
