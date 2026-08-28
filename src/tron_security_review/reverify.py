"""Build a verification-only run from immutable, completed scan metadata."""
from __future__ import annotations

from pathlib import Path
import re

from .gitops import target_metadata
from .planner import build_plan
from .verification import read_json


def verification_inputs(config, target: Path, source_run: Path):
    manifest = read_json(source_run / "run-manifest.json", source_run)
    if not isinstance(manifest, dict) or not manifest.get("completed_at") or manifest.get("dry_run"):
        raise ValueError("verification requires a completed, non-dry-run source scan")
    if manifest.get("execution_kind") == "verification_only":
        raise ValueError("use the original discovery run, not a previous verification run")
    if not isinstance(manifest.get("run_id"), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}", manifest["run_id"]):
        raise ValueError("source run id is invalid")
    revision = manifest.get("target_revision")
    revision_file = source_run / "target-revision.txt"
    if revision_file.is_file() and not revision_file.is_symlink():
        file_revision = revision_file.read_text(encoding="utf-8").strip()
        if revision and file_revision != revision:
            raise ValueError("source revision records disagree")
        revision = file_revision
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("source scan has no verifiable full target revision")
    metadata = target_metadata(target)
    if metadata["dirty"] or metadata["commit"] != revision:
        raise ValueError("verification requires a clean checkout at the source scan's exact revision")
    original = manifest.get("plan", {})
    jobs = original.get("jobs", [])
    if not isinstance(jobs, list) or not jobs or any(not isinstance(job, dict) for job in jobs):
        raise ValueError("source plan is invalid")
    # Initial support is intentionally limited to path-scoped reviews. Reconstruct
    # trusted profiles from current config, not commands/models/prompts in a report.
    scopes = {job.get("scope", {}).get("id") for job in jobs if isinstance(job.get("scope"), dict)}
    if original.get("run_mode") not in {"daily-tvm", "weekly"} or len(scopes) != 1:
        raise ValueError("verification-only currently requires one daily-tvm or weekly scope")
    scope = next(iter(scopes))
    if not isinstance(scope, str):
        raise ValueError("source scope is invalid")
    plan = build_plan(config, original["run_mode"], scope_id=scope)
    sources = [job for job in plan.jobs if job.profile.per_finding]
    if not sources:
        raise ValueError("no per-finding verifier is configured for the source plan")
    for verifier in sources:
        source = next((job for job in plan.jobs if job.profile.name == verifier.profile.candidate_source_profile), None)
        recorded = [job for job in jobs if source and job.get("id") == source.id]
        if source is None or len(recorded) != 1 or recorded[0].get("paths") != list(source.paths):
            raise ValueError("source scope differs from current configuration; inspect before rechecking")
    return plan, revision, manifest
