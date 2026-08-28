"""Build a verification-only run from immutable, completed scan metadata."""
from __future__ import annotations

from pathlib import Path
from hashlib import sha256
import json
import re

from .gitops import target_metadata
from .planner import build_plan
from .verification import SAFETY_MARKERS, collect_candidates, read_artifact_text, read_json


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
    return plan, revision, {**manifest, "target_revision": revision}


def failed_verification_inputs(plan, source_run, source_manifest, previous_run):
    """Select failures by stable identity, never use a report's commands or paths."""
    previous = read_json(previous_run / "run-manifest.json", previous_run)
    if not isinstance(previous, dict) or not previous.get("completed_at") or previous.get("dry_run"):
        raise ValueError("retry source must be a completed, non-dry-run review")
    if (previous.get("execution_kind") != "verification_only"
        or previous.get("source_run_id") != source_manifest["run_id"]
        or previous.get("target_revision") != source_manifest["target_revision"]
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}", str(previous.get("run_id", "")))):
        raise ValueError("retry source lineage or target revision does not match discovery")
    selection = {}
    for job in plan.jobs:
        if not job.profile.per_finding:
            continue
        queue = read_json(previous_run / job.id / "verification-manifest.json", previous_run)
        if not isinstance(queue, dict) or queue.get("status") != "completed" or not isinstance(queue.get("candidates"), list):
            raise ValueError("previous review queue must be completed")
        source_job = next(j for j in plan.jobs if j.profile.name == job.profile.candidate_source_profile)
        intake = collect_candidates(source_run, source_job.id)
        if intake["errors"]:
            raise ValueError("cannot select retry candidates from incomplete source artifacts")
        known = {entry["source_fingerprint"] for entry in intake["candidates"]}
        selected, seen = set(), set()
        for record in queue["candidates"]:
            fingerprint = record.get("source_fingerprint") if isinstance(record, dict) else None
            if fingerprint not in known or fingerprint in seen:
                raise ValueError("previous review has unknown or duplicate candidate identities")
            seen.add(fingerprint)
            if record.get("status") != "failed":
                continue
            if any(marker in json.dumps(record).lower() for marker in SAFETY_MARKERS):
                raise ValueError("safety-blocked candidates cannot be retried")
            if any(isinstance(record.get(name), dict) and record[name].get("safety_blocked") for name in ("primary", "retry", "fallback")):
                raise ValueError("safety-blocked attempts cannot be retried")
            index = record.get("index")
            if type(index) is not int or index < 1 or index > 10000:
                raise ValueError("invalid previous candidate index")
            token = sha256(fingerprint.encode()).hexdigest()[:12]
            directory = previous_run / job.id / "candidates" / f"{index:03d}-{token}"
            logs = list(directory.glob("*/invocation.stderr.log"))
            if not logs:
                raise ValueError("previous failure logs are missing; inspect before retrying")
            for log in logs:
                text = read_artifact_text(log, previous_run).lower()
                if any(marker in text for marker in SAFETY_MARKERS):
                    raise ValueError("safety-blocked attempts cannot be retried")
            selected.add(fingerprint)
        selection[job.id] = selected
    if not any(selection.values()):
        raise ValueError("previous review has no eligible failed candidates")
    return selection, previous
