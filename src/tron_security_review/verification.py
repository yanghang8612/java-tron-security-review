"""Candidate intake and fail-closed interpretation of independent model reviews."""
from __future__ import annotations

import json
from pathlib import Path
import re
import stat
from typing import Any

from .artifacts import finding_fingerprint


SAFETY_MARKERS = (
    "flagged for possible cyber-security risk", "trusted access for cyber",
    "safety policy", "safety_policy", "content_policy_violation", "content_filter",
    "safety refusal", "request refused",
)
TERMINAL_VERDICTS = {"supported", "rejected", "insufficient_evidence"}
VERDICT_FILE = "artifacts/jtsr-verdict.json"
_STOP_IDS = re.compile(r"(?:^|[-_])(?:scan[-_]stopped|scan[-_]interrupted|runtime[-_]error|safety[-_]blocked)(?:$|[-_])", re.I)
_SEVERITIES = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def read_artifact_text(path: Path, boundary: Path) -> str:
    """Only read bounded regular artifacts, never links or files outside the run."""
    relative = path.relative_to(boundary)
    current = boundary
    for part in ("", *relative.parts):
        current = current / part
        if current.is_symlink():
            raise ValueError("symlink is not a review artifact")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 8 * 1024 * 1024:
        raise ValueError("review artifact is not a bounded regular file")
    return path.read_text(encoding="utf-8")


def read_json(path: Path, boundary: Path) -> Any:
    def reject_constant(value):
        raise ValueError("non-finite JSON number")
    return json.loads(read_artifact_text(path, boundary), parse_constant=reject_constant)


def _findings(document: Any) -> list[dict]:
    if isinstance(document, list):
        if any(not isinstance(item, dict) for item in document):
            raise ValueError("invalid finding entry")
        return document
    if isinstance(document, dict):
        for key in ("findings", "items", "results"):
            if key in document:
                return _findings(document[key])
    raise ValueError("unrecognized findings schema")


def exclusion_reason(item: Any) -> str | None:
    if not isinstance(item, dict):
        return "non_candidate_coverage_note"
    text = json.dumps(item, ensure_ascii=False).lower()
    if any(marker in text for marker in SAFETY_MARKERS):
        return "safety_blocked"
    # A scanner interruption is not a vulnerability, even if it embeds a hypothesis.
    for record in (item, item.get("candidate", {})):
        if not isinstance(record, dict):
            continue
        for key in ("id", "candidateId", "type", "kind", "status", "title"):
            if _STOP_IDS.search(str(record.get(key, "")).replace(" ", "-")):
                return "operational_record"
    if any(marker in text for marker in (
        "scan stopped: estimated cost", "orchestrator timeout", "usage_limit_reached",
        "rate_limit_exceeded", "model_not_found", "model_unavailable",
    )):
        return "operational_record"
    return None


def deferred_candidate(item: Any) -> dict | None:
    """Require an actual hypothesis, not just an id/reason/open coverage surface."""
    if not isinstance(item, dict):
        return None
    body = item.get("candidate", item)
    if not isinstance(body, dict):
        return None
    identity = body.get("identity")
    title = body.get("title") or (identity.get("title") if isinstance(identity, dict) else None)
    substantive = any(body.get(key) for key in (
        "summary", "description", "rootCause", "root_cause", "evidence",
        "violatedInvariant", "violated_invariant", "impact",
    ))
    if not title or not substantive:
        return None
    candidate = dict(body)
    if not any(candidate.get(key) for key in ("id", "candidateId", "findingId", "finding_id", "fingerprint")):
        candidate["candidateId"] = item.get("candidateId") or item.get("id")
    return candidate


def _priority(entry: dict) -> tuple[int, str]:
    candidate = entry["candidate"]
    assessment = candidate.get("preliminaryAssessments", {})
    severity = candidate.get("severity") or candidate.get("level")
    if not severity and isinstance(assessment, dict):
        severity = assessment.get("sourceSeverity")
    return _SEVERITIES.get(str(severity).lower(), 4), entry["source_fingerprint"]


def collect_candidates(run_dir: Path, source_job_id: str) -> dict:
    """Union current findings and substantive deferred work; deduplicate native IDs."""
    entries: dict[str, dict] = {}
    excluded, errors = [], []
    for filename, kind in (("findings.json", "finding"), ("coverage.json", "deferred")):
        artifact = f"{source_job_id}/results/{filename}"
        try:
            document = read_json(run_dir / artifact, run_dir)
            if kind == "finding":
                items = _findings(document)
            else:
                if not isinstance(document, dict) or not isinstance(document.get("deferred", []), list):
                    raise ValueError("unrecognized coverage schema")
                items = document.get("deferred", [])
        except (OSError, ValueError, RecursionError):
            errors.append(f"candidate source is missing, unreadable or invalid: {artifact}")
            continue
        for item in items:
            reason = exclusion_reason(item)
            candidate = item if kind == "finding" else deferred_candidate(item)
            if reason or not candidate:
                excluded.append({"source_artifact": artifact,
                                 "id": item.get("id") if isinstance(item, dict) else None,
                                 "reason": reason or "non_candidate_coverage_note"})
                continue
            fingerprint = finding_fingerprint(candidate)
            if fingerprint in entries:
                entries[fingerprint]["source_artifacts"].append(artifact)
                if kind == "deferred":
                    entries[fingerprint]["deferral_reason"] = item.get("reason")
                    entries[fingerprint]["source_paths"] = item.get("paths", [])
                    for key, value in candidate.items():
                        entries[fingerprint]["candidate"].setdefault(key, value)
                continue
            entries[fingerprint] = {
                "source_fingerprint": fingerprint, "candidate": candidate,
                "source_kind": kind, "source_artifact": artifact,
                "source_artifacts": [artifact],
                "deferral_reason": item.get("reason") if kind == "deferred" else None,
                "source_paths": item.get("paths", []) if kind == "deferred" else [],
            }
    return {"candidates": sorted(entries.values(), key=_priority), "excluded": excluded, "errors": errors}


def validate_verdict(value: Any, fingerprint: str) -> dict:
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("missing verdict schema")
    if value.get("source_fingerprint") != fingerprint or value.get("status") not in TERMINAL_VERDICTS:
        raise ValueError("verdict does not identify this candidate")
    if not isinstance(value.get("rationale"), str) or not value["rationale"].strip():
        raise ValueError("verdict has no rationale")
    for key in ("evidence", "missing_evidence"):
        if not isinstance(value.get(key), list) or any(not isinstance(item, str) or not item.strip() for item in value[key]):
            raise ValueError(f"invalid verdict {key}")
    reachability = value.get("production_reachability")
    if not isinstance(reachability, dict) or reachability.get("status") not in {"proven", "not_reachable", "unverified"}:
        raise ValueError("missing production reachability assessment")
    if not isinstance(reachability.get("evidence"), list) or any(not isinstance(item, str) or not item.strip() for item in reachability["evidence"]):
        raise ValueError("invalid reachability evidence")
    if value["status"] in {"supported", "rejected"} and not value["evidence"]:
        raise ValueError("a supported or rejected verdict needs explicit evidence")
    if value["status"] == "supported" and (
        reachability["status"] != "proven" or not reachability["evidence"] or value["missing_evidence"]
    ):
        raise ValueError("support requires production evidence with no material proof gaps")
    return {key: value[key] for key in (
        "schema_version", "source_fingerprint", "status", "rationale", "evidence",
        "missing_evidence", "production_reachability",
    )}


def review_outcome(result, fingerprint: str) -> dict:
    """Never infer rejection/confirmation from an empty findings file or exit zero."""
    provenance = {"assessment_kind": "model_review", "human_confirmed": False}
    if result.safety_blocked:
        return {**provenance, "status": "blocked", "reason": "safety_blocked"}
    if getattr(result, "termination_reason", None):
        return {**provenance, "status": "failed", "reason": result.termination_reason}
    try:
        stderr = Path(result.stderr_path).read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        stderr = ""
    if result.returncode not in {0, 2} or any(marker in stderr for marker in (
        "orchestrator timeout", "scan stopped: estimated cost", "usage_limit_reached",
        "rate_limit_exceeded", "model_not_found", "model_unavailable", "model_overloaded",
    )):
        return {**provenance, "status": "failed", "reason": "review_attempt_failed_or_interrupted"}
    scan_dir = Path(result.scan_dir)
    responses = []
    completed = False
    try:
        responses.append((VERDICT_FILE, read_json(scan_dir / VERDICT_FILE, scan_dir)))
    except (OSError, ValueError, RecursionError):
        pass
    try:
        document = read_json(Path(result.stdout_path), scan_dir.parent)
        turn = document.get("turn", {})
        completed = turn.get("status") == "completed"
        final = turn.get("finalResponse", "")
        if isinstance(final, str):
            for block in re.findall(r"(?m)^```jtsr-verdict\s*\n(.*?)\n```", final, flags=re.S):
                responses.append(("turn.finalResponse", json.loads(block)))
    except (OSError, ValueError, AttributeError, RecursionError):
        pass
    if not completed:
        return {**provenance, "status": "failed" if result.returncode else "insufficient_evidence",
                "reason": "review_turn_not_completed"}
    valid = []
    for source, value in responses:
        try:
            valid.append((source, validate_verdict(value, fingerprint)))
        except (ValueError, TypeError):
            continue
    if not valid or any(value != valid[0][1] for _, value in valid[1:]):
        return {**provenance, "status": "insufficient_evidence",
                "reason": "missing_invalid_or_conflicting_explicit_verdict"}
    source, verdict = valid[0]
    return {**provenance, "status": verdict["status"], "verdict": verdict, "verdict_source": source}
