import copy
from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from tron_security_review.artifacts import write_json
from tron_security_review.config import load_config
from tron_security_review.planner import build_plan
from tron_security_review.reverify import verification_inputs
from tron_security_review.runner import _candidate_paths, run_plan
from tron_security_review.verification import collect_candidates, review_outcome, validate_verdict

ROOT = Path(__file__).resolve().parents[1]
SOURCE_JOB = "triage-tvm-opcode-dispatch"
VERIFY_JOB = "verifier-tvm-opcode-dispatch"
JAVA = "actuator/src/main/java/org/tron/core/vm/VM.java"


def candidate(number):
    return {"id": f"deferred-{number}", "reason": "Need activated deployment evidence",
            "paths": [JAVA], "candidate": {
                "candidateId": f"candidate-{number}", "title": f"Synthetic candidate {number}",
                "summary": "An example cross-module invariant to recheck, not an actual finding.",
                "counterEvidence": ["A caller may already guard this input"],
                "sourceLocations": [JAVA + ":12"],
                "preliminaryAssessments": {"sourceSeverity": "medium", "reachability": "unverified"}}}


def verdict(fingerprint="native:candidate-1", status="rejected"):
    return {"schema_version": 1, "source_fingerprint": fingerprint, "status": status,
            "rationale": "The caller checks the invariant before entering the selected branch.",
            "evidence": [JAVA + ":12: guard prevents this claimed path"],
            "production_reachability": {"status": "not_reachable", "evidence": ["Synthetic guard evidence"]},
            "missing_evidence": []}


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "source-run"
        self.target = self.root / "target"
        (self.target / JAVA).parent.mkdir(parents=True)
        (self.target / JAVA).write_text("// synthetic fixture\n")
        self.config = load_config(ROOT)
        self.plan = build_plan(self.config, "daily-tvm", scope_id="tvm-opcode-dispatch")
        self.metadata = {"commit": "a" * 40, "dirty": False}
        self.manifest = {"run_id": "source-run", "completed_at": "2026-08-28T00:00:00Z",
                         "dry_run": False, "target_revision": "a" * 40, "plan": self.plan.as_dict()}
        write_json(self.source / "run-manifest.json", self.manifest)
        self.source_results = self.source / SOURCE_JOB / "results"
        write_json(self.source_results / "findings.json", {"findings": []})
        write_json(self.source_results / "coverage.json", {"completeness": "partial", "deferred": [candidate(i) for i in range(1, 6)]})

    def test_five_deferred_candidates_enter_empty_findings_queue(self):
        intake = collect_candidates(self.source, SOURCE_JOB)
        self.assertEqual(len(intake["candidates"]), 5)
        self.assertFalse(intake["errors"])
        self.assertEqual({item["source_kind"] for item in intake["candidates"]}, {"deferred"})
        first = intake["candidates"][0]
        self.assertEqual(first["source_fingerprint"], "native:candidate-1")
        self.assertTrue(first["deferral_reason"])
        self.assertEqual(first["candidate"]["counterEvidence"], candidate(1)["candidate"]["counterEvidence"])

    def test_operational_and_safety_records_are_not_model_candidates(self):
        write_json(self.source_results / "coverage.json", {"deferred": [
            candidate(1), {**candidate(2), "id": "scan-stopped"},
            {**candidate(3), "reason": "Request refused by safety policy"},
            {"id": "unreviewed-surface", "reason": "Missing source coverage"},
            "Scan ended early", {**candidate(4), "reason": "rate_limit_exceeded"},
        ]})
        result = collect_candidates(self.source, SOURCE_JOB)
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(len(result["excluded"]), 5)
        self.assertIn("safety_blocked", [item["reason"] for item in result["excluded"]])

    def test_duplicate_native_ids_merge_formal_and_deferred_once(self):
        write_json(self.source_results / "findings.json", {"findings": [
            {"findingId": "candidate-1", "title": "Formal example", "severity": "high"}]})
        result = collect_candidates(self.source, SOURCE_JOB)
        self.assertEqual(len(result["candidates"]), 5)
        first = result["candidates"][0]
        self.assertEqual(first["source_kind"], "finding")
        self.assertEqual(len(first["source_artifacts"]), 2)
        self.assertTrue(first["deferral_reason"])

    def test_malformed_missing_and_symlink_artifacts_are_not_silent_empty(self):
        (self.source_results / "findings.json").write_text("{}")
        (self.source_results / "coverage.json").unlink()
        self.assertEqual(len(collect_candidates(self.source, SOURCE_JOB)["errors"]), 2)
        secret = self.root / "outside.json"
        write_json(secret, {"deferred": [candidate(1)]})
        (self.source_results / "coverage.json").symlink_to(secret)
        self.assertFalse(collect_candidates(self.source, SOURCE_JOB)["candidates"])

    def test_candidate_source_locations_and_wrapper_paths_remain_scoped(self):
        entry = candidate(1)["candidate"]
        entry["paths"] = ["../../outside.json", "/etc/passwd"]
        self.assertEqual(_candidate_paths(entry, self.target, (JAVA,)), (JAVA,))
        (self.target / "escape.java").symlink_to(self.root / "outside.java")
        self.assertFalse(_candidate_paths({"sourceLocations": ["escape.java"]}, self.target, ()))

    def test_supported_requires_production_evidence_not_just_agreement(self):
        value = verdict(status="supported")
        with self.assertRaises(ValueError):
            validate_verdict(value, "native:candidate-1")
        value["production_reachability"]["status"] = "proven"
        self.assertEqual(validate_verdict(value, "native:candidate-1")["status"], "supported")
        value["missing_evidence"] = ["activation"]
        with self.assertRaises(ValueError):
            validate_verdict(value, "native:candidate-1")

    def test_rejection_requires_counter_evidence_and_matching_identity(self):
        with self.assertRaises(ValueError):
            validate_verdict(verdict(), "native:another-candidate")
        value = verdict()
        value["evidence"] = []
        with self.assertRaises(ValueError):
            validate_verdict(value, "native:candidate-1")

    def result(self, code=0, blocked=False):
        attempt = self.root / "attempt"
        attempt.mkdir(exist_ok=True)
        (attempt / "stderr.log").write_text("")
        write_json(attempt / "stdout.json", {"turn": {"status": "completed"}})
        return SimpleNamespace(scan_dir=str(attempt / "results"), stdout_path=str(attempt / "stdout.json"),
                               stderr_path=str(attempt / "stderr.log"), returncode=code, safety_blocked=blocked)

    def test_empty_success_is_insufficient_and_never_rejected(self):
        result = self.result()
        write_json(Path(result.scan_dir) / "findings.json", {"findings": []})
        self.assertEqual(review_outcome(result, "native:candidate-1")["status"], "insufficient_evidence")

    def test_explicit_sidecar_and_final_response_with_conflict_detection(self):
        result = self.result(code=2)
        write_json(Path(result.scan_dir) / "artifacts/jtsr-verdict.json", verdict())
        outcome = review_outcome(result, "native:candidate-1")
        self.assertEqual(outcome["status"], "rejected")
        self.assertFalse(outcome["human_confirmed"])
        write_json(Path(result.stdout_path), {"turn": {"status": "completed", "finalResponse":
            "```jtsr-verdict\n" + json.dumps(verdict(status="insufficient_evidence")) + "\n```"}})
        self.assertEqual(review_outcome(result, "native:candidate-1")["status"], "insufficient_evidence")
        (Path(result.scan_dir) / "artifacts/jtsr-verdict.json").unlink()
        self.assertIn("verdict", review_outcome(result, "native:candidate-1"))

    def test_interrupted_or_blocked_reviews_never_accept_partial_verdict(self):
        result = self.result(code=2, blocked=True)
        write_json(Path(result.scan_dir) / "artifacts/jtsr-verdict.json", verdict())
        self.assertEqual(review_outcome(result, "native:candidate-1")["status"], "blocked")
        result.safety_blocked = False
        Path(result.stderr_path).write_text("orchestrator timeout")
        self.assertEqual(review_outcome(result, "native:candidate-1")["status"], "failed")

    def test_reverify_requires_original_clean_revision_and_unchanged_scope(self):
        with patch("tron_security_review.reverify.target_metadata", return_value=self.metadata):
            plan, revision, _ = verification_inputs(self.config, self.target, self.source)
            self.assertEqual(revision, "a" * 40)
            self.assertEqual(plan.jobs[0].scope.id, "tvm-opcode-dispatch")
            self.manifest["plan"]["jobs"][0]["paths"] = ["arbitrary/path"]
            write_json(self.source / "run-manifest.json", self.manifest)
            with self.assertRaises(ValueError):
                verification_inputs(self.config, self.target, self.source)
        for metadata in ({"commit": "b" * 40, "dirty": False}, {"commit": "a" * 40, "dirty": True}):
            with patch("tron_security_review.reverify.target_metadata", return_value=metadata), self.assertRaises(ValueError):
                verification_inputs(self.config, self.target, self.source)

    def test_reverify_preserves_original_and_progress_survives_one_failure(self):
        before = {str(path.relative_to(self.source)): path.read_bytes() for path in self.source.rglob("*") if path.is_file()}
        cli = self.root / "cli"
        cli.write_text("#!/bin/sh\nexit 0\n")
        cli.chmod(0o700)
        calls = []
        def fake_run(command, environment, stdout_path, stderr_path, timeout_seconds=None):
            if "export" in command:
                Path(command[command.index("--output") + 1]).write_text("{}")
                return 0
            calls.append(command)
            path = self.root / "output/new-run" / VERIFY_JOB / "verification-manifest.json"
            live = json.loads(path.read_text())
            self.assertEqual(live["candidate_count"], 5)
            self.assertEqual(live["candidates"][len(calls) - 1]["status"], "running")
            if len(calls) > 1:
                self.assertNotEqual(live["candidates"][0]["status"], "running")
            prompt = Path(command[command.index("--scan-prompt-file") + 1]).read_text()
            self.assertIn("Need activated deployment evidence", prompt)
            self.assertIn("A caller may already guard", prompt)
            self.assertEqual(command.count("--path"), 1)
            self.assertEqual(timeout_seconds, 3600)
            scan_dir = Path(command[command.index("--output-dir") + 1])
            write_json(scan_dir / "findings.json", {"findings": []})
            write_json(scan_dir / "coverage.json", {"completeness": "complete", "deferred": []})
            write_json(scan_dir / "artifacts/jtsr-verdict.json", verdict(f"native:candidate-{len(calls)}"))
            write_json(stdout_path, {"turn": {"status": "completed"}})
            stderr_path.write_text("Unknown failure" if len(calls) == 2 else "Estimated cost: $1.0")
            return 1 if len(calls) == 2 else 0
        with patch("tron_security_review.reverify.target_metadata", return_value=self.metadata), patch("tron_security_review.runner._run_command", side_effect=fake_run):
            run_dir, results = run_plan(self.config, self.plan, self.target, self.root / "output", "new-run", "chatgpt", cli_bin=cli, head_commit="a" * 40, source_run_dir=self.source)
        self.assertEqual(len(calls), 5)  # No triage invocation.
        queue = json.loads((run_dir / VERIFY_JOB / "verification-manifest.json").read_text())
        self.assertEqual([item["status"] for item in queue["candidates"]], ["rejected", "failed", "rejected", "rejected", "rejected"])
        self.assertTrue(json.loads((run_dir / "run-manifest.json").read_text())["partial_coverage"])
        after = {str(path.relative_to(self.source)): path.read_bytes() for path in self.source.rglob("*") if path.is_file()}
        self.assertEqual(before, after)
        with self.assertRaises(ValueError):
            run_plan(self.config, self.plan, self.target, self.root / "output", "new-run", "chatgpt")

    def test_candidate_limit_records_skips_and_safety_source_is_not_retried(self):
        profiles = tuple(replace(profile, max_candidates=2) if profile.per_finding else profile for profile in self.config.profiles)
        config = replace(self.config, profiles=profiles)
        plan = build_plan(config, "daily-tvm", scope_id="tvm-opcode-dispatch")
        with patch("tron_security_review.reverify.target_metadata", return_value=self.metadata):
            run_dir, results = run_plan(config, plan, self.target, self.root / "output", "preview", "chatgpt", head_commit="a" * 40, source_run_dir=self.source, dry_run=True)
        queue = json.loads((run_dir / VERIFY_JOB / "verification-manifest.json").read_text())
        self.assertEqual(queue["selected_candidate_count"], 2)
        self.assertEqual([entry["status"] for entry in queue["candidates"]], ["pending", "pending", "skipped", "skipped", "skipped"])
        self.assertFalse(results)
        (self.source / SOURCE_JOB / "invocation.stderr.log").write_text("flagged for possible cyber-security risk")
        with patch("tron_security_review.reverify.target_metadata", return_value=self.metadata), patch("tron_security_review.runner._run_command") as command:
            run_dir, results = run_plan(config, plan, self.target, self.root / "output", "blocked", "chatgpt", head_commit="a" * 40, source_run_dir=self.source)
        command.assert_not_called()
        self.assertFalse(results)
        self.assertEqual(json.loads((run_dir / VERIFY_JOB / "verification-manifest.json").read_text())["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
