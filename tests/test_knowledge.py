import json
from pathlib import Path
import tempfile
import unittest

from tron_security_review.knowledge import (
    extract_run_knowledge,
    render_review_memory,
    update_knowledge_store,
    validate_knowledge_document,
)


class KnowledgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.run = self.root / "20261013T000000Z-daily-tvm-abcdef123456"
        self.run.mkdir()
        self.write(
            "run-manifest.json",
            {
                "schema_version": 1,
                "run_id": self.run.name,
                "created_at": "2026-10-13T00:00:00+00:00",
                "completed_at": "2026-10-13T01:00:00+00:00",
                "target_revision": "a" * 40,
                "results": [],
            },
        )

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, relative, value):
        path = self.run / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def test_source_anchored_observations_and_explicit_verdicts_are_admitted(self):
        source = "actuator/src/main/java/org/tron/core/vm/VM.java:123"
        self.write(
            "triage-tvm/results/artifacts/jtsr-knowledge.json",
            {
                "schema_version": 1,
                "entries": [
                    {
                        "kind": "negative_result",
                        "title": "Activated gate excludes the legacy branch",
                        "statement": "The current transaction path selects the fixed branch.",
                        "applicability": "TVM transaction execution after proposal activation",
                        "evidence": [source],
                        "invalidation_conditions": ["The gate loading path or active value changes."],
                    },
                    {
                        "kind": "invariant",
                        "title": "Unanchored entry",
                        "statement": "Must not be admitted.",
                        "applicability": "TVM",
                        "evidence": ["no source anchor"],
                        "invalidation_conditions": ["Any change"],
                    },
                ],
            },
        )
        fingerprint = "native:candidate-1"
        self.write(
            "verifier-tvm/verification-manifest.json",
            {
                "candidates": [
                    {
                        "source_fingerprint": fingerprint,
                        "candidate": {
                            "title": "Legacy path is still exploitable",
                            "summary": "A proposal-disabled branch would violate accounting.",
                            "entryPoint": "VMActuator.execute",
                        },
                        "status": "rejected",
                        "verdict": {
                            "schema_version": 1,
                            "source_fingerprint": fingerprint,
                            "status": "rejected",
                            "rationale": "The proposal is active before this path can process a new block.",
                            "evidence": [source],
                            "missing_evidence": [],
                            "production_reachability": {
                                "status": "not_reachable",
                                "evidence": ["framework/src/main/java/org/tron/core/store/DynamicPropertiesStore.java:456"],
                            },
                        },
                    },
                    {
                        "source_fingerprint": "native:no-verdict",
                        "candidate": {"title": "Interrupted review"},
                        "status": "failed",
                    },
                ]
            },
        )

        delta = extract_run_knowledge(self.run)
        self.assertEqual(delta["accepted_count"], 2)
        self.assertEqual(
            {entry["kind"] for entry in delta["entries"]},
            {"negative_result", "rejected_hypothesis"},
        )
        self.assertTrue(delta["rejected_inputs"])
        self.assertNotIn("Interrupted review", json.dumps(delta))

    def test_update_is_deduplicated_bounded_and_rendered_for_later_scans(self):
        source = "actuator/src/main/java/org/tron/core/vm/VM.java:12"
        self.write(
            "triage-tvm/results/artifacts/jtsr-knowledge.json",
            {
                "schema_version": 1,
                "entries": [
                    {
                        "kind": "invariant",
                        "title": "Child state merges only after successful execution",
                        "statement": "Trace child repository commit and rollback together.",
                        "applicability": "Nested TVM calls",
                        "evidence": [source],
                        "invalidation_conditions": ["Repository lifecycle changes."],
                    }
                ],
            },
        )
        store = self.root / "knowledge"
        first = update_knowledge_store(self.run, store)
        second = update_knowledge_store(self.run, store)
        self.assertEqual(first["persistent_entry_count"], 1)
        self.assertEqual(second["persistent_entry_count"], 1)
        index = json.loads((store / "knowledge-index.json").read_text())
        self.assertEqual(index["entries"][0]["occurrences"], 1)
        memory = (store / "review-memory.md").read_text()
        self.assertIn("untrusted historical observations", memory)
        self.assertIn("Child state merges only after successful execution", memory)
        self.assertTrue((self.run / "knowledge-delta.json").is_file())

    def test_invalid_documents_fail_closed_and_open_hypotheses_are_labeled(self):
        with self.assertRaises(ValueError):
            validate_knowledge_document({"schema_version": 1, "entries": [{}] * 7})
        memory = render_review_memory(
            [
                {
                    "id": "open-1",
                    "kind": "open_hypothesis",
                    "title": "Needs proof",
                    "statement": "Reachability is not established.",
                    "applicability": "TVM",
                    "evidence": ["vm/Example.java:1"],
                    "invalidation_conditions": ["Resolve the missing call edge."],
                    "sources": [],
                }
            ]
        )
        self.assertIn("open_hypothesis", memory)
        self.assertIn("never promote an open hypothesis", memory)

    def test_run_identity_and_symlinks_are_rejected(self):
        manifest = json.loads((self.run / "run-manifest.json").read_text())
        manifest["run_id"] = "different"
        self.write("run-manifest.json", manifest)
        with self.assertRaises(ValueError):
            extract_run_knowledge(self.run)
        alias = self.root / "run-alias"
        alias.symlink_to(self.run, target_is_directory=True)
        with self.assertRaises(ValueError):
            extract_run_knowledge(alias)


if __name__ == "__main__":
    unittest.main()
