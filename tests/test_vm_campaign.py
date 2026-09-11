from pathlib import Path
from types import SimpleNamespace
import json
import tempfile
import unittest

from tron_security_review.config import load_config
from tron_security_review.planner import build_plan
from tron_security_review.vm_campaign import (
    SHARD_ORDER,
    build_coverage_manifest,
    evidenced_paths,
    inventory_vm_sources,
)


ROOT = Path(__file__).resolve().parents[1]


class VmCampaignTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.target = Path(self.tmp.name) / "target"
        self.files = (
            "actuator/src/main/java/org/tron/core/vm/VM.java",
            "actuator/src/main/java/org/tron/core/vm/program/Program.java",
            "actuator/src/main/java/org/tron/core/vm/repository/Repository.java",
            "actuator/src/main/java/org/tron/core/vm/nativecontract/Processor.java",
            "actuator/src/main/java/org/tron/core/vm/trace/ProgramTrace.java",
            "common/src/main/java/org/tron/core/vm/config/VMConfig.java",
        )
        for relative in self.files:
            path = self.target / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("class Example {}\n", encoding="utf-8")
        context = self.target / "actuator/src/main/java/org/tron/core/actuator/VMActuator.java"
        context.parent.mkdir(parents=True, exist_ok=True)
        context.write_text("class Example {}\n", encoding="utf-8")
        self.config = load_config(ROOT)

    def tearDown(self):
        self.tmp.cleanup()

    def test_plan_partitions_every_vm_source_exactly_once(self):
        plan = build_plan(
            self.config,
            "daily-tvm",
            day_of_year=1,
            target=self.target,
        )
        shards = [job for job in plan.jobs if job.campaign_shard]
        self.assertEqual(
            [job.campaign_shard for job in shards],
            list(SHARD_ORDER),
        )
        assigned = [path for job in shards for path in job.coverage_paths]
        self.assertEqual(sorted(assigned), list(inventory_vm_sources(self.target)))
        self.assertEqual(len(assigned), len(set(assigned)))
        self.assertTrue(all(job.profile.name == "triage" for job in shards))
        self.assertEqual(len([job for job in plan.jobs if job.profile.per_finding]), 1)
        self.assertTrue(
            all(
                "actuator/src/main/java/org/tron/core/actuator/VMActuator.java"
                in job.paths
                for job in shards
            )
        )

    def test_manifest_requires_semantic_file_evidence(self):
        plan = build_plan(
            self.config,
            "daily-tvm",
            day_of_year=1,
            target=self.target,
        )
        results = []
        for job in (job for job in plan.jobs if job.campaign_shard):
            scan_dir = self.target.parent / "results" / job.id
            scan_dir.mkdir(parents=True)
            (scan_dir / "coverage.json").write_text(
                json.dumps({
                    "completeness": "complete",
                    "includePaths": list(job.coverage_paths),
                    "surfaces": [
                        {"status": "no_issue_found", "notes": path}
                        for path in job.coverage_paths
                    ],
                }),
                encoding="utf-8",
            )
            results.append(SimpleNamespace(
                job_id=job.id,
                counts_toward_exit=True,
                scan_dir=str(scan_dir),
                returncode=0,
                export_returncode=0,
            ))
        complete = build_coverage_manifest(plan, results, self.target, False)
        self.assertEqual(complete["completeness"], "complete")
        self.assertEqual(complete["evidenced_count"], len(self.files))

        first = next(job for job in plan.jobs if job.campaign_shard)
        first_result = next(result for result in results if result.job_id == first.id)
        Path(first_result.scan_dir, "coverage.json").write_text(
            json.dumps({
                "completeness": "complete",
                "includePaths": list(first.coverage_paths),
                "surfaces": [],
            }),
            encoding="utf-8",
        )
        partial = build_coverage_manifest(plan, results, self.target, False)
        self.assertEqual(partial["completeness"], "partial")
        self.assertEqual(
            set(partial["missing_files"]),
            set(first.coverage_paths),
        )

    def test_ambiguous_basenames_require_repository_relative_paths(self):
        scan_dir = self.target.parent / "ambiguous"
        scan_dir.mkdir()
        (scan_dir / "report.md").write_text(
            "Reviewed Op.java and its dispatch invariant.\n",
            encoding="utf-8",
        )
        core = "actuator/src/main/java/org/tron/core/vm/Op.java"
        trace = "actuator/src/main/java/org/tron/core/vm/trace/Op.java"
        self.assertEqual(evidenced_paths(scan_dir, (core,), (core, trace)), ())
        (scan_dir / "report.md").write_text(
            f"Reviewed {core} and its dispatch invariant.\n",
            encoding="utf-8",
        )
        self.assertEqual(evidenced_paths(scan_dir, (core,), (core, trace)), (core,))


if __name__ == "__main__":
    unittest.main()
