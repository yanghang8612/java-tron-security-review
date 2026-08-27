from pathlib import Path
import unittest

from tron_security_review.config import load_config
from tron_security_review.planner import build_plan


ROOT = Path(__file__).resolve().parents[1]


class PlannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_config(ROOT)

    def test_critical_diff_selects_triage_and_verifier(self) -> None:
        plan = build_plan(
            self.config,
            "pr",
            files=("actuator/src/main/java/org/tron/core/vm/VM.java",),
        )
        self.assertEqual(plan.highest_risk, "critical")
        self.assertEqual([job.profile.name for job in plan.jobs], ["triage", "verifier"])

    def test_unmatched_java_diff_still_gets_triage(self) -> None:
        plan = build_plan(
            self.config,
            "pr",
            files=("common/src/main/java/org/tron/common/utils/Example.java",),
        )
        self.assertEqual(plan.highest_risk, "medium")
        self.assertEqual([job.profile.name for job in plan.jobs], ["triage"])

    def test_empty_incremental_scan_is_skipped(self) -> None:
        plan = build_plan(self.config, "nightly", files=())
        self.assertEqual(plan.jobs, ())
        self.assertEqual(plan.skipped_reason, "no changed files")

    def test_week_one_rotates_to_vm_scope(self) -> None:
        plan = build_plan(self.config, "weekly", iso_week=1)
        self.assertEqual(len(plan.jobs), 1)
        self.assertEqual(plan.jobs[0].profile.name, "deep")
        self.assertEqual(plan.jobs[0].scope.id, "vm-execution")

    def test_daily_tvm_rotates_one_critical_execution_facet(self) -> None:
        plan = build_plan(self.config, "daily-tvm", day_of_year=1)
        self.assertEqual(plan.highest_risk, "critical")
        self.assertEqual(
            [job.profile.name for job in plan.jobs], ["triage", "verifier"]
        )
        self.assertTrue(all(job.scope.id == "tvm-entry-context" for job in plan.jobs))
        self.assertTrue(
            all(
                "actuator/src/main/java/org/tron/core/actuator/VMActuator.java"
                in job.paths
                for job in plan.jobs
            )
        )
        self.assertTrue(all(job.scope.focus for job in plan.jobs))

    def test_daily_tvm_advances_to_the_next_facet(self) -> None:
        first = build_plan(self.config, "daily-tvm", day_of_year=1)
        second = build_plan(self.config, "daily-tvm", day_of_year=2)
        self.assertEqual(first.jobs[0].scope.id, "tvm-entry-context")
        self.assertEqual(second.jobs[0].scope.id, "tvm-opcode-dispatch")

    def test_daily_tvm_scope_can_be_forced_for_reproduction(self) -> None:
        plan = build_plan(
            self.config,
            "daily-tvm",
            scope_id="tvm-state-rollback",
            day_of_year=1,
        )
        self.assertTrue(
            all(job.scope.id == "tvm-state-rollback" for job in plan.jobs)
        )

    def test_daily_tvm_rejects_the_broad_weekly_scope(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown daily TVM scope"):
            build_plan(self.config, "daily-tvm", scope_id="vm-execution")

    def test_plan_serializes_paths(self) -> None:
        plan = build_plan(self.config, "weekly", iso_week=1)
        document = plan.as_dict()
        self.assertIsInstance(document["jobs"][0]["profile"]["prompt"], str)


if __name__ == "__main__":
    unittest.main()
