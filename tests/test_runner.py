import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
import unittest.mock

from tron_security_review.config import available_knowledge_bases, load_config
from tron_security_review.planner import build_plan
from tron_security_review.runner import (
    _candidate_paths,
    _cyber_safety_blocked,
    _estimated_cost,
    _has_partial_results,
    _run_command,
    _safe_environment,
    build_scan_command,
    ensure_output_is_safe,
    run_plan,
)


ROOT = Path(__file__).resolve().parents[1]


class RunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_config(ROOT)

    def test_rejects_output_inside_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            with self.assertRaises(ValueError):
                ensure_output_is_safe(target, target / "security-results")

    def test_verifier_budget_bounds_all_primary_and_fallback_attempts(self) -> None:
        verifier = next(
            profile for profile in self.config.profiles if profile.name == "verifier"
        )
        self.assertTrue(verifier.per_finding)
        primary_worst_case = (
            verifier.max_candidates * verifier.per_finding_max_cost
        )
        self.assertLessEqual(primary_worst_case, verifier.max_cost)
        self.assertEqual(verifier.fallback_model, "gpt-5.5")
        self.assertEqual(verifier.fallback_effort, "xhigh")
        self.assertEqual(verifier.max_fallbacks, 3)
        self.assertEqual(verifier.per_finding_max_cost, 30)
        self.assertEqual(verifier.per_finding_timeout_minutes, 60)
        self.assertEqual(verifier.fallback_timeout_minutes, 30)

    def test_detects_only_explicit_cyber_safety_marker_and_reads_cost(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stderr = Path(directory) / "stderr.log"
            stderr.write_text(
                "Estimated cost: $7.250000 of $8.00 limit\n"
                "This content was flagged for possible cyber-security risk.\n",
                encoding="utf-8",
            )
            self.assertTrue(_cyber_safety_blocked(stderr))
            self.assertEqual(_estimated_cost(stderr), 7.25)
            stderr.write_text("partial coverage: timeout\n", encoding="utf-8")
            self.assertFalse(_cyber_safety_blocked(stderr))

    def test_fallback_timeout_stops_the_process_group_as_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stdout = root / "stdout.log"
            stderr = root / "stderr.log"
            returncode = _run_command(
                ["/bin/sh", "-c", "sleep 5"],
                {"PATH": "/usr/bin:/bin"},
                stdout,
                stderr,
                timeout_seconds=0.05,
            )
            self.assertEqual(returncode, 2)
            self.assertIn("orchestrator timeout", stderr.read_text(encoding="utf-8"))

    def test_effective_exit_two_marks_partial_but_superseded_attempt_does_not(self) -> None:
        superseded = SimpleNamespace(
            counts_toward_exit=False,
            returncode=2,
            export_returncode=None,
        )
        successful_fallback = SimpleNamespace(
            counts_toward_exit=True,
            returncode=0,
            export_returncode=None,
        )
        failed_fallback = SimpleNamespace(
            counts_toward_exit=True,
            returncode=2,
            export_returncode=None,
        )
        self.assertFalse(_has_partial_results((superseded, successful_fallback)))
        self.assertTrue(_has_partial_results((superseded, failed_fallback)))

    def test_candidate_paths_are_scoped_and_cannot_escape_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            source = target / "actuator/src/main/java/org/tron/core/vm/Example.java"
            source.parent.mkdir(parents=True)
            source.write_text("class Example {}\n", encoding="utf-8")
            item = {
                "locations": [
                    {"path": "actuator/src/main/java/org/tron/core/vm/Example.java:12"},
                    {"path": "../../etc/passwd"},
                ]
            }
            paths = _candidate_paths(
                item,
                target,
                ("actuator/src/main/java/org/tron/core/vm",),
            )
            self.assertEqual(
                paths,
                ("actuator/src/main/java/org/tron/core/vm/Example.java",),
            )

    def test_safety_blocked_candidate_falls_back_to_gpt_5_5(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            source = target / "actuator/src/main/java/org/tron/core/vm/VM.java"
            source.parent.mkdir(parents=True)
            source.write_text("class Example {}\n", encoding="utf-8")
            output_root = root / "output"
            cli_bin = root / "codex-security"
            cli_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            cli_bin.chmod(0o755)
            plan = build_plan(
                self.config,
                "daily-tvm",
                scope_id="tvm-opcode-dispatch",
            )

            def fake_run(
                command,
                environment,
                stdout_path,
                stderr_path,
                timeout_seconds=None,
            ):
                stdout_path.parent.mkdir(parents=True, exist_ok=True)
                stdout_path.write_text("{}\n", encoding="utf-8")
                if "export" in command:
                    Path(command[command.index("--output") + 1]).write_text(
                        "{}\n", encoding="utf-8"
                    )
                    stderr_path.write_text("", encoding="utf-8")
                    return 0
                scan_dir = Path(command[command.index("--output-dir") + 1])
                scan_dir.mkdir(parents=True, exist_ok=True)
                model = command[command.index("--model") + 1]
                if model == "gpt-5.6-terra":
                    (scan_dir / "findings.json").write_text(
                        json.dumps(
                            {
                                "findings": [
                                    {
                                        "id": "candidate-1",
                                        "title": "Candidate",
                                        "severity": "high",
                                        "location": {
                                            "path": "actuator/src/main/java/org/tron/core/vm/VM.java"
                                        },
                                    }
                                ]
                            }
                        ),
                        encoding="utf-8",
                    )
                    stderr_path.write_text(
                        "Estimated cost: $1.0 of $8.0 limit\n", encoding="utf-8"
                    )
                    return 0
                if model == "gpt-5.6-sol":
                    stderr_path.write_text(
                        "Estimated cost: $2.0 of $8.0 limit\n"
                        "This content was flagged for possible cyber-security risk.\n",
                        encoding="utf-8",
                    )
                    return 2
                self.assertEqual(model, "gpt-5.5")
                (scan_dir / "findings.json").write_text(
                    '{"findings": []}\n', encoding="utf-8"
                )
                stderr_path.write_text(
                    "Estimated cost: $1.5 of $5.0 limit\n", encoding="utf-8"
                )
                return 0

            with unittest.mock.patch(
                "tron_security_review.runner._run_command", side_effect=fake_run
            ):
                run_dir, results = run_plan(
                    config=self.config,
                    plan=plan,
                    target=target,
                    output_root=output_root,
                    run_id="test-run",
                    auth="chatgpt",
                    cli_bin=cli_bin,
                )

            self.assertEqual([result.model for result in results], [
                "gpt-5.6-terra",
                "gpt-5.6-sol",
                "gpt-5.5",
            ])
            self.assertFalse(results[1].counts_toward_exit)
            self.assertTrue(results[2].counts_toward_exit)
            self.assertEqual(results[1].timeout_seconds, 3600)
            fallback_command = results[2].command
            self.assertEqual(
                fallback_command[fallback_command.index("--effort") + 1], "xhigh"
            )
            self.assertEqual(results[2].timeout_seconds, 1800)
            self.assertNotIn("--max-cost", fallback_command)
            self.assertIn(str(source.relative_to(target)), fallback_command)
            manifest = json.loads(
                (run_dir / "run-manifest.json").read_text(encoding="utf-8")
            )
            self.assertFalse(manifest["partial_coverage"])

    def test_openai_child_environment_does_not_receive_aws_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with unittest.mock.patch.dict(
                "os.environ",
                {
                    "OPENAI_API_KEY": "openai-secret",
                    "AWS_ACCESS_KEY_ID": "aws-secret",
                    "CODEX_HOME": "/unrelated/codex-home",
                },
                clear=True,
            ):
                environment = _safe_environment(
                    Path(directory), {"openai"}, auth="api-key"
                )
        self.assertEqual(environment["OPENAI_API_KEY"], "openai-secret")
        self.assertNotIn("AWS_ACCESS_KEY_ID", environment)
        self.assertNotIn("CODEX_HOME", environment)
        self.assertEqual(environment["AWS_EC2_METADATA_DISABLED"], "true")

    def test_bedrock_child_environment_does_not_receive_openai_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with unittest.mock.patch.dict(
                "os.environ",
                {
                    "OPENAI_API_KEY": "openai-secret",
                    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/credentials",
                    "AWS_REGION": "us-east-2",
                },
                clear=True,
            ):
                environment = _safe_environment(
                    Path(directory), {"amazon-bedrock"}
                )
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertEqual(
            environment["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"], "/credentials"
        )

    def test_chatgpt_auth_receives_codex_home_but_not_api_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with unittest.mock.patch.dict(
                "os.environ",
                {
                    "OPENAI_API_KEY": "openai-secret",
                    "CODEX_API_KEY": "codex-secret",
                    "CODEX_HOME": "/scan/auth",
                },
                clear=True,
            ):
                environment = _safe_environment(
                    Path(directory), {"openai"}, auth="chatgpt"
                )
        self.assertEqual(environment["CODEX_HOME"], "/scan/auth")
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertNotIn("CODEX_API_KEY", environment)
        self.assertNotIn("CODEX_SECURITY_STATE_DIR", environment)

    def test_pr_command_is_read_only_and_diff_scoped(self) -> None:
        plan = build_plan(
            self.config,
            "pr",
            files=("actuator/src/main/java/org/tron/core/vm/VM.java",),
        )
        job = plan.jobs[0]
        target = ROOT.parent / "java-tron"
        command = build_scan_command(
            config=self.config,
            job=job,
            plan=plan,
            target=target,
            scan_dir=ROOT / "var/test/results",
            prompt_path=ROOT / "prompts/scan.md",
            knowledge_bases=available_knowledge_bases(self.config),
            auth="api-key",
            cli_bin=None,
            base_commit="a" * 40,
            head_commit="b" * 40,
            dry_run=True,
        )
        self.assertIn("--diff", command)
        self.assertIn("--head", command)
        self.assertIn("--dry-run", command)
        self.assertNotIn("--auth", command)
        self.assertNotIn("--patch", command)
        self.assertNotIn("--create-pr", command)
        self.assertNotIn("--plugin-path", command)
        self.assertIn("--validation-prompt-file", command)
        self.assertNotIn("--post-scan-prompt-file", command)

    def test_deep_command_uses_paths_not_diff(self) -> None:
        plan = build_plan(self.config, "weekly", iso_week=1)
        job = plan.jobs[0]
        target = ROOT.parent / "java-tron"
        command = build_scan_command(
            config=self.config,
            job=job,
            plan=plan,
            target=target,
            scan_dir=ROOT / "var/test/deep-results",
            prompt_path=ROOT / "prompts/scan.md",
            knowledge_bases=available_knowledge_bases(self.config),
            auth="api-key",
            cli_bin=None,
            base_commit="a" * 40,
            head_commit="b" * 40,
            dry_run=True,
        )
        self.assertEqual(command[command.index("--mode") + 1], "deep")
        self.assertIn("--path", command)
        self.assertNotIn("--diff", command)
        self.assertNotIn("--validation-prompt-file", command)
        self.assertNotIn("--post-scan-prompt-file", command)

    def test_daily_tvm_standard_command_uses_paths(self) -> None:
        plan = build_plan(self.config, "daily-tvm", day_of_year=1)
        command = build_scan_command(
            config=self.config,
            job=plan.jobs[0],
            plan=plan,
            target=ROOT.parent / "java-tron",
            scan_dir=ROOT / "var/test/tvm-results",
            prompt_path=ROOT / "prompts/scan.md",
            knowledge_bases=available_knowledge_bases(self.config),
            auth="api-key",
            cli_bin=None,
            base_commit=None,
            head_commit="b" * 40,
            dry_run=True,
        )
        self.assertEqual(command[command.index("--mode") + 1], "standard")
        self.assertIn("--path", command)
        self.assertIn(
            "actuator/src/main/java/org/tron/core/actuator/VMActuator.java",
            command,
        )
        self.assertNotIn("--diff", command)
        self.assertEqual(
            command[command.index("--validation-prompt-file") + 1],
            str(self.config.system.validation_prompt),
        )
        self.assertNotIn("--post-scan-prompt-file", command)

    def test_per_finding_verifier_does_not_repeat_custom_validation(self) -> None:
        plan = build_plan(self.config, "daily-tvm", day_of_year=1)
        verifier = next(job for job in plan.jobs if job.profile.per_finding)
        command = build_scan_command(
            config=self.config,
            job=verifier,
            plan=plan,
            target=ROOT.parent / "java-tron",
            scan_dir=ROOT / "var/test/verifier-results",
            prompt_path=ROOT / "prompts/skeptic.md",
            knowledge_bases=available_knowledge_bases(self.config),
            auth="api-key",
            cli_bin=None,
            base_commit=None,
            head_commit="b" * 40,
            dry_run=True,
        )
        self.assertNotIn("--validation-prompt-file", command)
        self.assertNotIn("--post-scan-prompt-file", command)

    def test_daily_tvm_prompt_contains_cross_module_focus(self) -> None:
        plan = build_plan(self.config, "daily-tvm", day_of_year=4)
        job = plan.jobs[0]
        with tempfile.TemporaryDirectory() as directory:
            prompt_path = Path(directory) / "scan-context.md"
            from tron_security_review.runner import _render_job_prompt

            _render_job_prompt(job, plan, prompt_path)
            rendered = prompt_path.read_text(encoding="utf-8")
        self.assertIn("Selected scope: tvm-state-rollback", rendered)
        self.assertIn("Required analysis focus", rendered)
        self.assertIn("Trace account, contract, code, storage", rendered)

    def test_chatgpt_scan_command_selects_stored_auth(self) -> None:
        plan = build_plan(self.config, "daily-tvm")
        command = build_scan_command(
            config=self.config,
            job=plan.jobs[0],
            plan=plan,
            target=ROOT.parent / "java-tron",
            scan_dir=ROOT / "var/test/tvm-chatgpt-results",
            prompt_path=ROOT / "prompts/scan.md",
            knowledge_bases=available_knowledge_bases(self.config),
            auth="chatgpt",
            cli_bin=None,
            base_commit=None,
            head_commit="b" * 40,
            dry_run=False,
        )
        self.assertEqual(command[command.index("--auth") + 1], "chatgpt")

    def test_bedrock_override_omits_openai_auth_flag(self) -> None:
        plan = build_plan(self.config, "daily-tvm")
        command = build_scan_command(
            config=self.config,
            job=plan.jobs[0],
            plan=plan,
            target=ROOT.parent / "java-tron",
            scan_dir=ROOT / "var/test/bedrock-results",
            prompt_path=ROOT / "prompts/scan.md",
            knowledge_bases=available_knowledge_bases(self.config),
            auth="api-key",
            cli_bin=None,
            base_commit=None,
            head_commit="b" * 40,
            dry_run=True,
            provider_override="amazon-bedrock",
            model_override="openai.gpt-5.6-sol",
        )
        self.assertIn("amazon-bedrock", command)
        self.assertNotIn("--auth", command)


if __name__ == "__main__":
    unittest.main()
