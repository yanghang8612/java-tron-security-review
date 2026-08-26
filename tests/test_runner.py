from pathlib import Path
import tempfile
import unittest
import unittest.mock

from tron_security_review.config import available_knowledge_bases, load_config
from tron_security_review.planner import build_plan
from tron_security_review.runner import (
    _safe_environment,
    build_scan_command,
    ensure_output_is_safe,
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

    def test_daily_tvm_standard_command_uses_paths(self) -> None:
        plan = build_plan(self.config, "daily-tvm")
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
        self.assertNotIn("--diff", command)

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
