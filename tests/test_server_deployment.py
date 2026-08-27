import json
import hashlib
import re
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "deploy" / "server"


class ServerDeploymentTests(unittest.TestCase):
    def test_daily_runner_keeps_source_read_only_and_reports_outside_it(self) -> None:
        script = (SERVER / "run-daily-tvm.sh").read_text(encoding="utf-8")
        self.assertIn("dst=/scan/target,readonly", script)
        self.assertIn("dst=/scan/output", script)
        self.assertIn("--read-only", script)
        self.assertIn("--cap-drop ALL", script)
        self.assertIn("--security-opt no-new-privileges", script)
        self.assertIn('--security-opt "seccomp=$JTSR_SECCOMP_PROFILE"', script)
        self.assertIn('--user "$JTSR_SCANNER_UID:$JTSR_SCANNER_GID"', script)
        self.assertIn('chmod -R a+rX,a-w "$TARGET_DIR"', script)
        self.assertNotIn("--patch", script)
        self.assertNotIn("--create-pr", script)

    def test_server_installs_the_pinned_codex_security_seccomp_profile(self) -> None:
        profile_path = SERVER / "codex-security-seccomp.json"
        profile_bytes = profile_path.read_bytes()
        self.assertEqual(
            hashlib.sha256(profile_bytes).hexdigest(),
            "4d9767cdcdc79338c0ce172baab5042d1c5a7d847a0d73a10e308f54c44a286d",
        )
        profile = json.loads(profile_bytes)
        allowed = {
            name
            for rule in profile["syscalls"]
            if rule["action"] == "SCMP_ACT_ALLOW"
            for name in rule["names"]
        }
        for syscall in ("clone", "clone3", "mount", "unshare"):
            self.assertIn(syscall, allowed)
        installer = (SERVER / "install.sh").read_text(encoding="utf-8")
        self.assertIn("codex-security-seccomp.json", installer)

    def test_user_namespace_enablement_is_explicit_and_bounded(self) -> None:
        installer = (SERVER / "install.sh").read_text(encoding="utf-8")
        runner = (SERVER / "run-daily-tvm.sh").read_text(encoding="utf-8")
        sysctl = (SERVER / "java-tron-security-review-userns.conf").read_text(
            encoding="utf-8"
        )
        self.assertIn("--enable-userns", installer)
        self.assertIn("user.max_user_namespaces = 1024", sysctl)
        self.assertIn("user.max_user_namespaces=1024", installer)
        self.assertIn("user.max_user_namespaces > 0", runner)

    def test_daily_runner_uses_rotating_tvm_mode_and_prevents_overlap(self) -> None:
        script = (SERVER / "run-daily-tvm.sh").read_text(encoding="utf-8")
        self.assertIn("--mode daily-tvm", script)
        self.assertNotIn("--scope vm-execution", script)
        self.assertIn("flock -n 9", script)
        self.assertRegex(script, re.compile(r"JTSR_RETENTION_DAYS.*90"))

    def test_daily_runner_supports_git_1_8_3(self) -> None:
        script = (SERVER / "run-daily-tvm.sh").read_text(encoding="utf-8")
        self.assertIn("git_in_target()", script)
        self.assertNotRegex(
            script, re.compile(r"^\s*git\b[^\n]*\s-C(?:\s|$)", re.MULTILINE)
        )

    def test_timer_is_daily_and_persistent(self) -> None:
        timer = (SERVER / "java-tron-security-review.timer").read_text(
            encoding="utf-8"
        )
        self.assertIn("OnCalendar=*-*-* 18:17:00", timer)
        self.assertNotIn("18:17:00 UTC", timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn("Unit=java-tron-security-review.service", timer)

    def test_openai_key_is_not_baked_into_the_image(self) -> None:
        dockerfile = (ROOT / "deploy" / "container" / "Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("OPENAI_API_KEY", dockerfile)
        self.assertNotIn("CODEX_API_KEY", dockerfile)

    def test_container_requires_the_native_codex_package(self) -> None:
        container = ROOT / "deploy" / "container"
        dockerfile = (container / "Dockerfile").read_text(encoding="utf-8")
        package = json.loads((container / "package.json").read_text(encoding="utf-8"))
        self.assertIn("codex --version", dockerfile)
        self.assertIn("@openai/codex-linux-arm64", package["optionalDependencies"])
        self.assertIn("@openai/codex-linux-x64", package["optionalDependencies"])

    def test_codex_security_version_is_pinned_consistently(self) -> None:
        container = ROOT / "deploy" / "container"
        package = json.loads((container / "package.json").read_text(encoding="utf-8"))
        lock = json.loads(
            (container / "package-lock.json").read_text(encoding="utf-8")
        )
        with (ROOT / "config" / "system.toml").open("rb") as handle:
            system = tomllib.load(handle)["system"]
        expected = package["dependencies"]["@openai/codex-security"]
        self.assertEqual(
            system["cli_package"], f"@openai/codex-security@{expected}"
        )
        self.assertEqual(
            lock["packages"]["node_modules/@openai/codex-security"]["version"],
            expected,
        )
        dockerfile = (container / "Dockerfile").read_text(encoding="utf-8")
        campaign = (ROOT / ".github/workflows/security-campaign.yml").read_text(
            encoding="utf-8"
        )
        reusable = (ROOT / ".github/workflows/reusable-pr.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(f"ARG CODEX_SECURITY_VERSION={expected}", dockerfile)
        self.assertIn(f'CODEX_SECURITY_VERSION: "{expected}"', campaign)
        self.assertIn(f"@openai/codex-security@{expected}", reusable)

    def test_chatgpt_auth_is_persistent_and_separate_from_reports(self) -> None:
        runner = (SERVER / "run-daily-tvm.sh").read_text(encoding="utf-8")
        auth = (SERVER / "auth-chatgpt.sh").read_text(encoding="utf-8")
        environment = (SERVER / "jtsr.env.example").read_text(encoding="utf-8")
        self.assertIn("JTSR_AUTH=chatgpt", environment)
        self.assertIn(
            "JTSR_AUTH_ROOT=/var/lib/java-tron-security-review/auth", environment
        )
        self.assertIn("dst=/scan/auth", runner)
        self.assertIn("CODEX_HOME=/scan/auth", runner)
        self.assertIn("--auth chatgpt", runner)
        self.assertIn("codex-security login status", runner)
        self.assertIn("login --device-auth", auth)
        self.assertIn("CLI_ARGS=(login status)", auth)
        self.assertIn("CLI_ARGS=(logout)", auth)
        self.assertIn("auth root must not be inside the output root", runner)
        self.assertIn("auth root must not be inside the output root", auth)

    def test_chatgpt_auth_service_uses_the_root_only_environment_file(self) -> None:
        unit = (
            SERVER / "java-tron-security-review-auth@.service"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "EnvironmentFile=/etc/java-tron-security-review/jtsr.env", unit
        )
        self.assertIn("auth-chatgpt %i", unit)
        self.assertIn("NoNewPrivileges=true", unit)


if __name__ == "__main__":
    unittest.main()
