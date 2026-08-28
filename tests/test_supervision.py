import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from tron_security_review.supervision import ProgressTracker, execution_path, run_command
from tron_security_review.runner import _fallback_reason, _recovery_reason, InvocationResult


class SupervisionTests(unittest.TestCase):
    def test_startup_and_reconnect_are_not_first_response(self):
        tracker = ProgressTracker()
        for line in ("[00:00] Preparing scan", "[00:01] Scan phase: preflight (0/2 files).",
                     "[05:00] Running scan: preflight | Files: 0/2",
                     'codex-security: debug: connection.retry reason="network" attempt=1',
                     'codex-security: debug: authentication.selected verified=true'):
            self.assertFalse(tracker.feed(line + "\n"))

    def test_changed_counters_not_heartbeats_are_progress(self):
        tracker = ProgressTracker()
        self.assertTrue(tracker.feed("[00:10] Tokens: 1,000 input, 900 cached, 50 output\n"))
        self.assertFalse(tracker.feed("[09:59] Tokens: 1,000 input, 900 cached, 50 output\n"))
        self.assertTrue(tracker.feed("[10:00] Tokens: 2,000 input, 900 cached, 55 output\n"))
        self.assertTrue(tracker.feed("[10:01] Scan phase: analyzing attack paths (1/2 files).\n"))
        self.assertFalse(tracker.feed("[10:02] Scan phase: analyzing attack paths (1/2 files).\n"))

    def test_verbose_cost_and_split_lines(self):
        tracker = ProgressTracker()
        self.assertFalse(tracker.feed('codex-security: debug: cost.updated input_tokens='))
        self.assertTrue(tracker.feed('100 output_tokens=5 estimated_usd=0.2\n'))
        self.assertFalse(tracker.feed('codex-security: debug: cost.updated input_tokens=100 output_tokens=5 estimated_usd=0.2\n'))
        self.assertFalse(tracker.feed("Estimated cost: $...\n"))

    def run_child(self, script, **limits):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stdout, stderr = root / "stdout.json", root / "stderr.log"
            code = run_command([sys.executable, "-u", "-c", script], dict(os.environ), stdout, stderr, **limits)
            return code, json.loads(execution_path(stdout).read_text()), stderr.read_text()

    def test_first_response_watchdog_ignores_startup_noise(self):
        code, execution, stderr = self.run_child(
            'import sys,time; print("Preparing scan",file=sys.stderr); time.sleep(3)',
            timeout_seconds=2, first_response_timeout_seconds=0.12, idle_timeout_seconds=0.1)
        self.assertEqual(code, 2)
        self.assertEqual(execution["termination_reason"], "first_response_timeout")
        self.assertIn("orchestrator timeout", stderr)
        self.assertLess(execution["duration_seconds"], 2)

    def test_idle_watchdog_ignores_repeated_progress(self):
        code, execution, _ = self.run_child(
            'import sys,time\nfor i in range(30):\n print("Tokens: 10 input, 0 cached, 1 output",file=sys.stderr); time.sleep(.03)',
            timeout_seconds=2, first_response_timeout_seconds=1, idle_timeout_seconds=.13)
        self.assertEqual(code, 2)
        self.assertEqual(execution["termination_reason"], "no_progress_timeout")

    def test_active_work_and_completed_command_do_not_timeout(self):
        code, execution, _ = self.run_child(
            'import sys,time\nfor i in range(1,6):\n print(f"Tokens: {i} input, 0 cached, {i} output",file=sys.stderr); time.sleep(.06)',
            timeout_seconds=2, first_response_timeout_seconds=1, idle_timeout_seconds=.4)
        self.assertEqual(code, 0)
        self.assertIsNone(execution["termination_reason"])

    def test_invalid_time_limits_fail_before_start(self):
        for limit in (0, -1, float("nan"), float("inf")):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                self.run_child("raise Exception('must not run')", first_response_timeout_seconds=limit)

    def test_stall_recovery_never_overrides_safety_budget_or_auth(self):
        with tempfile.TemporaryDirectory() as directory:
            stderr = Path(directory) / "stderr.log"
            for reason in ("first_response_timeout", "no_progress_timeout"):
                stderr.write_text("orchestrator timeout")
                self.assertEqual(_fallback_reason(stderr, reason), reason)
                for block in ("content_filter", "Scan stopped: estimated cost", "Authentication interrupted", 'connection.retry reason="authorization"'):
                    stderr.write_text("orchestrator timeout\n" + block)
                    self.assertIsNone(_fallback_reason(stderr, reason))
            stderr.write_text("orchestrator timeout")
            self.assertIsNone(_fallback_reason(stderr, "wall_timeout"))

    def test_completed_partial_scan_does_not_retry_historical_network_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stderr, stdout = root / "stderr.log", root / "stdout.json"
            stderr.write_text('codex-security: debug: connection.retry reason="network"')
            stdout.write_text('{"turn":{"status":"completed"}}')
            result = InvocationResult("test", (), str(root / "results"), 2, None, str(stdout), str(stderr), None, "gpt-5.6-sol", "high")
            self.assertIsNone(_recovery_reason(result))
            stdout.write_text("")
            self.assertEqual(_recovery_reason(result), "network_error")
