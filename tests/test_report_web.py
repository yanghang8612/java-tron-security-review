import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import quote
import zipfile

from tron_security_review.report_web import Auth, ReportServer, ReportStore, allowed_artifact, init_auth

ROOT = Path(__file__).resolve().parents[1]
RUN = "20260827T182332Z-daily-tvm-test"
REPORT = "triage-tvm-calls/results/report.md"
COVERAGE = "triage-tvm-calls/results/coverage.json"


class ReportStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.scans = self.root / "scans"
        self.scans.mkdir()
        self.run = self.scans / RUN
        (self.run / "triage-tvm-calls" / "results").mkdir(parents=True)
        self.manifest = {"created_at": "2026-08-27T18:23:32Z", "completed_at": "2026-08-27T18:31:24Z",
                         "partial_coverage": True, "results": [{"model": "model-primary", "returncode": 2, "estimated_cost": 2.25}],
                         "plan": {"run_mode": "daily-tvm", "jobs": [{"scope": {"id": "tvm-calls"}, "profile": {"model": "model-primary"}}]}}
        self.write("run-manifest.json", self.manifest)
        self.write("aggregate.json", {"finding_group_count": 0, "finding_groups": []})
        self.write(COVERAGE, {"completeness": "partial", "deferred": [{"id": "candidate-1", "reason": "Runtime evidence required"}]})
        (self.run / REPORT).write_text("# Test report\n<script>bad()</script>\n")
        (self.run / "target-revision.txt").write_text("a" * 40)
        self.store = ReportStore(self.scans)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def write(self, path, value):
        (self.run / path).write_text(json.dumps(value))

    def test_partial_is_not_green(self):
        result = self.store.detail(RUN)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["finding_count"], 0)
        self.assertEqual(len(result["deferred"]), 1)
        self.assertEqual(result["estimated_cost"], 2.25)
        self.assertEqual(result["scopes"], ["tvm-calls"])

    def test_complete_requires_coverage(self):
        self.manifest["partial_coverage"] = False
        self.manifest["results"][0]["returncode"] = 0
        self.write("run-manifest.json", self.manifest)
        self.assertEqual(self.store.summary(RUN)["status"], "partial")
        self.write(COVERAGE, {"completeness": "complete"})
        self.assertEqual(self.store.summary(RUN)["status"], "completed")
        (self.run / COVERAGE).unlink()
        self.assertEqual(self.store.summary(RUN)["status"], "unknown")

    def test_failure_dry_run_and_interruption(self):
        self.manifest["results"][0]["returncode"] = 1
        self.write("run-manifest.json", self.manifest)
        self.assertEqual(self.store.summary(RUN)["status"], "failed")
        self.manifest["dry_run"] = True
        self.write("run-manifest.json", self.manifest)
        self.assertEqual(self.store.summary(RUN)["status"], "dry_run")
        self.manifest.pop("dry_run")
        self.manifest.pop("completed_at")
        self.write("run-manifest.json", self.manifest)
        self.assertEqual(self.store.summary(RUN)["status"], "unfinished")

    def test_missing_and_malformed_are_unknown(self):
        (self.run / "run-manifest.json").write_text("{")
        (self.run / "aggregate.json").write_text("not json")
        value = self.store.summary(RUN)
        self.assertEqual(value["status"], "unknown")
        self.assertIsNone(value["finding_count"])
        self.assertTrue(value["warnings"])

    def test_nan_is_not_valid_report(self):
        (self.run / "aggregate.json").write_text('{"finding_group_count": NaN}')
        self.assertIsNone(self.store.summary(RUN)["finding_count"])

    def test_fallback_cost_includes_failed_attempt(self):
        self.manifest["results"].append({"returncode": 1, "counts_toward_exit": False, "estimated_cost": 1.5, "model": "fallback-attempt"})
        self.write("run-manifest.json", self.manifest)
        result = self.store.summary(RUN)
        self.assertEqual(result["estimated_cost"], 3.75)
        self.assertEqual(result["status"], "partial")

    def test_artifact_allowlist_and_archive(self):
        (self.run / "triage-tvm-calls" / "invocation.stderr.log").write_text("PRIVATE LOG")
        (self.run / "auth.json").write_text("SECRET")
        self.assertTrue(allowed_artifact("verifier-tvm/candidates/001-test/gpt-5.5/results/report.md"))
        self.assertTrue(allowed_artifact("verifier-tvm/candidates/001-test/gpt-5.5/results.sarif"))
        self.assertTrue(allowed_artifact("primary/results/report.md"))
        self.assertTrue(allowed_artifact("deep-vm-execution/results/coverage.json"))
        self.assertFalse(allowed_artifact("triage-tvm-calls/invocation.stderr.log"))
        self.assertFalse(allowed_artifact("../auth.json"))
        with zipfile.ZipFile(io.BytesIO(self.store.archive(RUN))) as archive:
            self.assertIn(RUN + "/" + REPORT, archive.namelist())
            self.assertFalse(any("auth" in n or ".log" in n for n in archive.namelist()))

    def test_symlink_traversal_and_fifo_blocked(self):
        secret = self.root / "secret"
        secret.write_text("DO NOT READ")
        (self.run / "aggregate.json").unlink()
        (self.run / "aggregate.json").symlink_to(secret)
        (self.scans / "latest").symlink_to(self.run)
        (self.run / "verifier-escape").symlink_to(self.root, target_is_directory=True)
        self.assertEqual(self.store.run_ids(), [RUN])
        for run_id, path in [(RUN, "aggregate.json"), ("..", "aggregate.json"), (RUN, "../secret"), ("latest", REPORT)]:
            with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                self.store.read(run_id, path)
        (self.run / "aggregate.json").unlink()
        os.mkfifo(self.run / "aggregate.json")
        with self.assertRaises(ValueError):
            self.store.read(RUN, "aggregate.json")

    def test_file_and_archive_size_limits(self):
        with patch("tron_security_review.report_web.FILE_LIMIT", 10):
            with self.assertRaises(ValueError):
                self.store.read(RUN, REPORT)
        with patch("tron_security_review.report_web.ARCHIVE_LIMIT", 10):
            with self.assertRaises(ValueError):
                self.store.archive(RUN)


class ReportHTTPTests(ReportStoreTests):
    def setUp(self):
        super().setUp()
        self.auth_file, self.login_file = self.root / "auth.json", self.root / "login.txt"
        init_auth(self.auth_file, self.login_file)
        self.password = dict(line.split("=", 1) for line in self.login_file.read_text().splitlines())["password"]
        self.auth = Auth(self.auth_file)
        self.server = ReportServer(("127.0.0.1", 0), self.store, self.auth)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.cookie = None
        self.host = "127.0.0.1:" + str(self.server.server_port)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        super().tearDown()

    def request(self, path, method="GET", body=None, headers=None):
        client = http.client.HTTPConnection(self.host, timeout=5)
        all_headers = {"Cookie": self.cookie} if self.cookie else {}
        all_headers.update(headers or {})
        client.request(method, "/security" + path, body=body, headers=all_headers)
        response = client.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        client.close()
        return result

    def login(self):
        result = self.request("/api/login", "POST", json.dumps({"username": "reviewer", "password": self.password}),
                              {"Content-Type": "application/json", "Origin": "http://" + self.host})
        self.assertEqual(result[0], 200)
        self.cookie = result[1]["Set-Cookie"].split(";")[0]
        return result

    def test_auth_is_required_for_every_report_route(self):
        for path in ("/api/runs", "/api/runs/" + RUN, "/api/runs/" + RUN + "/download", "/api/runs/" + RUN + "/artifact?path=" + REPORT):
            self.assertEqual(self.request(path)[0], 401)
        self.assertEqual(self.request("/")[0], 200)
        self.assertEqual(self.request("/api/health")[0], 200)

    def test_login_read_download_and_logout(self):
        result = self.login()
        self.assertIn("HttpOnly", result[1]["Set-Cookie"])
        self.assertIn("SameSite=Strict", result[1]["Set-Cookie"])
        self.assertNotIn("; Secure", result[1]["Set-Cookie"])
        self.assertEqual(json.loads(self.request("/api/runs")[2])["total"], 1)
        self.assertEqual(json.loads(self.request("/api/runs/" + RUN)[2])["status"], "partial")
        code, headers, body = self.request("/api/runs/" + RUN + "/artifact?path=" + REPORT)
        self.assertEqual(code, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/plain"))
        self.assertIn("attachment", headers["Content-Disposition"])
        self.assertIn(b"<script>", body)
        self.assertIn("no-store", headers["Cache-Control"])
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertEqual(self.request("/api/runs/" + RUN + "/download")[0], 200)
        self.assertEqual(self.request("/api/logout", "POST", "{}", {"Content-Type": "application/json", "Origin": "http://" + self.host})[0], 200)
        self.assertEqual(self.request("/api/runs")[0], 401)

    def test_cross_origin_login_and_logout_rejected(self):
        for path in ("/api/login", "/api/logout"):
            result = self.request(path, "POST", "{}", {"Content-Type": "application/json", "Origin": "http://evil.test"})
            self.assertEqual(result[0], 403)

    def test_bad_credentials_and_throttling(self):
        self.assertEqual(self.auth.login("reviewer", "wrong")[1], 401)
        self.auth.attempts.extend([self.auth.attempts[-1]] * 14)
        self.assertEqual(self.auth.login("reviewer", self.password)[1], 429)

    def test_encoded_traversal_and_logs_rejected(self):
        self.login()
        for path in ("../auth.json", "triage-tvm-calls/invocation.stderr.log", "triage-tvm-calls/results/../../auth.json"):
            code = self.request("/api/runs/" + RUN + "/artifact?path=" + quote(path, safe=""))[0]
            self.assertEqual(code, 404)

    def test_auth_is_private_and_not_overwritten(self):
        self.assertEqual(self.auth_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.login_file.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(self.password, self.auth_file.read_text())
        with self.assertRaises(ValueError):
            init_auth(self.auth_file, self.login_file)

    def test_frontend_never_injects_model_html(self):
        source = (ROOT / "src/tron_security_review/web/app.js").read_text()
        self.assertNotIn("innerHTML", source)
        self.assertNotIn("insertAdjacentHTML", source)
        self.assertIn("textContent", source)


class ReportDeploymentTests(unittest.TestCase):
    def test_container_is_read_only_loopback_and_separate_from_scanner(self):
        script = (ROOT / "deploy/server/run-report-web.sh").read_text()
        for value in ("--read-only", "--cap-drop ALL", "--security-opt no-new-privileges", "127.0.0.1:8765:8765", "dst=/scan/reports,readonly", "dst=/run/report-auth.json,readonly", "--user 10001:10001"):
            self.assertIn(value, script)
        for value in ("/auth,", "docker.sock", "OPENAI_API_KEY", "--privileged"):
            self.assertNotIn(value, script)
        installer = (ROOT / "deploy/server/install-report-web.sh").read_text()
        self.assertNotIn("java-tron-security-review.timer", installer)
        self.assertIn("nginx -t", installer)
        self.assertIn("trap rollback ERR", installer)

    def test_nginx_insertion_is_scoped_idempotent_and_preserves_routes(self):
        spec = importlib.util.spec_from_file_location("nginx_config", ROOT / "deploy/server/configure-report-nginx.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        original = "server {\n    listen 6060;\n    location /gm/ { proxy_pass http://gtron_main/; }\n}\n"
        updated = module.configure(original)
        self.assertEqual(updated.replace("    " + module.INCLUDE + "\n", ""), original)
        self.assertEqual(module.configure(updated), updated)
        for invalid in ("server { listen 6060; }", original + original, original.replace("location /gm/", "location /security/")):
            with self.assertRaises(ValueError):
                module.configure(invalid)


if __name__ == "__main__":
    unittest.main()
