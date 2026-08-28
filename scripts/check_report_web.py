#!/usr/bin/env python3
"""Smoke-test a running portal without printing credentials, cookies or report contents."""
import argparse
import http.cookiejar
import io
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPCookieProcessor, Request, build_opener
import zipfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="e.g. http://127.0.0.1:6060/security/")
    parser.add_argument("--login-file", type=Path, required=True)
    args = parser.parse_args()
    base = args.url.rstrip("/")
    parsed = urlsplit(base)
    origin = parsed.scheme + "://" + parsed.netloc
    client = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(path, body=None, expected=200):
        headers = {}
        if body is not None:
            headers = {"Content-Type": "application/json", "Origin": origin}
        req = Request(base + "/api" + path, data=json.dumps(body).encode() if body is not None else None, headers=headers)
        try:
            response = client.open(req, timeout=20)
        except HTTPError as exc:
            response = exc
        with response:
            if response.status != expected:
                raise RuntimeError(f"unexpected HTTP status {response.status}; expected {expected}")
            return response.read()

    request("/runs", expected=401)
    credentials = dict(line.split("=", 1) for line in args.login_file.read_text().splitlines())
    request("/login", {"username": credentials["username"], "password": credentials["password"]})
    runs = json.loads(request("/runs"))
    result = {"authentication": "passed", "run_count": runs["total"]}
    if runs["runs"]:
        run_id = runs["runs"][0]["id"]
        prefix = "/runs/" + quote(run_id, safe="")
        detail = json.loads(request(prefix))
        for path in ("../auth.json", "triage/invocation.stderr.log"):
            request(prefix + "/artifact?path=" + quote(path, safe=""), expected=404)
        artifacts = [item for item in detail["artifacts"] if item["available"]]
        if artifacts:
            request(prefix + "/artifact?path=" + quote(artifacts[0]["path"], safe=""))
        with zipfile.ZipFile(io.BytesIO(request(prefix + "/download"))) as archive:
            if archive.testzip() is not None:
                raise RuntimeError("corrupt archive")
            if len(archive.namelist()) != len(artifacts):
                raise RuntimeError("archive membership does not match the report allowlist")
        result.update({"latest_run": run_id, "status": detail["status"],
                       "finding_count": detail["finding_count"], "deferred_count": len(detail["deferred"]),
                       "artifact_count": len(artifacts), "download": "passed", "path_isolation": "passed"})
    request("/logout", {})
    request("/runs", expected=401)
    result["logout"] = "passed"
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
