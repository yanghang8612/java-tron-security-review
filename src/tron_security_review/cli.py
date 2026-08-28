from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys

from . import __version__
from .config import available_knowledge_bases, load_config
from .gitops import (
    GitError,
    changed_files,
    ensure_worktree,
    merge_base,
    resolve_revision,
    target_metadata,
)
from .planner import VALID_RUN_MODES, build_plan
from .runner import default_run_id, read_scan_summary, run_plan


def _path(value: str) -> Path:
    return Path(value).expanduser()


def _common_target_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--target", type=_path, help="java-tron Git worktree root")
    parser.add_argument("--base", help="base revision for PR/nightly diff scans")
    parser.add_argument("--head", default="HEAD", help="head revision; default: HEAD")
    parser.add_argument("--scope", help="configured scope id override")
    parser.add_argument("--iso-week", type=int, help="override ISO week for rotation tests")


def _target(args: argparse.Namespace, default: Path) -> Path:
    return ensure_worktree((args.target or default).resolve())


def _plan_inputs(config, args):
    target = _target(args, config.system.default_target)
    files: tuple[str, ...] = ()
    base_commit: str | None = None
    head_commit = resolve_revision(target, args.head)
    if args.mode in {"pr", "nightly"}:
        if not args.base:
            raise ValueError(f"--base is required for {args.mode} scans")
        base_commit = merge_base(target, args.base, args.head)
        files = changed_files(target, args.base, args.head)
    plan = build_plan(
        config,
        args.mode,
        files=files,
        scope_id=args.scope,
        iso_week=args.iso_week,
    )
    return target, base_commit, head_commit, plan


def cmd_doctor(args: argparse.Namespace) -> int:
    config = load_config(args.root)
    checks: list[dict[str, object]] = []

    def record(name: str, ok: bool, detail: str) -> None:
        checks.append({"name": name, "ok": ok, "detail": detail})

    record("python", sys.version_info >= (3, 11), platform.python_version())
    node = shutil.which("node")
    if node:
        completed = subprocess.run(
            [node, "--version"], check=False, capture_output=True, text=True
        )
        version = completed.stdout.strip().lstrip("v")
        parts = tuple(int(part) for part in version.split(".")[:2])
        node_ok = parts >= (22, 13) if parts[0] == 22 else parts[0] in {24, 26}
        record("node", node_ok, version)
    else:
        record("node", False, "not found")
    record("npx", shutil.which("npx") is not None, shutil.which("npx") or "not found")
    try:
        target = _target(args, config.system.default_target)
        record("target", True, json.dumps(target_metadata(target), sort_keys=True))
    except (GitError, OSError) as error:
        record("target", False, str(error))
    try:
        bases = available_knowledge_bases(config)
        record("knowledge_bases", True, ", ".join(str(path) for path in bases))
    except FileNotFoundError as error:
        record("knowledge_bases", False, str(error))
    record("scan_prompt", config.system.scan_prompt.is_file(), str(config.system.scan_prompt))
    record(
        "validation_prompt",
        config.system.validation_prompt.is_file(),
        str(config.system.validation_prompt),
    )
    print(json.dumps({"ok": all(check["ok"] for check in checks), "checks": checks}, indent=2))
    return 0 if all(check["ok"] for check in checks) else 1


def cmd_plan(args: argparse.Namespace) -> int:
    config = load_config(args.root)
    target, base_commit, head_commit, plan = _plan_inputs(config, args)
    output = {
        "target": target_metadata(target),
        "base_commit": base_commit,
        "head_commit": head_commit,
        "plan": plan.as_dict(),
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    config = load_config(args.root)
    if args.provider == "amazon-bedrock" and not args.model:
        raise ValueError("--model is required with --provider amazon-bedrock")
    target, base_commit, head_commit, plan = _plan_inputs(config, args)
    metadata = target_metadata(target)
    if args.mode in {"pr", "nightly"} and metadata["dirty"]:
        raise ValueError(
            "Codex Security committed-diff scans require a clean target worktree; "
            "use a separate clean clone/worktree and do not discard local changes"
        )
    output_root = (args.output_root or config.system.output_root).resolve()
    run_id = args.run_id or default_run_id(args.mode)
    if plan.skipped_reason:
        print(json.dumps({"skipped": True, "reason": plan.skipped_reason, "plan": plan.as_dict()}, indent=2))
        return 0
    run_dir, results = run_plan(
        config=config,
        plan=plan,
        target=target,
        output_root=output_root,
        run_id=run_id,
        auth=args.auth or config.system.default_auth,
        cli_bin=args.cli_bin,
        base_commit=base_commit,
        head_commit=head_commit,
        dry_run=args.dry_run,
        extra_knowledge_bases=tuple(args.knowledge_base or ()),
        provider_override=args.provider,
        model_override=args.model,
    )
    summary = read_scan_summary(run_dir)
    print(json.dumps({"run_dir": str(run_dir), **summary}, indent=2))
    effective_results = [result for result in results if result.counts_toward_exit]
    codes = [result.returncode for result in effective_results]
    export_codes = [
        result.export_returncode
        for result in effective_results
        if result.export_returncode is not None
    ]
    if any(code not in {0, 2} for code in codes + export_codes):
        return 1
    if summary.get("partial_coverage") or any(
        code == 2 for code in codes + export_codes
    ):
        return 2
    return 0


def cmd_summary(args: argparse.Namespace) -> int:
    print(json.dumps(read_scan_summary(args.run_dir.resolve()), indent=2))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    from .reverify import failed_verification_inputs, verification_inputs
    from .verification import collect_candidates
    config = load_config(args.root)
    target = _target(args, config.system.default_target)
    source = args.source_run.absolute()
    plan, revision, manifest = verification_inputs(config, target, source)
    retry_selection = None
    if args.retry_failed_from:
        retry_selection, _ = failed_verification_inputs(plan, source, manifest, args.retry_failed_from.absolute())
    if args.plan_only:
        queues = []
        for job in plan.jobs:
            if job.profile.per_finding:
                source_job = next(j for j in plan.jobs if j.profile.name == job.profile.candidate_source_profile)
                intake = collect_candidates(source, source_job.id)
                if retry_selection is not None:
                    intake["candidates"] = [entry for entry in intake["candidates"] if entry["source_fingerprint"] in retry_selection[job.id]]
                queues.append({"job_id": job.id, "candidate_count": len(intake["candidates"]),
                               "selected_candidate_count": min(len(intake["candidates"]), job.profile.max_candidates),
                               "sources": [entry["source_kind"] for entry in intake["candidates"]],
                               "fingerprints": [entry["source_fingerprint"] for entry in intake["candidates"]],
                               "excluded": intake["excluded"], "errors": intake["errors"],
                               "profile": asdict(job.profile)})
        print(json.dumps({"execution_kind": "verification_only", "source_run_id": manifest["run_id"],
                          "target_revision": revision, "queues": queues}, indent=2, default=str))
        return 0 if all(not queue["errors"] for queue in queues) else 2
    run_dir, results = run_plan(
        config=config, plan=plan, target=target,
        output_root=(args.output_root or config.system.output_root).resolve(),
        run_id=args.run_id or default_run_id("verify"),
        auth=args.auth or config.system.default_auth, cli_bin=args.cli_bin,
        head_commit=revision, dry_run=args.dry_run, source_run_dir=source,
        retry_failed_from=args.retry_failed_from.absolute() if args.retry_failed_from else None,
    )
    summary = read_scan_summary(run_dir)
    print(json.dumps({"run_dir": str(run_dir), **summary}, indent=2))
    if any(result.returncode not in {0, 2} for result in results if result.counts_toward_exit):
        return 1
    return 2 if summary.get("partial_coverage") else 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .report_web import serve
    return serve(args)


def cmd_report_auth(args: argparse.Namespace) -> int:
    from .report_web import init_auth
    init_auth(args.auth_file, args.login_file, args.username)
    print("Report credentials created; password is only in the private login file.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jtsr",
        description="Orchestrate evidence-driven Codex Security reviews of java-tron.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "--root",
        type=_path,
        default=None,
        help="security-system repository root (normally auto-detected)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="check local prerequisites and configuration")
    doctor.add_argument("--target", type=_path)
    doctor.set_defaults(handler=cmd_doctor)

    plan = subparsers.add_parser("plan", help="classify a target and print the scan plan")
    plan.add_argument("--mode", choices=sorted(VALID_RUN_MODES), required=True)
    _common_target_arguments(plan)
    plan.set_defaults(handler=cmd_plan)

    scan = subparsers.add_parser("scan", help="run the selected Codex Security profiles")
    scan.add_argument("--mode", choices=sorted(VALID_RUN_MODES), required=True)
    _common_target_arguments(scan)
    scan.add_argument("--output-root", type=_path)
    scan.add_argument("--run-id")
    scan.add_argument("--auth", choices=["auto", "chatgpt", "api-key"])
    scan.add_argument(
        "--provider",
        choices=["openai", "openrouter", "fireworks", "amazon-bedrock"],
        help="override every selected profile provider",
    )
    scan.add_argument(
        "--model",
        help="override every selected profile model (required for a Bedrock override)",
    )
    scan.add_argument("--cli-bin", type=_path, help="preinstalled codex-security executable")
    scan.add_argument("--knowledge-base", type=_path, action="append")
    scan.add_argument("--dry-run", action="store_true")
    scan.set_defaults(handler=cmd_scan)

    verify = subparsers.add_parser("verify", help="recheck saved candidates without rerunning discovery")
    verify.add_argument("--source-run", required=True, type=_path)
    verify.add_argument("--retry-failed-from", type=_path, help="select only failed candidates from a completed supplemental review")
    verify.add_argument("--target", type=_path)
    verify.add_argument("--output-root", type=_path)
    verify.add_argument("--run-id")
    verify.add_argument("--auth", choices=["auto", "chatgpt", "api-key"])
    verify.add_argument("--cli-bin", type=_path)
    verify.add_argument("--plan-only", action="store_true", help="inspect candidate counts and limits without invoking a model")
    verify.add_argument("--dry-run", action="store_true")
    verify.set_defaults(handler=cmd_verify)

    summary = subparsers.add_parser("summary", help="summarize a completed run directory")
    summary.add_argument("run_dir", type=_path)
    summary.set_defaults(handler=cmd_summary)

    web = subparsers.add_parser("serve", help="serve a private, read-only report portal")
    web.add_argument("--reports", required=True, type=_path)
    web.add_argument("--auth-file", required=True, type=_path)
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8765)
    web.add_argument("--base-path", default="/security")
    web.add_argument("--secure-cookie", action="store_true", help="only when the gateway uses HTTPS")
    web.set_defaults(handler=cmd_serve)

    auth = subparsers.add_parser("report-init-auth", help="generate private report portal credentials")
    auth.add_argument("--auth-file", required=True, type=_path)
    auth.add_argument("--login-file", required=True, type=_path)
    auth.add_argument("--username", default="reviewer")
    auth.set_defaults(handler=cmd_report_auth)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (FileNotFoundError, GitError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
