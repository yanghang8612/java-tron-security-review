from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
from typing import Iterable

from .artifacts import aggregate_run, write_json
from .config import AppConfig, available_knowledge_bases
from .planner import PlanJob, ScanPlan, existing_scope_paths


@dataclass(frozen=True)
class InvocationResult:
    job_id: str
    command: tuple[str, ...]
    scan_dir: str
    returncode: int
    export_returncode: int | None
    stdout_path: str
    stderr_path: str
    sarif_path: str | None


def default_run_id(mode: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{mode}"


def ensure_output_is_safe(target: Path, output_root: Path) -> None:
    target = target.resolve()
    output_root = output_root.resolve()
    if output_root == target or output_root.is_relative_to(target):
        raise ValueError(
            f"scan output must be outside the target worktree: {output_root}"
        )


def _safe_environment(
    state_dir: Path,
    providers: set[str],
    auth: str = "auto",
) -> dict[str, str]:
    exact = {
        "PATH",
        "HOME",
        "TMPDIR",
        "TMP",
        "TEMP",
        "SHELL",
        "LANG",
        "TERM",
        "CI",
        "NO_COLOR",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
    }
    if auth in {"auto", "chatgpt"}:
        exact.add("CODEX_HOME")
    provider_credentials = {
        "openai": {"OPENAI_API_KEY", "CODEX_API_KEY"},
        "openrouter": {"OPENROUTER_API_KEY"},
        "fireworks": {"FIREWORKS_API_KEY"},
        "amazon-bedrock": {
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_REGION",
            "AWS_DEFAULT_REGION",
            "AWS_PROFILE",
            "AWS_SHARED_CREDENTIALS_FILE",
            "AWS_CONFIG_FILE",
            "AWS_ROLE_ARN",
            "AWS_ROLE_SESSION_NAME",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            "AWS_CONTAINER_AUTHORIZATION_TOKEN",
            "AWS_BEARER_TOKEN_BEDROCK",
            "AWS_EC2_METADATA_DISABLED",
            "AWS_SDK_LOAD_CONFIG",
        },
    }
    for provider in providers:
        if provider == "openai" and auth == "chatgpt":
            continue
        exact.update(provider_credentials.get(provider, set()))
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in exact or key.startswith("LC_")
    }
    if "amazon-bedrock" not in providers:
        environment["AWS_EC2_METADATA_DISABLED"] = "true"
    # Codex Security gives its state directory precedence over CODEX_HOME.  In
    # ChatGPT mode, keep both login and scan jobs on the managed Codex home
    # mounted below CODEX_HOME so the scanner can see the stored credentials.
    uses_chatgpt_home = auth == "chatgpt" or (
        auth == "auto" and "CODEX_HOME" in environment
    )
    if not uses_chatgpt_home:
        environment["CODEX_SECURITY_STATE_DIR"] = str(state_dir.resolve())
    return environment


def _cli_prefix(config: AppConfig, cli_bin: Path | None) -> list[str]:
    if cli_bin:
        resolved = cli_bin.expanduser().resolve()
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise FileNotFoundError(f"Codex Security binary is not executable: {resolved}")
        return [str(resolved)]
    npx = shutil.which("npx")
    if not npx:
        raise FileNotFoundError("npx was not found on PATH")
    return [npx, "--yes", config.system.cli_package]


def _render_job_prompt(
    job: PlanJob,
    plan: ScanPlan,
    destination: Path,
) -> Path:
    base = job.profile.prompt.read_text(encoding="utf-8")
    matched = []
    for scope_match in plan.scope_matches:
        matched.append(
            f"- {scope_match.scope.id} ({scope_match.scope.risk}): "
            + ", ".join(scope_match.files)
        )
    changed = "\n".join(f"- {path}" for path in plan.changed_files) or "- full/path scan"
    route_context = "\n".join(matched) or "- no configured scope matched"
    scope_context = (
        f"{job.scope.id}: {job.scope.description}" if job.scope else "diff/full target"
    )
    rendered = (
        base.rstrip()
        + "\n\n## Orchestrator-provided run context\n\n"
        + f"Run mode: `{plan.run_mode}`\n\n"
        + f"Highest routed risk: `{plan.highest_risk}`\n\n"
        + f"Selected scope: {scope_context}\n\n"
        + "Matched risk routes:\n"
        + route_context
        + "\n\nChanged files:\n"
        + changed
        + "\n"
    )
    destination.write_text(rendered, encoding="utf-8")
    return destination


def _append_option(command: list[str], flag: str, value: object | None) -> None:
    if value is not None:
        command.extend([flag, str(value)])


def build_scan_command(
    config: AppConfig,
    job: PlanJob,
    plan: ScanPlan,
    target: Path,
    scan_dir: Path,
    prompt_path: Path,
    knowledge_bases: Iterable[Path],
    auth: str,
    cli_bin: Path | None,
    base_commit: str | None,
    head_commit: str | None,
    dry_run: bool,
    provider_override: str | None = None,
    model_override: str | None = None,
) -> list[str]:
    provider = provider_override or job.profile.provider
    model = model_override or job.profile.model
    command = _cli_prefix(config, cli_bin)
    command.extend(
        [
            "scan",
            str(target),
            "--output-dir",
            str(scan_dir),
            "--provider",
            provider,
            "--model",
            model,
            "--effort",
            job.profile.effort,
            "--mode",
            job.profile.scan_mode,
            "--scan-prompt-file",
            str(prompt_path),
            "--post-scan-prompt-file",
            str(config.system.post_scan_prompt),
            "--headless",
            "--json",
        ]
    )
    if provider != "amazon-bedrock" and not dry_run:
        command.extend(["--auth", auth])
    for knowledge_base in knowledge_bases:
        command.extend(["--knowledge-base", str(knowledge_base)])

    _append_option(command, "--max-cost", job.profile.max_cost)
    if job.paths:
        paths = existing_scope_paths(target, job)
        if not paths:
            raise ValueError(
                f"none of the configured paths exist for scoped job {job.id!r}"
            )
        for path in paths:
            command.extend(["--path", path])
    elif base_commit and head_commit:
        command.extend(["--diff", base_commit, "--head", head_commit])

    if job.profile.scan_mode == "deep":
        _append_option(command, "--workers", job.profile.workers)
        _append_option(command, "--subagents", job.profile.subagents)
        _append_option(command, "--stop-after-no-new", job.profile.stop_after_no_new)
        _append_option(command, "--max-discovery-runs", job.profile.max_discovery_runs)
        _append_option(command, "--max-time-hours", job.profile.max_time_hours)
    if scan_dir.exists():
        command.append("--archive-existing")
    if dry_run:
        command.append("--dry-run")
    return command


def _run_command(
    command: list[str],
    environment: dict[str, str],
    stdout_path: Path,
    stderr_path: Path,
) -> int:
    with stdout_path.open("w", encoding="utf-8") as stdout_handle, stderr_path.open(
        "w", encoding="utf-8"
    ) as stderr_handle:
        completed = subprocess.run(
            command,
            check=False,
            env=environment,
            stdout=stdout_handle,
            stderr=stderr_handle,
            text=True,
        )
    return completed.returncode


def run_plan(
    config: AppConfig,
    plan: ScanPlan,
    target: Path,
    output_root: Path,
    run_id: str,
    auth: str,
    cli_bin: Path | None = None,
    base_commit: str | None = None,
    head_commit: str | None = None,
    dry_run: bool = False,
    extra_knowledge_bases: tuple[Path, ...] = (),
    provider_override: str | None = None,
    model_override: str | None = None,
) -> tuple[Path, tuple[InvocationResult, ...]]:
    ensure_output_is_safe(target, output_root)
    run_dir = output_root.resolve() / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    state_dir = output_root.resolve() / ".state"
    state_dir.mkdir(parents=True, exist_ok=True)
    providers = (
        set()
        if dry_run
        else {provider_override or job.profile.provider for job in plan.jobs}
    )
    environment = _safe_environment(state_dir, providers, auth=auth)
    knowledge_bases = list(available_knowledge_bases(config))
    for path in extra_knowledge_bases:
        resolved = path.expanduser().resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"knowledge base does not exist: {resolved}")
        knowledge_bases.append(resolved)

    initial_manifest = {
        "schema_version": 1,
        "run_id": run_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target": str(target),
        "plan": plan.as_dict(),
        "dry_run": dry_run,
        "advisory": config.system.advisory,
        "provider_override": provider_override,
        "model_override": model_override,
        "knowledge_bases": [str(path) for path in knowledge_bases],
        "results": [],
    }
    write_json(run_dir / "run-manifest.json", initial_manifest)

    results: list[InvocationResult] = []
    prefix = _cli_prefix(config, cli_bin)
    for job in plan.jobs:
        job_dir = run_dir / job.id
        job_dir.mkdir(parents=True, exist_ok=True)
        scan_dir = job_dir / "results"
        prompt_path = _render_job_prompt(job, plan, job_dir / "scan-context.md")
        stdout_path = job_dir / "invocation.stdout.json"
        stderr_path = job_dir / "invocation.stderr.log"
        command = build_scan_command(
            config=config,
            job=job,
            plan=plan,
            target=target,
            scan_dir=scan_dir,
            prompt_path=prompt_path,
            knowledge_bases=knowledge_bases,
            auth=auth,
            cli_bin=cli_bin,
            base_commit=base_commit,
            head_commit=head_commit,
            dry_run=dry_run,
            provider_override=provider_override,
            model_override=model_override,
        )
        returncode = _run_command(command, environment, stdout_path, stderr_path)

        export_returncode: int | None = None
        sarif_path: Path | None = None
        if not dry_run and (scan_dir / "findings.json").exists():
            sarif_path = job_dir / "results.sarif"
            export_stdout = job_dir / "export.stdout.log"
            export_stderr = job_dir / "export.stderr.log"
            export_command = prefix + [
                "export",
                str(scan_dir),
                "--export-format",
                "sarif",
                "--source-root",
                str(target),
                "--output",
                str(sarif_path),
            ]
            export_returncode = _run_command(
                export_command, environment, export_stdout, export_stderr
            )
            if export_returncode != 0 or not sarif_path.exists():
                sarif_path = None

        results.append(
            InvocationResult(
                job_id=job.id,
                command=tuple(command),
                scan_dir=str(scan_dir),
                returncode=returncode,
                export_returncode=export_returncode,
                stdout_path=str(stdout_path),
                stderr_path=str(stderr_path),
                sarif_path=str(sarif_path) if sarif_path else None,
            )
        )

    aggregate = aggregate_run(run_dir)
    write_json(run_dir / "aggregate.json", aggregate)
    final_manifest = dict(initial_manifest)
    final_manifest["completed_at"] = datetime.now(timezone.utc).isoformat()
    final_manifest["results"] = [asdict(result) for result in results]
    write_json(run_dir / "run-manifest.json", final_manifest)
    return run_dir, tuple(results)


def command_for_display(command: Iterable[str]) -> str:
    return shlex.join(command)


def read_scan_summary(run_dir: Path) -> dict:
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    aggregate = json.loads((run_dir / "aggregate.json").read_text(encoding="utf-8"))
    return {
        "run_id": manifest["run_id"],
        "dry_run": manifest["dry_run"],
        "job_count": len(manifest.get("results", [])),
        "finding_group_count": aggregate.get("finding_group_count", 0),
        "results": manifest.get("results", []),
    }
