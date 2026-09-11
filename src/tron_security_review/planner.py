from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import date
import fnmatch
import json
from pathlib import Path

from .config import AppConfig, Profile, RISK_ORDER, Scope
from .vm_campaign import cross_module_context, shard_vm_sources


VALID_RUN_MODES = {
    "pr",
    "daily-tvm",
    "nightly",
    "weekly",
    "release",
    "manual",
}


@dataclass(frozen=True)
class ScopeMatch:
    scope: Scope
    files: tuple[str, ...]


@dataclass(frozen=True)
class PlanJob:
    id: str
    profile: Profile
    scope: Scope | None
    paths: tuple[str, ...]
    campaign_shard: str | None = None
    coverage_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScanPlan:
    run_mode: str
    highest_risk: str
    changed_files: tuple[str, ...]
    scope_matches: tuple[ScopeMatch, ...]
    jobs: tuple[PlanJob, ...]
    skipped_reason: str | None = None

    def as_dict(self) -> dict:
        return json.loads(json.dumps(asdict(self), default=str))


def _matches(path: str, pattern: str) -> bool:
    normalized = path.replace("\\", "/")
    return fnmatch.fnmatchcase(normalized, pattern)


def classify_files(config: AppConfig, files: tuple[str, ...]) -> tuple[ScopeMatch, ...]:
    matches: list[ScopeMatch] = []
    for scope in config.scopes:
        selected = tuple(
            path
            for path in files
            if any(_matches(path, pattern) for pattern in scope.patterns)
        )
        if selected:
            matches.append(ScopeMatch(scope=scope, files=selected))
    return tuple(matches)


def highest_risk(files: tuple[str, ...], matches: tuple[ScopeMatch, ...]) -> str:
    if matches:
        return max(
            (match.scope.risk for match in matches), key=lambda risk: RISK_ORDER[risk]
        )
    if any(path.endswith((".java", ".proto", ".gradle")) for path in files):
        return "medium"
    return "low"


def _eligible_profiles(
    config: AppConfig,
    mode: str,
    risk: str,
    enabled_profiles: tuple[str, ...] = (),
) -> tuple[Profile, ...]:
    enabled = set(enabled_profiles)
    return tuple(
        profile
        for profile in config.profiles
        if mode in profile.modes
        and RISK_ORDER[risk] >= RISK_ORDER[profile.minimum_risk]
        and (not profile.optional or profile.name in enabled)
    )


def _rotation_scope(config: AppConfig, scope_id: str | None, week: int) -> Scope:
    rotating = [scope for scope in config.scopes if scope.rotation]
    if not rotating:
        raise ValueError("no rotating scopes are configured")
    if scope_id:
        for scope in rotating:
            if scope.id == scope_id:
                return scope
        choices = ", ".join(scope.id for scope in rotating)
        raise ValueError(f"unknown rotating scope {scope_id!r}; choose one of: {choices}")
    return rotating[(week - 1) % len(rotating)]


def _scope_by_id(config: AppConfig, scope_id: str) -> Scope:
    for scope in config.scopes:
        if scope.id == scope_id:
            return scope
    choices = ", ".join(scope.id for scope in config.scopes)
    raise ValueError(f"unknown scope {scope_id!r}; choose one of: {choices}")


def _daily_tvm_scope(
    config: AppConfig, scope_id: str | None, day_of_year: int | None
) -> Scope:
    choices = [scope for scope in config.scopes if scope.daily_tvm]
    if not choices:
        raise ValueError("no daily TVM scopes are configured")
    if scope_id:
        for scope in choices:
            if scope.id == scope_id:
                return scope
        allowed = ", ".join(scope.id for scope in choices)
        raise ValueError(
            f"unknown daily TVM scope {scope_id!r}; choose one of: {allowed}"
        )
    day = day_of_year or date.today().timetuple().tm_yday
    if day < 1 or day > 366:
        raise ValueError("day_of_year must be between 1 and 366")
    return choices[(day - 1) % len(choices)]


def build_plan(
    config: AppConfig,
    run_mode: str,
    files: tuple[str, ...] = (),
    scope_id: str | None = None,
    iso_week: int | None = None,
    day_of_year: int | None = None,
    enabled_profiles: tuple[str, ...] = (),
    target: Path | None = None,
) -> ScanPlan:
    if run_mode not in VALID_RUN_MODES:
        allowed = ", ".join(sorted(VALID_RUN_MODES))
        raise ValueError(f"run mode must be one of {allowed}; got {run_mode!r}")

    optional_names = {profile.name for profile in config.profiles if profile.optional}
    invalid_enabled = set(enabled_profiles) - optional_names
    if invalid_enabled:
        choices = ", ".join(sorted(optional_names)) or "none"
        invalid = ", ".join(sorted(invalid_enabled))
        raise ValueError(
            f"--enable-profile accepts optional profiles only; got {invalid}; "
            f"configured optional profiles: {choices}"
        )

    matches = classify_files(config, files)
    selected_scope: Scope | None = None
    if run_mode == "daily-tvm":
        selected_scope = _daily_tvm_scope(config, scope_id, day_of_year)
        risk = selected_scope.risk
    else:
        risk = highest_risk(files, matches)

    if run_mode in {"pr", "nightly"} and not files:
        return ScanPlan(
            run_mode=run_mode,
            highest_risk="low",
            changed_files=files,
            scope_matches=(),
            jobs=(),
            skipped_reason="no changed files",
        )

    profiles = _eligible_profiles(config, run_mode, risk, enabled_profiles)
    jobs: list[PlanJob] = []

    if run_mode == "daily-tvm":
        assert selected_scope is not None
        for profile in profiles:
            if profile.full_vm_campaign and target is not None:
                shards = shard_vm_sources(target)
                if not shards:
                    raise ValueError(
                        "daily TVM campaign found no Java sources under the configured VM roots"
                    )
                context = cross_module_context(selected_scope.paths, target)
                for shard, sources in shards.items():
                    jobs.append(
                        PlanJob(
                            id=f"{profile.name}-{selected_scope.id}-{shard}",
                            profile=profile,
                            scope=selected_scope,
                            paths=(*sources, *context),
                            campaign_shard=shard,
                            coverage_paths=sources,
                        )
                    )
            else:
                jobs.append(
                    PlanJob(
                        id=f"{profile.name}-{selected_scope.id}",
                        profile=profile,
                        scope=selected_scope,
                        paths=selected_scope.paths,
                    )
                )
    elif run_mode == "weekly":
        week = iso_week or date.today().isocalendar().week
        selected_scope = _rotation_scope(config, scope_id, week)
        for profile in profiles:
            jobs.append(
                PlanJob(
                    id=f"{profile.name}-{selected_scope.id}",
                    profile=profile,
                    scope=selected_scope,
                    paths=selected_scope.paths,
                )
            )
    else:
        for profile in profiles:
            jobs.append(
                PlanJob(
                    id=profile.name,
                    profile=profile,
                    scope=None,
                    paths=(),
                )
            )

    return ScanPlan(
        run_mode=run_mode,
        highest_risk=risk,
        changed_files=files,
        scope_matches=matches,
        jobs=tuple(jobs),
        skipped_reason=None if jobs else "no eligible scan profile",
    )


def existing_scope_paths(target: Path, job: PlanJob) -> tuple[str, ...]:
    return tuple(path for path in job.paths if (target / path).exists())
