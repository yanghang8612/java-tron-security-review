from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tomllib


RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass(frozen=True)
class SystemConfig:
    name: str
    cli_package: str
    default_target: Path
    output_root: Path
    default_auth: str
    advisory: bool
    knowledge_bases: tuple[Path, ...]
    optional_knowledge_bases: tuple[Path, ...]
    scan_prompt: Path
    post_scan_prompt: Path


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    provider: str
    model: str
    effort: str
    scan_mode: str
    modes: tuple[str, ...]
    minimum_risk: str
    max_cost: float | None
    prompt: Path
    workers: int | None = None
    subagents: int | None = None
    stop_after_no_new: int | None = None
    max_discovery_runs: int | None = None
    max_time_hours: float | None = None
    per_finding: bool = False
    candidate_source_profile: str | None = None
    max_candidates: int | None = None
    per_finding_max_cost: float | None = None
    fallback_model: str | None = None
    fallback_effort: str | None = None
    max_fallbacks: int | None = None
    fallback_timeout_minutes: float | None = None


@dataclass(frozen=True)
class Scope:
    id: str
    description: str
    risk: str
    rotation: bool
    paths: tuple[str, ...]
    patterns: tuple[str, ...]


@dataclass(frozen=True)
class AppConfig:
    root: Path
    system: SystemConfig
    profiles: tuple[Profile, ...]
    scopes: tuple[Scope, ...]


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _read_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _resolve(root: Path, value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = root / path
    return path.resolve()


def _validate_risk(value: str, field: str) -> str:
    if value not in RISK_ORDER:
        allowed = ", ".join(RISK_ORDER)
        raise ValueError(f"{field} must be one of: {allowed}; got {value!r}")
    return value


def load_config(root: Path | None = None) -> AppConfig:
    root = (root or project_root()).resolve()
    raw_system = _read_toml(root / "config/system.toml")["system"]
    raw_profiles = _read_toml(root / "config/profiles.toml")["profiles"]
    raw_scopes = _read_toml(root / "config/scopes.toml")["scopes"]

    system = SystemConfig(
        name=raw_system["name"],
        cli_package=raw_system["cli_package"],
        default_target=_resolve(root, raw_system["default_target"]),
        output_root=_resolve(root, raw_system["output_root"]),
        default_auth=raw_system.get("default_auth", "auto"),
        advisory=bool(raw_system.get("advisory", True)),
        knowledge_bases=tuple(
            _resolve(root, value) for value in raw_system.get("knowledge_bases", [])
        ),
        optional_knowledge_bases=tuple(
            _resolve(root, value)
            for value in raw_system.get("optional_knowledge_bases", [])
        ),
        scan_prompt=_resolve(root, raw_system["scan_prompt"]),
        post_scan_prompt=_resolve(root, raw_system["post_scan_prompt"]),
    )

    profiles: list[Profile] = []
    for name, values in raw_profiles.items():
        scan_mode = values.get("scan_mode", "standard")
        if scan_mode not in {"standard", "deep"}:
            raise ValueError(f"profiles.{name}.scan_mode is invalid: {scan_mode!r}")
        profile = Profile(
            name=name,
            description=values.get("description", ""),
            provider=values["provider"],
            model=values["model"],
            effort=values["effort"],
            scan_mode=scan_mode,
            modes=tuple(values.get("modes", [])),
            minimum_risk=_validate_risk(
                values.get("minimum_risk", "low"),
                f"profiles.{name}.minimum_risk",
            ),
            max_cost=float(values["max_cost"]) if "max_cost" in values else None,
            prompt=_resolve(root, values.get("prompt", raw_system["scan_prompt"])),
            workers=values.get("workers"),
            subagents=values.get("subagents"),
            stop_after_no_new=values.get("stop_after_no_new"),
            max_discovery_runs=values.get("max_discovery_runs"),
            max_time_hours=(
                float(values["max_time_hours"])
                if "max_time_hours" in values
                else None
            ),
            per_finding=bool(values.get("per_finding", False)),
            candidate_source_profile=values.get("candidate_source_profile"),
            max_candidates=values.get("max_candidates"),
            per_finding_max_cost=(
                float(values["per_finding_max_cost"])
                if "per_finding_max_cost" in values
                else None
            ),
            fallback_model=values.get("fallback_model"),
            fallback_effort=values.get("fallback_effort"),
            max_fallbacks=values.get("max_fallbacks"),
            fallback_timeout_minutes=(
                float(values["fallback_timeout_minutes"])
                if "fallback_timeout_minutes" in values
                else None
            ),
        )
        if profile.per_finding:
            if not profile.candidate_source_profile:
                raise ValueError(
                    f"profiles.{name}.candidate_source_profile is required for per-finding review"
                )
            if not profile.max_candidates or profile.max_candidates < 1:
                raise ValueError(
                    f"profiles.{name}.max_candidates must be a positive integer"
                )
            if not profile.per_finding_max_cost or profile.per_finding_max_cost <= 0:
                raise ValueError(
                    f"profiles.{name}.per_finding_max_cost must be positive"
                )
            if bool(profile.fallback_model) != bool(profile.fallback_effort):
                raise ValueError(
                    f"profiles.{name}.fallback_model and fallback_effort must be configured together"
                )
            if profile.fallback_model == "gpt-5.5" and profile.fallback_effort not in {
                "none",
                "low",
                "medium",
                "high",
                "xhigh",
            }:
                raise ValueError(
                    f"profiles.{name}.fallback_effort is unsupported by gpt-5.5"
                )
            if profile.fallback_model and (
                not profile.max_fallbacks or profile.max_fallbacks < 1
            ):
                raise ValueError(
                    f"profiles.{name}.max_fallbacks must be positive when fallback is enabled"
                )
            if profile.fallback_model and (
                profile.fallback_timeout_minutes is None
                or profile.fallback_timeout_minutes <= 0
            ):
                raise ValueError(
                    f"profiles.{name}.fallback_timeout_minutes must be positive when fallback is enabled"
                )
            primary_worst_case = (
                profile.max_candidates * profile.per_finding_max_cost
            )
            if profile.max_cost is None or primary_worst_case > profile.max_cost:
                raise ValueError(
                    f"profiles.{name} per-finding primary cost {primary_worst_case:g} "
                    f"exceeds max_cost {profile.max_cost!r}"
                )
        profiles.append(profile)

    profile_names = {profile.name for profile in profiles}
    for profile in profiles:
        if (
            profile.per_finding
            and profile.candidate_source_profile not in profile_names
        ):
            raise ValueError(
                f"profiles.{profile.name}.candidate_source_profile "
                f"{profile.candidate_source_profile!r} does not exist"
            )

    scopes: list[Scope] = []
    seen_scope_ids: set[str] = set()
    for values in raw_scopes:
        scope_id = values["id"]
        if scope_id in seen_scope_ids:
            raise ValueError(f"duplicate scope id: {scope_id}")
        seen_scope_ids.add(scope_id)
        scopes.append(
            Scope(
                id=scope_id,
                description=values.get("description", ""),
                risk=_validate_risk(values["risk"], f"scopes.{scope_id}.risk"),
                rotation=bool(values.get("rotation", False)),
                paths=tuple(values.get("paths", [])),
                patterns=tuple(values.get("patterns", [])),
            )
        )

    return AppConfig(
        root=root,
        system=system,
        profiles=tuple(profiles),
        scopes=tuple(scopes),
    )


def available_knowledge_bases(config: AppConfig) -> tuple[Path, ...]:
    required = list(config.system.knowledge_bases)
    missing = [path for path in required if not path.exists()]
    if missing:
        joined = ", ".join(str(path) for path in missing)
        raise FileNotFoundError(f"required knowledge base is missing: {joined}")
    optional = [
        path for path in config.system.optional_knowledge_bases if path.exists()
    ]
    return tuple(required + optional)
