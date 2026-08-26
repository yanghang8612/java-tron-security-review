from __future__ import annotations

from pathlib import Path
import subprocess


class GitError(RuntimeError):
    pass


def _git(target: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(target), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise GitError(f"git {' '.join(args)} failed: {detail}")
    return completed.stdout.strip()


def ensure_worktree(target: Path) -> Path:
    target = target.expanduser().resolve()
    root = Path(_git(target, "rev-parse", "--show-toplevel")).resolve()
    if root != target:
        raise GitError(f"target must be the Git worktree root: {root}")
    return root


def resolve_revision(target: Path, revision: str) -> str:
    return _git(target, "rev-parse", "--verify", f"{revision}^{{commit}}")


def merge_base(target: Path, base: str, head: str) -> str:
    return _git(target, "merge-base", base, head)


def changed_files(target: Path, base: str, head: str) -> tuple[str, ...]:
    base_commit = merge_base(target, base, head)
    output = _git(target, "diff", "--name-only", "--diff-filter=ACMR", base_commit, head)
    return tuple(line for line in output.splitlines() if line)


def target_metadata(target: Path) -> dict[str, str | bool]:
    status = _git(target, "status", "--porcelain=v1")
    branch = _git(target, "branch", "--show-current")
    return {
        "root": str(target),
        "commit": resolve_revision(target, "HEAD"),
        "branch": branch,
        "dirty": bool(status),
    }
