"""Bounded CLI supervision; log traffic alone is not model progress."""
from __future__ import annotations

from dataclasses import dataclass, field
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import time

from .artifacts import write_json


@dataclass
class ProgressTracker:
    counters: dict[str, float] = field(default_factory=dict)
    phases: set[str] = field(default_factory=set)
    pending: str = ""

    def feed(self, text: str) -> bool:
        self.pending += text
        lines = self.pending.split("\n")
        self.pending = lines.pop()[-65536:]
        changed = False
        for line in lines:
            # Only explicit increasing counters/phase transitions qualify. Startup,
            # preflight 0/N, reconnects and timestamp-only heartbeats do not.
            values = {}
            for name, pattern in (
                ("input", r"Tokens:\s*([\d,]+) input"),
                ("output", r"([\d,]+) output"),
                ("files", r"(?:Files:|\()\s*([\d,]+)/[\d,]+"),
                ("cost", r"Estimated cost:\s*\$([\d.]+)"),
            ):
                match = re.search(pattern, line)
                if match:
                    try:
                        values[name] = float(match[1].replace(",", ""))
                    except ValueError:
                        pass
            if line.startswith("codex-security: debug: cost.updated "):
                for key, name in (("input_tokens", "input"), ("output_tokens", "output"), ("estimated_usd", "cost")):
                    match = re.search(rf"\b{key}=([\d.]+)", line)
                    if match:
                        try:
                            values[name] = float(match[1])
                        except ValueError:
                            pass
            for name, value in values.items():
                if math.isfinite(value) and value > self.counters.get(name, 0):
                    self.counters[name] = value
                    changed = True
            match = re.search(r"Scan phase: ([a-z -]+?)(?:\s*\(|\.|$)", line)
            if match:
                phase = match[1].strip()
                if phase != "preflight" and phase not in self.phases:
                    self.phases.add(phase)
                    changed = True
        return changed


def execution_path(stdout_path: Path) -> Path:
    return stdout_path.with_suffix(".execution.json")


def _stop_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    # The parent can exit before a descendant which ignores SIGTERM. Always
    # clean up the original process group before allowing another attempt.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def run_command(command, environment, stdout_path, stderr_path, timeout_seconds=None,
                first_response_timeout_seconds=None, idle_timeout_seconds=None) -> int:
    limits = (timeout_seconds, first_response_timeout_seconds, idle_timeout_seconds)
    if any(value is not None and (not math.isfinite(value) or value <= 0) for value in limits):
        raise ValueError("execution timeouts must be finite and positive")
    tracker = ProgressTracker()
    started = time.monotonic()
    last_progress = None
    reason = None
    with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open("w", encoding="utf-8") as stderr:
        process = subprocess.Popen(command, env=environment, stdout=stdout, stderr=stderr,
                                   text=True, start_new_session=True)
        with stderr_path.open("r", encoding="utf-8", errors="replace") as reader:
            try:
                while process.poll() is None:
                    now = time.monotonic()
                    if tracker.feed(reader.read(256 * 1024)):
                        last_progress = now
                    if timeout_seconds and now - started >= timeout_seconds:
                        reason = "wall_timeout"
                    elif last_progress is None and first_response_timeout_seconds and now - started >= first_response_timeout_seconds:
                        reason = "first_response_timeout"
                    elif last_progress is not None and idle_timeout_seconds and now - last_progress >= idle_timeout_seconds:
                        reason = "no_progress_timeout"
                    if reason:
                        _stop_group(process)
                        stderr.write(f"\njava-tron-security-review: orchestrator timeout ({reason}) after {now - started:.3f} seconds\n")
                        stderr.flush()
                        break
                    remaining = [value for value in (
                        timeout_seconds - (now - started) if timeout_seconds else None,
                        first_response_timeout_seconds - (now - started) if last_progress is None and first_response_timeout_seconds else None,
                        idle_timeout_seconds - (now - last_progress) if last_progress is not None and idle_timeout_seconds else None,
                    ) if value is not None]
                    try:
                        process.wait(timeout=max(0.01, min([0.25, *remaining])))
                    except subprocess.TimeoutExpired:
                        pass
            except BaseException:
                _stop_group(process)
                raise
        code = 2 if reason else process.returncode
    write_json(execution_path(stdout_path), {
        "schema_version": 1, "returncode": code, "termination_reason": reason,
        "duration_seconds": round(time.monotonic() - started, 3),
        "last_progress_seconds": round(last_progress - started, 3) if last_progress is not None else None,
        "progress_counters": tracker.counters,
        "timeout_seconds": timeout_seconds,
        "first_response_timeout_seconds": first_response_timeout_seconds,
        "idle_timeout_seconds": idle_timeout_seconds,
    })
    return code
