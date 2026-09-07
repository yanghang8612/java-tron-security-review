# Reviewed dependency exception

## Codex Security 0.1.25 transitive advisories

`npm audit` currently reports three High-severity and one Moderate-severity production advisories
through the pinned `@openai/codex-security@0.1.25`. They affect `extract-zip@2.0.1`
([GHSA-jmr9-qjv8-65gv](https://github.com/advisories/GHSA-jmr9-qjv8-65gv)),
`fast-uri@3.1.5` (four host-confusion/SSRF advisories) and `fflate@0.8.2`
(malformed ZIP64 infinite loop). npm publishes no fixed version allowed by the current upstream
dependency graph.

This is a temporary, explicit exception rather than a claim that the dependency is generally safe.
The exposure is constrained in this system:

- Codex Security uses `extract-zip` only when an operator supplies a ZIP with `--plugin-path`.
- `jtsr` exposes no plugin-path option and its generated commands never add `--plugin-path`.
- The orchestrator supplies its own local schema/prompt paths and does not accept target-controlled
  schema or remote-reference URIs, constraining the `fast-uri` call surface.
- Scheduled TVM scopes contain source/config files rather than ZIP input. A malformed-input hang is
  also contained by the process-group wall-clock and progress watchdogs.
- The installed CLI and its complete dependency tree are integrity-locked; lifecycle scripts are
  disabled during installation.
- The scanner runs unprivileged in an ephemeral container. Target and knowledge-base source are
  cloned as root, made non-writable, and then read by the scanner user.
- The upstream call site performs its own central-directory checks and rejects symbolic-link,
  duplicate, backslash-qualified, oversized and unsafe archive paths before accepting a plugin.

Residual risk remains if a future code path begins resolving target-controlled URIs, extracting an
attacker-controlled ZIP, or the upstream validation proves incomplete. Do not add `--plugin-path`,
plugin upload, untrusted archive input, or remote-schema support while these exceptions exist.

`scripts/check_npm_audit.py` accepts only the exact package, advisory, severity and no-fix set and
fails for every new or changed production advisory. Re-evaluate and remove the exceptions whenever
Codex Security or any affected package is updated. Image scanning in an operator-selected registry
is an additional signal, not a replacement for this review.
