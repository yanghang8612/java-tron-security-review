# Reviewed dependency exception

## `extract-zip` / GHSA-jmr9-qjv8-65gv

`npm audit` currently reports High-severity
[GHSA-jmr9-qjv8-65gv](https://github.com/advisories/GHSA-jmr9-qjv8-65gv) against
`extract-zip@2.0.1`. The current latest `@openai/codex-security@0.1.16` directly pins that version,
and npm publishes no fixed `extract-zip` release.

This is a temporary, explicit exception rather than a claim that the dependency is generally safe.
The exposure is constrained in this system:

- Codex Security uses `extract-zip` only when an operator supplies a ZIP with `--plugin-path`.
- `jtsr` exposes no plugin-path option and its generated commands never add `--plugin-path`.
- The installed CLI and its complete dependency tree are integrity-locked; lifecycle scripts are
  disabled during installation.
- The scanner runs unprivileged in an ephemeral container. Target and knowledge-base source are
  cloned as root, made non-writable, and then read by the scanner user.
- The upstream call site performs its own central-directory checks and rejects symbolic-link,
  duplicate, backslash-qualified, oversized and unsafe archive paths before accepting a plugin.

Residual risk remains if a future code path begins extracting an attacker-controlled ZIP or the
upstream validation proves incomplete. Do not add `--plugin-path`, plugin upload, or untrusted ZIP
support while this exception exists.

`scripts/check_npm_audit.py` accepts only this exact advisory/package set and fails for every new or
changed production advisory. Re-evaluate and remove the exception whenever Codex Security or
`extract-zip` is updated. Image scanning in an operator-selected registry is an additional signal,
not a replacement for this review.
