# Operations and rollout

## Rollout stages

1. **Dry run:** validate paths, revisions, knowledge bases and model configuration.
2. **Advisory:** run PR/nightly scans without blocking merges; measure precision, coverage,
   duration and cost.
3. **Verified alerting:** route confirmed findings to a private security workbench or advisory.
4. **Selective gate:** block only new High/Critical findings that have independent evidence,
   complete enough coverage and production reachability.

Do not make deep-scan completeness a synchronous PR requirement. Deep mode is intended for
scheduled path/repository review and cannot scan a diff.

## Cadence

- Daily TVM at 02:17 Asia/Shanghai: fixed `vm-execution` paths, even with no source changes.
- Nightly incremental mode, when invoked manually: changes from the prior comparison window.
- Weekly: one of seven critical/risk domains selected by ISO week.
- Pull requests: exact merge-base-to-head diff, same-repository branches only.
- Release: explicit full-repository deep scan against a pinned release candidate commit.

Committed-diff scans require a clean target checkout. CI naturally supplies one. Local operators
should use a separate clean clone/worktree rather than modifying an active development checkout.

## Exit codes and coverage

The wrapper preserves Codex Security exit semantics:

- `0`: all invoked jobs and exports completed.
- `2`: at least one scan completed only partially or reached a bounded limit.
- `1`: an operational/configuration error or an unexpected CLI/export failure.

High/Critical verifier work is isolated per triage candidate. A candidate that returns exit `2`
with the explicit Codex Security cyber-safety marker is retried once with the configured fallback
model. A successful fallback supersedes that one failed attempt. Timeouts, ordinary bounded
coverage, budget exhaustion, malformed output and other failures are not silently reclassified as
safety blocks. Candidates beyond the configured count remain partial coverage and keep exit `2`.

The default verifier bounds at most eight GPT-5.6 candidate attempts to 12 USD each, keeping the
96 USD primary worst case below the verifier stage ceiling of 110 USD. Codex Security does not
currently provide estimated-cost limiting for GPT-5.5. The fallback therefore omits `--max-cost`,
is limited to three candidates per run, and has a hard ten-minute process-group timeout per
candidate. Treat fallback usage as time-bounded but not cost-bounded.

Advisory workflows use `continue-on-error` so partial results can still be exported. Review
`coverage.json`; a partial or unknown coverage value is never a clean bill of health.

## Credential isolation

The wrapper creates a minimal child environment. It passes operating-system basics, proxy values,
Codex state, and credentials only for the selected supported model providers. GitHub, cloud and
deployment tokens are not inherited unless explicitly included for a supported provider.

CI installs `@openai/codex-security` outside the repository checkout with lifecycle scripts
disabled. The target checkout uses `persist-credentials: false` and the scan never receives a
checkout token.

## Handling a candidate finding

1. Keep all details private.
2. Confirm the exact target revision and dirty state.
3. Reproduce the trigger and inspect upstream callers/guards.
4. Identify the violated invariant and affected node roles/configuration.
5. Trace the introducing/fixing commits, release tags and activation gates.
6. Have an independent reviewer attempt to falsify the claim.
7. Follow java-tron's `SECURITY.md` disclosure route; do not open a public issue.

Model profiles and prompts are versioned evidence. Record their exact versions in the run
manifest when comparing scan quality over time.

## Single-server runbook

- Verify the next trigger with `systemctl list-timers java-tron-security-review.timer`.
- Start an acceptance run with `systemctl start java-tron-security-review.service` after every
  reviewed scanner update or credential rotation.
- Treat service exit `2` as an alert: it means partial/bounded coverage, not a clean result.
- Use `journalctl -u java-tron-security-review.service` for operational logs and inspect
  `last-run.json`, `run-manifest.json`, `coverage.json`, and `aggregate.json` together.
- Keep `/etc/java-tron-security-review/jtsr.env` root-only and reports outside any public web root.
- Check ChatGPT device authentication with
  `systemctl start java-tron-security-review-auth@status.service`; a missing stored login fails
  before the source checkout and should be treated as an operational alert.
- Keep `/var/lib/java-tron-security-review/auth` out of report archives and backups unless the
  backup is explicitly approved for account credentials and encrypted accordingly.
- Monitor disk use under `/var/lib/java-tron-security-review/scans`; the default retention is 90
  days and only the daily-run naming scheme is pruned.
- If a node shares the host, watch its latency and memory during the first scans and lower the
  container limits if necessary.

Detailed installation and rollback guidance is in [single-server deployment](server-deployment.md).
The [AWS-managed runbook](aws-deployment.md) applies only when that optional Terraform deployment is
explicitly selected.
