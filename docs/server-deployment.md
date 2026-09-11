# Single-server deployment: daily TVM review

This is the default deployment for an operator-managed Linux server, including an ordinary AWS
EC2 instance. AWS is only the host: the deployment does not require EventBridge, CodeBuild, ECR,
Terraform, S3, Secrets Manager, or a new inbound listener.

```text
systemd timer (daily at 18:17 UTC / 02:17 Asia/Shanghai)
        |
        v
root host wrapper, protected by flock
        |
        +--> shallow fetch of an exact java-tron revision into temporary storage
        +--> root-owned, read-only target mount
        |
        v
one non-root Docker container (dedicated uid 10001, no capabilities, bounded CPU/RAM,
the seccomp profile pinned to Codex Security 0.1.25, with its Codex runtime compatibility override
pinned to 0.153.4)
        |
        +--> daily-tvm Astra triage profile
        +--> daily-tvm Grok Build challenger profile
        +--> daily-tvm independent verifier profile
        |
        v
/var/lib/java-tron-security-review/scans (private local evidence)
```

The scanner is a batch job. It opens no port, does not join the node process, does not write into
the node's java-tron checkout, and does not modify findings automatically. It performs static,
source-based Codex Security analysis; transaction replay, fuzzing, and live-node validation remain
separate confirmation activities.

## Daily TVM scope

Every run selects exactly one of eight configured TVM execution facets as its depth axis, even
when the branch has not changed: entry/context, opcode dispatch, call/create, state rollback,
precompiles/native work, resource limits, activation/replay, or simulation parity. Astra first
inventories every production Java file below `actuator/.../core/vm` and
`common/.../core/vm`, then partitions that inventory into five sequential Standard scans: core
dispatch/configuration, Program runtime, Repository state, native contracts, and trace/utilities.
Each source is assigned exactly once while the selected facet's cross-module callers and sinks are
available to every shard. The day of year selects the facet deterministically; use
`jtsr plan --mode daily-tvm` to preview it or `--scope <facet-id>` to reproduce one explicitly.

After the scans, `coverage-manifest.json` compares the inventory with semantic file references in
sealed coverage, architecture, finding and report artifacts. Merely passing a file through
`--path` is not counted as evidence. Missing, duplicate, failed or unassigned work forces partial
coverage and is shown by shard in the report portal.

The mandatory evidence gate rejects proposal-disabled, pre-hard-fork, historical-replay and
test-only branches from findings and candidate-shaped deferred work unless a plausibly current
production path is independently established.

The server runs two independent discovery lanes: `gpt-6-astra` at `max` and Grok Build through
the signed-in Grok subscription. Their candidate sets are unioned and deduplicated; agreement is
recorded only as provenance and never treated as proof. Every selected candidate then gets its own
`gpt-6-astra` at `xhigh` skeptical-verifier invocation. Grok receives only the selected facet and
is constrained to read/grep tools, `dontAsk` fail-closed permissions, a read-only source mount,
and a root-owned policy that disables bypass-permissions mode. The default Grok sandbox is
`strict` on a Landlock-capable kernel.
Only explicitly recognized usage/rate limits or model-availability errors are retried with
`gpt-5.5` at `high`. Safety refusals and local budget/time limits never trigger model fallback.
At most eight candidates are selected in severity order. Each of the five Astra discovery shards
has a two-hour process-group limit; each Astra primary candidate has a shared 60-minute window
including its same-model retry.
The currently pinned Codex Security CLI, including its latest checked release 0.1.25, has no Astra
cost model and rejects `--max-cost` before the first model request. The configured 200/30/240 USD
values are therefore retained only as operator budget references and are explicitly recorded as
unenforced; wall-clock, progress and candidate-count limits are the active controls. GPT-5.5
fallbacks are limited to three candidates and thirty minutes each. These limits do not describe
the ChatGPT subscription bill or guarantee complete coverage.

## Host prerequisites

- A systemd-based Linux host with Docker Engine running.
- `git` and `flock` (normally supplied by the `util-linux` package).
- Outbound HTTPS to GitHub, OpenAI, `cli-chat-proxy.grok.com`, and `auth.x.ai`.
- Enough capacity for the default container limits: 4 CPUs, 8 GiB RAM, and 512 processes.
- An authorized, private location for scan reports.
- Unprivileged user namespaces for Codex Security's inner filesystem sandbox. On hosts exposing
  `/proc/sys/user/max_user_namespaces`, the value must be greater than zero.

Grok `strict` additionally requires Landlock (Linux 5.13 or newer). On a legacy kernel that cannot
be upgraded, set `JTSR_GROK_SANDBOX_PROFILE=devbox` in the root-only `jtsr.env` only after accepting
the reduced defense in depth. The wrapper still runs the whole scanner in a non-root container with
a read-only root filesystem and source mount, all capabilities dropped, `no-new-privileges`, the
pinned seccomp policy, resource limits, and only Grok `Read`/`Grep` tools. `off` is deliberately not
accepted. Return the setting to `strict` after moving to a Landlock-capable host.

If this runs on the same EC2 instance as a node, measure spare CPU, memory, disk, and outbound
bandwidth before enabling the timer. Reduce `JTSR_CPU_LIMIT` and `JTSR_MEMORY_LIMIT` when necessary;
the scan may take longer. The runtime does not use the node's HTTP, JSON-RPC, gRPC, P2P, Nginx, or
pprof ports.

## Install manually

Copy or clone this repository onto the server, review the current commit, then run:

```bash
cd /opt/java-tron-security-review
sudo deploy/server/install.sh
sudoedit /etc/java-tron-security-review/jtsr.env
```

The installer deploys the syscall allowlist shipped by the pinned Codex Security release while
retaining the non-root uid, `--cap-drop ALL`, `no-new-privileges`, a read-only container root, and a
read-only target mount. If the installer reports `user.max_user_namespaces=0`, the kernel is
blocking the inner sandbox. After reviewing the host-wide security implication, opt in to a finite
limit and reinstall:

```bash
sudo deploy/server/install.sh --enable-userns
cat /proc/sys/user/max_user_namespaces
```

This installs `/etc/sysctl.d/90-java-tron-security-review-userns.conf` with a limit of 1024 and
applies it immediately. The setting is global to the host, so do not enable it implicitly on a
shared machine. The daily wrapper checks it before cloning or starting a paid scan.

The new-install default is `JTSR_AUTH=chatgpt`. Keep `OPENAI_API_KEY` empty and keep `JTSR_MODEL`
empty to retain the configured profile routing. The installer deliberately does not enable the timer on
its first run, so an unauthenticated account cannot start an unattended scan.

Start ChatGPT device authentication and follow its journal from the EC2 terminal:

```bash
sudo systemctl start --no-block java-tron-security-review-auth@login.service
sudo journalctl -fu java-tron-security-review-auth@login.service
```

Open the displayed URL on a trusted browser, enter the short-lived device code, and complete the
ChatGPT sign-in. Stop following the journal with `Ctrl-C` after the login service completes. Then
check the stored sign-in:

```bash
sudo systemctl start java-tron-security-review-auth@status.service
sudo journalctl -u java-tron-security-review-auth@status.service -n 30 --no-pager
```

Then authenticate Grok Build separately. This uses the Grok subscription pool, not xAI API
billing:

```bash
sudo systemctl start --no-block java-tron-security-review-grok-auth@login.service
sudo journalctl -fu java-tron-security-review-grok-auth@login.service
```

Open the displayed xAI URL, enter the device code, and then verify that the account exposes models:

```bash
sudo systemctl start java-tron-security-review-grok-auth@status.service
sudo journalctl -u java-tron-security-review-grok-auth@status.service -n 30 --no-pager
```

Run one acceptance scan and inspect it before enabling the schedule:

```bash
sudo systemctl start java-tron-security-review.service
sudo systemctl status java-tron-security-review.service
sudo journalctl -u java-tron-security-review.service --since today
sudo ls -la /var/lib/java-tron-security-review/scans
sudo systemctl enable --now java-tron-security-review.timer
systemctl list-timers java-tron-security-review.timer
```

Exit `0` means both passes completed, exit `2` means partial/bounded coverage, and other non-zero
status means an operational failure. A partial run is intentionally a failed systemd service so it
cannot be mistaken for a clean result. Available evidence remains in the run directory.

The timer expects the host timezone to be UTC and uses `18:17` host time, equivalent to `02:17
Asia/Shanghai` on the following calendar day. Omitting a timezone suffix keeps the unit compatible
with systemd 219. It adds up to ten minutes of randomized delay. `Persistent=true` starts a missed
run after the host returns. To use another time or a non-UTC host, edit the timer, run `systemctl
daemon-reload`, and restart the timer.
`deploy/server/cron.example` is a fallback for operators who prefer cron.

## Results, retention, and logs

The host wrapper writes results beneath:

```text
/var/lib/java-tron-security-review/scans/
├── last-run.json
├── latest -> <most-recent-run>
├── latest-successful -> <most-recent-complete-run>
└── <UTC timestamp>-daily-tvm-<12-char revision>/
    ├── target-revision.txt
    ├── run-manifest.json
    ├── aggregate.json
    ├── triage-<tvm-facet>/
    ├── triage-grok-<tvm-facet>/
    └── verifier-<tvm-facet>/
        ├── verification-manifest.json
        └── candidates/<candidate>/<model-attempt>/
```

Directories matching the daily-run naming scheme are deleted after 90 days by default. The prune
selector does not match `.state`, status files, symlinks, or arbitrary directories. Change
`JTSR_RETENTION_DAYS` only after accounting for disk capacity and evidence policy.

Operational logs go to journald. Detailed findings stay under the private output directory and may
contain source excerpts, secret-like data, and unpatched vulnerability details. Do not place this
directory under an Nginx document root, sync it to a public bucket, or attach it to a public issue.

Set `JTSR_FAILURE_WEBHOOK_URL` to enable an optional failure webhook. Its payload contains only the
unit, host, timestamp, and failure event; findings are never included.

## Authentication

### ChatGPT device sign-in (default)

Set `JTSR_PROVIDER=openai` and `JTSR_AUTH=chatgpt`. The device flow stores refresh credentials under
`/var/lib/java-tron-security-review/auth`, mounted as `CODEX_HOME=/scan/auth`. That directory is
separate from the temporary source and `/var/lib/java-tron-security-review/scans`, so report
retention and report backups never select it. The daily service runs `login status` before cloning
java-tron and fails early if no stored sign-in is available. Authentication rejected by OpenAI is
reported by the scan itself.

The auth directory is mode `0700` and owned by the non-login `jtsr-scanner` account. It contains
account credentials, not merely cache: use encrypted host storage, do not copy it into report
archives, and trust host root and Docker-daemon administrators accordingly. To revoke the local
sign-in:

The private Codex Security workbench state also remains under this auth directory so login,
status checks, and scheduled scans all use the same managed Codex home.

```bash
sudo systemctl disable --now java-tron-security-review.timer
sudo systemctl start java-tron-security-review-auth@logout.service
```

### Grok Build subscription device sign-in

The independent challenger stores refresh credentials under
`/var/lib/java-tron-security-review/grok-auth`, mounted as
`GROK_HOME=/scan/grok-auth`. It is not an xAI API key and is never supplied to Codex Security.
The daily wrapper runs `grok models` before cloning or scanning and fails early if the sign-in is
missing or expired. The directory is mode `0700`, belongs to the non-login scanner UID, and must be
excluded from report archives and ordinary backups. Revoke it with:

```bash
sudo systemctl disable --now java-tron-security-review.timer
sudo systemctl start java-tron-security-review-grok-auth@logout.service
```

Codex Security access still depends on the signed-in account. `20x` is not a CLI setting, and the
official documentation does not guarantee that a particular ChatGPT Pro multiplier applies to
Codex Security scans. OpenAI recommends API keys for CI and other automated workflows; this device
mode is an explicit operator choice for the manually managed server.

### OpenAI API key (optional fallback)

Set `JTSR_AUTH=api-key` and supply `OPENAI_API_KEY` or `CODEX_API_KEY` in the root-only systemd
environment file. The wrapper passes the selected key only to the one-shot container and does not
mount the ChatGPT auth directory. The key is not baked into the image or written to the scan
manifest.

The installer reserves host uid/gid `10001` for the non-login `jtsr-scanner` account. It refuses to
continue if either numeric identity already belongs to another account, preventing scan reports
and ChatGPT credentials from becoming readable by an unrelated host user.

### Amazon Bedrock (optional)

Set `JTSR_PROVIDER=amazon-bedrock`, `AWS_REGION`, and an explicit `JTSR_MODEL`. Prefer a narrowly
scoped EC2 instance role. Container access to EC2 instance-role credentials depends on the host's
Docker networking and instance-metadata configuration, so verify it with a manual scan before
enabling the timer. Static AWS access keys are supported by the wrapper but are not recommended.

Because one provider/model override applies to both passes, Bedrock override mode uses two prompts
against one selected model rather than the default two-model pair.

## Upgrade and rollback

Pull or copy a reviewed security-review revision and reinstall it:

```bash
cd /opt/java-tron-security-review
git pull --ff-only
sudo deploy/server/install.sh
sudo systemctl start java-tron-security-review.service
```

The installer preserves the existing `/etc/java-tron-security-review/jtsr.env`. For rollback,
check out the previously reviewed repository commit, rerun the installer, and run an acceptance
scan. Do not enable automatic pulls of the scanner control plane; upgrades should be reviewed and
manual.

The `--enable-userns` setting is persistent and is not removed by a code rollback. To remove it,
first stop the scanner and keep the timer disabled, then delete the dedicated sysctl file and apply
the operator-approved replacement value for `user.max_user_namespaces`.

An installation upgraded from an API-key-only revision also preserves its old environment file.
To migrate it, add `JTSR_AUTH=chatgpt` and
`JTSR_AUTH_ROOT=/var/lib/java-tron-security-review/auth`, clear the API-key values, rerun the
installer, and complete the device login before enabling the timer.
