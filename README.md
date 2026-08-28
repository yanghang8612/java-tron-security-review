# java-tron security review

An evidence-driven, scheduled security-review control plane for
[java-tron](https://github.com/tronprotocol/java-tron), built on the Codex Security CLI.

The system routes changed code by java-tron risk domain, runs cost-bounded model profiles,
supplies a project-specific threat model and optional knowledge base, exports sealed findings to
SARIF, and keeps scan state outside the target worktree. It is advisory and read-only by default.

## What is implemented

- PR diff planning with Sol/xhigh discovery and isolated, Sol/high per-finding falsification for
  High/Critical candidates.
- A GPT-5.5/high fallback only for explicitly recognized usage/rate limits or model availability
  failures. Safety refusals, local budget/time limits and unknown errors do not trigger fallback.
- One-facet-per-day TVM execution-flow reviews, nightly incremental scans and a seven-domain weekly
  deep-scan rotation.
- A hard production-reachability admission gate that rejects pre-activation, historical-replay and
  test-only proposal branches from the formal finding list.
- Release/manual full-repository scan modes.
- Mandatory release/runtime reachability policy for every finding.
- Environment filtering so the scanner does not inherit unrelated CI credentials.
- Private run manifests, logs, native CLI artifacts, SARIF exports and cross-profile grouping.
- A reusable PR workflow plus a scheduled/dispatch campaign workflow.
- A default single-server deployment for manually operated Linux/EC2 hosts: local Docker image,
  systemd timer, overlap protection, CPU/RAM limits, a pinned Codex Security seccomp profile,
  private reports, retention and failure webhook.
- An optional AWS-managed CodeBuild/EventBridge deployment for operators who explicitly want it.
- Dependency-free Python control plane with offline unit tests.
- A private, read-only HTTP report portal with login, coverage/deferred evidence, and Markdown,
  JSON, SARIF and ZIP downloads through an existing Nginx gateway.

Multi-model agreement is only corroboration. It never promotes a finding without code-path,
trigger, impact, proof and reachability evidence.

## Requirements

- Python 3.11 or later.
- Node.js 22.13+, 24 or 26.
- Codex Security access.
- ChatGPT sign-in for local scans, persisted device sign-in for the manual server deployment, or
  an OpenAI API key for CI.
- An authorized java-tron checkout.

The Codex Security CLI version is pinned in `config/system.toml`. CI installs the package outside
both the scanner and target repositories.

## Local setup

```bash
git clone <repository-url>
cd java-tron-security-review
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --no-deps -e .
jtsr doctor --target ../java-tron
```

Inspect a plan before spending model budget:

```bash
jtsr plan \
  --mode pr \
  --target ../java-tron \
  --base origin/develop \
  --head HEAD
```

Validate all local inputs without loading credentials or starting a model scan:

```bash
jtsr scan \
  --mode pr \
  --target ../java-tron \
  --base origin/develop \
  --head HEAD \
  --dry-run
```

Committed-diff scans require a clean target checkout. If your main java-tron worktree contains
unfinished changes, point `--target` at a separate clean clone or detached worktree; do not stash or
discard unrelated work merely to run a scheduled review.

Run a live local scan after signing in:

```bash
npx @openai/codex-security@0.1.20 login
jtsr scan \
  --mode pr \
  --target ../java-tron \
  --base origin/develop \
  --head HEAD \
  --auth chatgpt
```

Force a particular weekly deep-review scope:

```bash
jtsr scan --mode weekly --target ../java-tron --scope vm-execution
```

Preview the same date-selected TVM facet used by the single-server daily schedule:

```bash
jtsr scan --mode daily-tvm --target ../java-tron --dry-run
```

Force one facet when reproducing or comparing a result:

```bash
jtsr scan \
  --mode daily-tvm \
  --target ../java-tron \
  --scope tvm-state-rollback \
  --dry-run
```

## Results and privacy

Results default to `var/scans/<run-id>/`, outside the java-tron worktree:

```text
var/scans/<run-id>/
├── run-manifest.json
├── aggregate.json
├── triage/
│   ├── scan-context.md
│   ├── invocation.stderr.log
│   ├── invocation.stdout.json
│   ├── results.sarif
│   └── results/
│       ├── scan-manifest.json
│       ├── findings.json
│       ├── coverage.json
│       └── report.md
└── verifier/
    ├── verification-manifest.json
    └── candidates/
        └── 001-<fingerprint>/
            ├── candidate-context.md
            ├── gpt-5-6-sol/
            └── gpt-5-5/          # present only after an eligible availability fallback
```

These files may contain source excerpts, secrets and unpatched vulnerability details. `var/` is
Git-ignored. Do not publish it or attach it to public issues. The aggregate groups stable/native
finding IDs when available; it does not claim that model agreement proves exploitability.

## GitHub Actions

- `.github/workflows/security-campaign.yml` runs daily rotating TVM facet scans, weekly deep
  scans, and manual release/full scans from this control-plane repository.
- Set the optional repository variable `JTSR_KB_REPOSITORY` to an authorized
  `owner/repository` if a private knowledge base should be included. It is disabled by default.
- `.github/workflows/reusable-pr.yml` is called from java-tron and can upload SARIF into the target
  repository's private code-scanning view.
- `integrations/java-tron/security-pr.yml` is the caller template. Replace `YOUR_ORG`, publish this
  repository, and pin the reusable workflow to a reviewed commit SHA before enabling it.

Create the `CODEX_SECURITY_API_KEY` Actions secret. Keep the security-system repository private if
you want it to retain detailed scan artifacts. PR scans are restricted to same-repository branches;
fork PRs must not receive the API key.

The initial workflows are advisory. After measuring precision, coverage and runtime, gating can be
enabled for new, independently verified and production-reachable High/Critical findings.

## Single-server deployment

The default deployment targets one manually operated Linux server, including an ordinary AWS EC2
instance. A systemd timer starts one constrained Docker container each day, fetches an exact
java-tron revision into temporary storage, selects one TVM execution facet, and keeps reports locally.
It requires no AWS-managed build or scheduler services. The scanner opens no network port;
the optional report portal publishes a loopback-only backend behind your existing HTTP gateway.

OpenAI authentication can use a persisted ChatGPT device sign-in or a dedicated API key. ChatGPT
credentials are kept in a private directory separate from source checkouts and scan reports.

See [single-server deployment](docs/server-deployment.md) for installation, credentials, resource
limits, retention, acceptance testing and rollback.

See [HTTP report portal](docs/report-web.md) for browser access and report downloads. It has
separate credentials and mounts only scan reports read-only, never the scanner's model credentials.

The previous [AWS-managed deployment](docs/aws-deployment.md) remains an explicitly optional
alternative for operators who want CodeBuild/EventBridge/S3. It is not required by the default
system and no cloud resources are created by this repository.

## Configuration

- `config/system.toml`: CLI pin, target/output defaults and knowledge bases.
- `config/profiles.toml`: models, effort, modes, per-finding/fallback policy, cost and deep-scan
  limits.
- `config/scopes.toml`: java-tron path-to-risk routing, daily TVM facets and weekly rotation.
- `knowledge/threat-model.md`: mandatory security and reachability policy.
- `knowledge/tvm-review-playbook.md`: proposal-gate and cross-module TVM tracing method.
- `prompts/`: normal investigation, independent falsification and structured final validation gate.

Optional local knowledge comes from the sibling `java-tron-kb` repository when present. The KB is
orientation only; its draft claims must be rechecked against the target source.

## Development and verification

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile src/tron_security_review/*.py
python3 scripts/check_npm_audit.py
```

See [operations](docs/operations.md) for rollout and incident-handling guidance.
The current reviewed upstream npm exception is documented in
[dependency risk](docs/dependency-risk.md); CI fails on any unreviewed advisory.

The implementation tracks the official OpenAI documentation for the
[Codex Security CLI](https://learn.chatgpt.com/docs/security/cli),
[CLI reference](https://learn.chatgpt.com/docs/security/cli/reference), and
[CI integration](https://learn.chatgpt.com/docs/security/cli/ci).
