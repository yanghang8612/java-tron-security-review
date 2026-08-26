# java-tron security review policy and threat model

This document is mandatory context for automated scans. It describes review priorities, not proof
that a particular deployment is vulnerable.

## 1. Mandatory release and runtime reachability gate

Before assigning production impact or severity, trace every implicated change through Git history,
release tags and runtime activation. A commit being authored, merged, or present on a development
branch does not prove that users were affected.

For each finding, determine where evidence permits:

- the introducing commit and relevant later reverts, replacements or cherry-picks;
- the first affected and last affected release;
- the fixing commit and first fixed release;
- whether the behavior was enabled by configuration, proposal, hardfork height or network state;
- affected networks, node roles and deployment assumptions; and
- one of `production-reachable`, `not production-reachable`, or `reachability unverified`.

If code never shipped or never became active, it is not an effective production vulnerability.
When release or activation evidence is incomplete, do not assume production impact.

## 2. System and assets

java-tron is a Java implementation of a TRON full node, Solidity node, PBFT node and witness/block
producer. It validates untrusted P2P blocks and transactions, executes adversarial TVM bytecode,
maintains LevelDB or RocksDB chain state, and exposes HTTP, gRPC and Ethereum-compatible JSON-RPC.
Deployments may also hold witness signing keys, enable shielded APIs, load local event plugins,
publish events, expose metrics, and run database or keystore tooling.

Highest-value invariants include:

- honest nodes applying the same activated rules compute identical state and receipts;
- only valid signatures and permission thresholds authorize protected state transitions;
- balances, tokens, stake, votes, rewards, market state and shielded state are conserved;
- failed, reverted, timed-out or rejected execution leaves no partial state, logs or successful
  internal-transaction status;
- adversarial peers, API clients and contracts cannot obtain unbounded CPU, memory, disk,
  cryptographic work or response amplification at low cost;
- witness keys, keystore passwords and shielded material remain confidential; and
- simulation and estimation remain consistent enough with activated execution to avoid unsafe
  signing decisions.

## 3. Attacker-controlled inputs

Assume attackers control P2P messages, blocks, transactions, protobuf encodings, signatures,
contract bytecode and calldata, HTTP/gRPC/JSON-RPC request data, block ranges, filters, log topics,
precompile inputs, malformed JSON/hex/address values, concurrency and request timing. A malicious
contract can execute arbitrary TVM bytecode within whatever limits the implementation actually
enforces.

Configuration files, CLI arguments, plugin paths, database paths and key sources are normally
operator-controlled. Findings requiring their modification are not remote protocol vulnerabilities
unless a remote path to that control is demonstrated. Tests, fixtures, build logic and generated
code are developer-controlled, but remain security-relevant when they can compromise release
artifacts or disable effective gates.

## 4. Trust boundaries and review targets

### Consensus, transactions and native state transitions

Review block and transaction validation, TAPOS, duplicate suppression, protobuf canonicalization,
permission weights, operation masks, signature caching, fee/resource accounting, actuator
validation/execution parity, overflow, underflow, reorg replay and proposal activation.

Any behavior change that affects historical execution results must be bit-identical or correctly
fork-gated. Never assume upstream EVM semantics match TRON-specific behavior.

### TVM and precompiles

Review deterministic arithmetic and collection order, stack/jump validation, memory growth, call
depth, exceptional paths, Energy charge-before-work, refund behavior, static context, caller/value
semantics, native processors, precompile length/curve checks, JNI boundaries and fork-gated opcode
registration.

### State isolation, rollback and storage

Review child repository commit/discard, nested calls, REVERT, exceptions, timeouts, deletion/log
merging, receipts, transaction sessions, snapshots, checkpoints, block commit failure and fork
switching. Failed paths must be atomic and deterministic.

### Public APIs and P2P

Public APIs are commonly unauthenticated. Review payload and response bounds, batch amplification,
expensive simulation, filters, aliases, disabled API bypasses, gRPC streams, error conversion,
rate-limit composition, requested-data checks, queue bounds, peer lifecycle and parsing failures.

Classic session, CSRF, XSS and SQL-injection findings are usually low relevance because this is not
a conventional session-backed SQL web application. They become relevant only when browser
authority, secret-bearing operations or a real SQL/HTML sink is demonstrated.

### Keys, cryptography and shielded paths

Review signature encoding/recovery, curve and point validation, constant-time comparisons where
secrets are involved, proof parameter selection, nullifiers, proof/resource bounds, keystore KDF
and MAC validation, file permissions and server-held signing behavior.

### Supply chain, plugins and tools

Event plugins are trusted local code unless an attacker can influence their path or contents.
Administrative database and keystore tools are normally local surfaces, but path traversal,
symlink, overwrite, unsafe snapshot handling and privilege boundaries still matter.

Review workflow permissions, unpinned actions, dependency verification, build-time downloads,
mutable branches/tags, container bases, generated SBOMs and whether released artifacts correspond
to reviewed source.

## 5. Severity calibration

Severity applies only after reachability is established.

- **Critical:** production-reachable consensus split; invalid block/transaction acceptance;
  authorization bypass; unauthorized asset movement or minting; shielded double-spend; persistent
  mutation after failed execution; remote code execution; witness-key extraction; or deterministic
  active-mainnet TVM/precompile divergence.
- **High:** practical unauthenticated remote crash or sustained exhaustion; P2P sync/propagation
  failure; severe amplification; sensitive API bypass; practical keystore compromise; or simulation
  divergence likely to cause user loss.
- **Medium:** harmful behavior requiring non-default exposure, high attacker cost, unusual operator
  settings or local/tool privileges; bounded information disclosure; or significant but contained
  service degradation.
- **Low:** build/test-only issues without artifact impact, bounded malformed-input errors, local
  misuse, non-authoritative web findings, or behavior that was not production-reachable.

## 6. Required finding record

Every reportable finding must include:

- affected component and symbol, attacker-controlled entry point and trigger;
- root cause, source-to-impact path and violated invariant;
- existing guard or limit analysis;
- concrete impact and attacker cost/prerequisites;
- focused reproducer/test, or why dynamic proof was unavailable;
- introducing/fixing history and relevant tags;
- network, node role, configuration and activation status;
- source-level severity and deployment-adjusted severity;
- confidence and coverage limitations; and
- production reachability status.

High and Critical candidates remain unconfirmed until independently reviewed by a human. Automated
systems must not publish vulnerability details to public issues or pull-request comments.
