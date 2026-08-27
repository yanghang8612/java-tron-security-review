# TVM execution review playbook

This is mandatory methodology for daily TVM scans. It is not evidence that a particular branch is
active or vulnerable.

## 1. Start with one execution slice

Use the orchestrator-selected facet and its supplied cross-module paths. Before proposing a bug,
write a compact flow map covering:

1. attacker-controlled entry point and execution variant;
2. context creation and proposal/fork snapshot selection;
3. calldata/bytecode decoding and control-flow transitions;
4. Energy/resource charge relative to attacker-scaled work;
5. parent/child repository and result ownership;
6. success, REVERT, exception, timeout and cleanup paths; and
7. externally visible receipt, status, logs, internal transactions and committed state.

Do not stop at the first suspicious callee. Follow both callers and downstream sinks in the scoped
paths. Use tests to falsify claims and to discover variants, but do not treat a test-only setup as a
production trigger.

## 2. Build a gate matrix before reporting legacy behavior

For every relevant gate, record:

| Evidence | Questions |
| --- | --- |
| `ProposalUtil.ProposalType` and validator | What proposal controls the behavior and is it one-way? |
| `ProposalService` | How and when is the approved value persisted? |
| `DynamicPropertiesStore` | What is the stored chain value and startup fallback? |
| `ConfigLoader` / `VMConfig` | Which snapshot does this execution read? |
| `ForkController` / block version | Is the decision height-, vote- or snapshot-dependent? |
| callers and tests | Is gate-zero used by current execution, historical replay, or only fixtures? |
| tags/history/release notes | Did the fix ship and activate before the claimed attack window? |

Examples requiring this treatment include `StorageUtils.getEnergyLimitHardFork()`,
`VMConfig.allowTvmOsaka()` and all other `allowTvm*`/proposal-controlled branches. Their false
branches may be consensus-critical historical behavior. The mere ability to invoke those branches
in a unit test is not an attack path.

If the repository and supplied knowledge do not establish the effective value for the target
network, reject the item as a formal finding and record the missing chain-parameter/activation
evidence in coverage. Never substitute a default value, a test fixture or branch existence for
live activation evidence.

## 3. Cross-module invariants

Prioritize these end-to-end invariants:

- every honest node selects identical activated semantics, opcode tables and Energy costs;
- constant-call and estimation isolation cannot mutate state or contaminate later execution;
- attacker-scaled allocation or cryptographic work is bounded and charged before work;
- nested failure cannot leak child state, logs, refunds, deletion markers or success status;
- caller/origin/address/value/static/depth context survives every call/create transition;
- timeout, out-of-Energy and exceptional halt produce deterministic rollback and receipts; and
- simulation differences cannot cause an unsafe signing decision unless a concrete consumer and
  consequence are demonstrated.

## 4. Finding admission

A formal finding needs all of the following:

- a current production-reachable entry point for a stated network and node role;
- an end-to-end source-to-impact trace across the relevant modules;
- analysis of active proposals, hard forks, guards, limits and rollback;
- a violated invariant with concrete attacker benefit or network consequence; and
- a focused test/reproducer or a precise explanation of the remaining proof gap.

Otherwise record it as a rejected hypothesis, negative result or deferred edge in coverage. A
small, auditable list of deeply supported findings is the objective.
