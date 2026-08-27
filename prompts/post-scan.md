# Post-scan evidence gate

Re-evaluate every candidate before finalizing the report. Remove candidates that are speculative,
duplicate the same root cause, depend on operator or developer control without a release impact, or
are already blocked by a reachable guard.

Remove any candidate whose impact depends on a proposal, hard-fork or compatibility branch unless
the report establishes the effective gate value for the stated production network and execution
context. In particular, do not report a legacy false branch merely because tests can set the gate
to zero or historical replay must preserve it. If the fixing proposal/hard fork was active before
the affected behavior could be used on that network, classify it as a rejected false positive.

For remaining findings, explicitly record attacker prerequisites, violated invariant, concrete
impact, proof status, confidence, affected node roles/configuration, and one of:
`production-reachable`, `not production-reachable`, or `reachability unverified`.

Only `production-reachable` candidates may remain in the formal finding list. Move
`not production-reachable` and `reachability unverified` candidates to coverage/deferred notes with
the missing evidence and rejection reason.

Do not upgrade severity solely because the affected component is consensus-critical. Mark coverage
partial when important callers, activation gates, release history, tests, or runtime behavior could
not be checked.
