# Post-scan evidence gate

Re-evaluate every candidate before finalizing the report. Remove candidates that are speculative,
duplicate the same root cause, depend on operator or developer control without a release impact, or
are already blocked by a reachable guard.

For remaining findings, explicitly record attacker prerequisites, violated invariant, concrete
impact, proof status, confidence, affected node roles/configuration, and one of:
`production-reachable`, `not production-reachable`, or `reachability unverified`.

Do not upgrade severity solely because the affected component is consensus-critical. Mark coverage
partial when important callers, activation gates, release history, tests, or runtime behavior could
not be checked.
