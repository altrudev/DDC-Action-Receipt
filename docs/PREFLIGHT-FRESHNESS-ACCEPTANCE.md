# DDCAR preflight freshness correction

The verifier must distinguish historical validity from permission to execute now. An unexecuted ALLOW commitment may have been valid when issued while its observations are no longer fresh. In preflight mode, every evidence validity interval must cover the later of the decision timestamp and the current verification timestamp. Historical mode continues to assess the actual recorded decision/execution time.

This correction is wire-compatible with v0.1 and does not create an execution authority. A clock supplied by an untrusted caller is not an independent trusted timestamp. Production must additionally obtain fresh state from independently trusted sources, check revocation and prerequisites at the effect boundary, and record the exact action and outcome. No payment or device execution is authorized by this patch.

## DDC review

- Authority: no new grant or permission is created.
- State: stale evidence is rejected before a new execution.
- Time/frequency: the current verification clock is used for freshness, not inferred from observation frequency.
- Lineage: existing bounded verification is unchanged.
- Failure-path independence: no new claims of independent outcome evidence.
- Recovery: nonce and effect-state mechanisms are unchanged.
- Proprietary boundary: no private DDC logic included.

Run `python -m pytest -q`. The 46 existing tests and three new regression tests pass locally. This is a reference-code correction, not production acceptance or a live deployment.
