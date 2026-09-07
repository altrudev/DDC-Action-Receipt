# DDCAR 0.1.1 — bounded verifier maintenance

This is a compatible reference-implementation maintenance release. The v0.1 wire format and signing domains are unchanged.

The lineage verifier now memoizes successful parent verification, bounds recursive work to 256 nodes/attempts, limits supplied parents to 64 and their aggregate canonical bytes to 16 MiB, and caps diagnostic count and length. Invalid shared-parent DAGs fail closed rather than consuming unbounded resources. The adversarial tests include valid and invalid shared-ancestor DAGs and parent-count rejection.

The verifier remains experimental. It does not establish independent time, actual human consent, policy correctness, physical outcome, or independence of two signers merely because their keys differ. Production deployments require an externally governed trust profile, key lifecycle/revocation policy, independently controlled execution boundary, destination-specific verification, and durable reconciliation. No production payment authorization is conferred by this release.

Validation: 46 tests passed on the controlled runner. DDC methodology review uses the standing-principles registry at 376e5d75d2a6cdef557eb8acccfd24cfba238ec8. No private DDC implementation is included.
