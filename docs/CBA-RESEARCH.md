# CBA/0.1 research and integration profile

Status: experimental shadow profile, not an authorization standard or production release. The DDCAR v0.1 wire format and existing enforcement are unchanged.

## Purpose
Cross-Boundary Assurance records material divergence between an independently established commitment and observations across identity, authority, representation, policy, state, execution, observation, and evidence. It does not replace signature verification, policy evaluation, durable replay reservation, sandboxing, or physical interlocks. A CONSISTENT report is not permission to execute.

## Contract
`analyze(commitment, events, policy=..., trusted_baseline=...)` returns a deterministic diagnostic report. The explicit policy requires nonempty critical fields and required boundaries; text fields and maximum inter-event age are optional. Every event contains boundary, nonnegative sequence, integer time, unique nonce, observed object, and a trusted boolean. The caller must establish the trust of observations independently; the boolean is an assertion, not proof. All values must be JSON-compatible; floats, oversized integers, excessive nesting, and oversized inputs are rejected. The profile uses its own deterministic JSON digest, not DDCAR-CJ1, and its hashes are not interchangeable with DDCAR protocol commitments. No wire-format change is proposed.

The baseline must come from the authoritative request or another independently verified source, never from an untrusted worker's echo. For a real DDCAR receipt, verify the original receipt and authority grant using the existing verifier and independently pinned keys before constructing the baseline. Preserve original bytes and signed digests. Do not normalize identifiers, commands, or paths before authorization. The Unicode checks are limited indicators, not a complete confusable or tokenizer analysis; RenderDiff may provide a separately verified representation report.

## Boundaries and limitations
A critical field mismatch, missing field, missing boundary, untrusted observation, sequence/time reorder, duplicate event nonce, or configured temporal gap produces DIVERGENT. The replay check is local to one trace and does not replace DDCAR's durable replay database. Times are caller-provided logical observations, not authenticated clocks. The age check measures gaps, not absolute freshness. No filesystem resolution, symlink confinement, cryptographic verification, physical sensing, or remote action is performed by CBA/0.1. An attacker who controls all observations can fabricate a consistent trace; independent evidence is essential.

The report retains field names, diagnostic codes, and observation digests rather than raw private evidence. It is not signed or independently attestable. Before production use, bind a versioned policy, independently verified evidence provenance, authoritative time/sequence semantics, and a signed report to the existing receipt model through a compatible versioned extension. Never insert an unsigned report into a signed receipt or change its canonical payload after sealing.

## Integration sequence
1. DDCAR: verify the existing receipt, independent authority, exact action, expiry, and signatures. Construct an immutable baseline from verified fields. Run CBA only as an additional diagnostic and keep all existing fail-closed decisions unchanged.
2. DDCRE: only after an independently established executor identity and approved adapter exist, collect signed claims/results and construct the trace. Compare actual target, exact action, policy version, state, and evidence commitments. No generic remote shell or new privilege is introduced.
3. RenderDiff: supply representation findings as separately verified evidence; do not treat CBA's lightweight Unicode indicators as comprehensive analysis.
4. Physical Gate: use independently measured device state and existing interlocks; CBA cannot grant physical authority.
5. RadialD: analyze counts and time series in shadow mode. Frequency is non-authoritative, and no anomaly score can override a deterministic block.

## Research basis and novelty boundary
The historical research lead is Anthony Maio's 2026 retrospective of early mobile security work. Independently documented Java ME implementation security failures and COMP128 side-channel attacks motivate compositional testing. The retrospective's operational claims and chronology are not independently verified here. This profile does not implement historical exploits or establish novelty over zero-trust, policy enforcement, runtime monitoring, or provenance systems. A genuine improvement requires controlled comparison against an existing baseline with independently labelled compound failures.

## Acceptance and release gates
The initial fixtures cover authority substitution, parameter divergence, representation ambiguity, policy downgrade, state drift, replay, worker substitution, evidence divergence, compound divergence, and temporal anomaly, plus a clean control. They are synthetic and deliberately contain observable differences. Passing them is not evidence of real-world attack detection or an improvement over DDCAR's existing controls.

Before an enforcement integration: run the complete original DDCAR suite; verify packaging and Python 3.10+ compatibility; implement independent evidence authentication and trust binding; specify precise field-level policy semantics; establish cross-process replay/freshness semantics; add signed interoperability vectors and malformed-input/property tests; compare against the existing verifier and at least one independent baseline; measure detection, false positives, earliest detection, latency, memory, and evidence size on representative workloads; review privacy, versioning, and backward compatibility. Privileged, network, payment, cloud, and physical execution remain disabled until independently approved and verified. No GitHub Actions are required.
