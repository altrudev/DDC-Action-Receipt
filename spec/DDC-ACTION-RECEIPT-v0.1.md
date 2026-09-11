# DDC Action Receipt v0.1 — Experimental Specification

Status: public reference candidate, not a ratified standard. This document defines the implemented Python profile and its limits. The terms MUST, SHOULD and MAY are normative for this profile. The protocol does not require a DDC implementation.

## 1. Purpose and distinction

The missing property is a portable commitment joining human authority, a policy decision, observed evidence, an exact action and an execution claim. Identity, authorization, tracing, and provenance each contribute necessary evidence but do not alone establish that complete chain. DDCAR composes with MCP/A2A, OAuth, SPIFFE, enterprise identity, OpenTelemetry, in-toto/SLSA, DSSE/COSE, SCITT and other existing infrastructure. It is not a replacement for them.

A DDCAR receipt is a signed statement about an action. A SCITT receipt is a proof of registration of a signed statement in a transparency structure. They are distinct objects and may be composed.

## 2. Wire representation

The normative schema is `ddcar/receipt.schema.json`. `version` is `0.1`; `spec` is the exact schema-defined URI. Unknown top-level and defined nested fields are rejected. Open structured parameter, scope and outcome values use the restricted JSON data model. Extensions require a new version or explicitly specified profile, not silent extra security fields.

Canonicalization is DDCAR-CJ1: UTF-8, RFC 8785-compatible JSON serialization restricted to null, booleans, strings, arrays, objects and safe integers. Floating-point values are forbidden; decimal amounts are strings. Object keys are sorted by UTF-16 code units, no insignificant whitespace is emitted, and strings use ECMAScript-compatible JSON escaping without Unicode normalization. Duplicate keys, unpaired surrogates, integers outside ±(2^53−1), excessive nesting and payloads over 4 MiB are rejected. Hashes are `sha256:` followed by 64 lowercase hexadecimal digits. Binary data is hashed as bytes, not converted to JSON first. This profile does not claim to serialize all RFC 8785 numeric values.

`requested_action` is exactly `{tool,operation,parameters}`. `tool` includes kind, stable identity, version and schema digest. Tool schemas and semantics must be resolved from a trusted source; a hash alone does not prove the tool's behavior. An API adapter must bind the actual destination, method, security-relevant headers, body bytes and predecessor conditions. No unapproved normalization or reserialization may occur after commitment.

## 3. Authority and signatures

The grant contains principal, agent, exact action digest, scope, nonce, issuance/expiry times and optional delegation parent. A human/organizational authority signs this grant. The receipt binds the grant and its proof; the gate signs the decision payload. The executor signs the decision digest, decision proof and execution object.

The `ddcar-ed25519-v1` profile signs `UTF8("DDCAR\\0" + domain + "\\0") || canonical_payload`, where domain is `authority-v0.1`, `decision-v0.1` or `execution-v0.1`. The separators are actual zero bytes. Signatures use unpadded canonical base64url. The verifier MUST use externally configured public keys and key-to-principal bindings. Embedded names or supplied keys alone do not establish trust. Decision and execution public keys MUST differ. Production systems SHOULD use distinct credentials and execution environments for human authority, gate and executor.

The decision payload is the entire receipt excluding `decision_proof`, `execution` and `execution_proof`. The execution payload contains `decision_digest`, `decision_proof` and `execution`. A producer must not modify a signed decision and reuse its proof. `BLOCK` and `HUMAN-REVIEW` are terminal non-execution records. An ALLOW may be verified as a decision-only commitment before execution; a completed receipt requires an execution signature.

## 4. Exact-action and transition rules

The executor MUST verify the decision and authority proofs before acting, reserve the nonce durably, and consume the committed action without agent-side reinterpretation. It MUST reject any different action digest. The outcome MUST identify SUCCEEDED, FAILED or UNKNOWN and bind an evidence digest. An UNKNOWN outcome must not be converted to success by retrying or by trusting the agent's narrative.

The verifier recomputes both action hashes and checks equality. It does not trust a producer-supplied `matches_approved` boolean. Tool schema digests, predecessor state, policy digest, permission checks and evidence hashes are signed commitments. Their real-world meaning and validity require independent evidence or a trusted evaluator. A valid receipt does not itself establish an independently verified external outcome.

## 5. Evidence, time and replay

Evidence records bind type, raw-byte digest, observation time and validity deadline. Evidence may also identify its source and predecessor. The reference verifier checks that evidence predates the decision and remains valid at execution. Historical verification checks authorization validity at the recorded execution time; preflight additionally checks current expiration. A trusted time source, signed timestamp or transparency inclusion is required for stronger historical time claims. A producer-controlled timestamp alone is not independent proof of time.

Nonces are scoped to issuer/security domain. A production executor MUST atomically and durably reserve the nonce before execution. Reservation failure blocks execution. A crash after reservation produces an indeterminate operation requiring external reconciliation, not automatic replay. For payments and other consequential operations, the destination must also enforce an idempotency key or exact-predecessor condition. The CLI replay database detects repeated audit submissions; it is not a global distributed replay authority. Offline verification cannot establish worldwide nonce uniqueness or current revocation without additional evidence.

## 6. Assurance and policy

The public fields expose results, claims and evidence references, never proprietary DDC algorithms. ALLOW requires PASS for semantic, authority, state, resource, security, physical and lineage assurance dimensions in this reference profile. Frequency is observational/non-authoritative and cannot grant permission or override a failed dimension. Explicit prerequisites and permissions must all PASS. Unknown scope constraints fail closed in the reference evaluator. Supported scope keys are max_amount, destination, currency, tool_id, operation, frame, workspace, max_speed, max_force and max_payload. Payment limits use finite, nonnegative decimal-string comparison. The physical profile binds a tool/device identity and operation and may additionally constrain coordinate frame, per-axis workspace bounds, speed, force and payload ceilings. Unknown keys still fail closed. Unit semantics remain part of the committed tool/schema profile and must be independently validated by the physical assurance layer. An ALLOW requires a bounded receipt expiry not later than its authority-grant expiry, and explicit tool_id and operation scope constraints; an empty scope is never unrestricted authority.

The verifier checks signed assertions and the supported constraint vocabulary. It does not independently reproduce DDC reasoning. Unresolved contradictions require refusal or human review; model confidence, repetition, urgency or observed data never create authority.

## 7. Lineage and delegation

`lineage.previous` lists digest-addressed related receipts. `delegation_parent` is optional and must also appear in previous. Related actions do not automatically inherit permissions. A delegation edge must have an independently signed human grant naming the parent, exact child action and agent. The child scope must be contained by the parent scope, must not extend its expiry, and must not self-delegate. Every supplied parent is rehashed, signature-verified and recursively checked against external trust anchors. Missing parents, cycles, excessive depth, forged ancestry or expanded authority are rejected. The reference profile does not permit an agent to mint new human authority by itself; general delegated capability credentials require a future explicit trust profile.

## 8. Verification outcomes

`ddcar verify` returns exit 0 for a valid reference-profile receipt and exit 2 for invalid, malformed or untrusted input. A valid result means the signed evidence is internally consistent under the supplied trust policy. It does not imply policy correctness, external outcome verification, trusted time, current revocation status or production authorization. A relying party MUST inspect these limitations before using the result to authorize another action. The verifier is read-only except for an explicitly requested replay database reservation.

## 9. Open interfaces and evolution

The specification, schema, verifier, vectors and adapters are public under Apache-2.0. DDC Action Gate may emit the public assurance claims; DDCAL may verify them without being a mandatory service. Future profiles may use COSE/DSSE, OAuth RAR, SPIFFE, hardware-backed attestations and SCITT registration. Such profiles must specify exact byte/signature semantics and independently testable trust requirements. v0.1 must not claim interoperability with a format merely because it uses similar terminology.


## 10. Physical-action authority profile

The reference verifier includes a conservative physical-action scope profile intended for composition with an independent physical assurance gate.

A physical scope MUST contain `tool_id` and `operation`. It MAY contain `frame`, `workspace`, `max_speed`, `max_force`, and `max_payload`.

`workspace` is an object keyed by coordinate axis. Each value is a two-element inclusive lower/upper bound. The requested action's `parameters.target` MUST contain exactly the same axes and each requested coordinate MUST fall within the bound. If `frame` is present, every target coordinate MUST commit to that exact frame.

`max_speed`, `max_force`, and `max_payload` are finite nonnegative decimal ceilings. Their requested parameter objects are expected at `parameters.speed.value`, `parameters.force.value`, and `parameters.payload.value` respectively when the corresponding scope constraint is present.

This profile verifies authority containment only. It does not replace device-state validation, trajectory analysis, collision avoidance, functional safety, interlocks, emergency-stop systems, or certified safety controllers. A DDCAR-valid physical receipt is evidence that a signed action remained within the signed authority vocabulary; it is not proof that the physical action was safe or that the claimed physical outcome occurred.
