# DDCAR Execution Binding v0.2 — Candidate Companion Profile

**Status:** candidate extension profile; validation intentionally deferred.

This profile does **not** change the DDC Action Receipt v0.1 wire format. Instead, it defines a separately signed, content-addressed execution-binding artifact that a v0.1 receipt can reference through its existing `evidence[]` mechanism.

## 1. Purpose

The v0.1 receipt already binds human/organizational authority, exact action, decision, evidence, policy, lineage, and execution claim.

The missing property addressed here is a compact portable commitment joining the v0.1 action to additional execution-time context that may live in other DDC components:

- root authority and effective leaf authority;
- current state/predecessor;
- exact tool contract;
- governed execution route;
- context/memory set;
- policy;
- worker/runtime attestation;
- route-closure and enforcement evidence;
- optional large evidence objects.

The profile exists to avoid expanding every receipt with high-volume or implementation-specific evidence while still allowing a verifier to establish exact cryptographic linkage.

## 2. Separation from v0.1

A v0.1 receipt remains valid or invalid according to the v0.1 specification.

The v0.2 execution-binding artifact is an optional companion object. A relying party that requires this profile MUST verify both:

1. the underlying DDCAR v0.1 receipt; and
2. the referenced v0.2 execution-binding artifact.

The presence of an `execution-binding` evidence item alone is not equivalent to semantic verification of the companion artifact.

## 3. Artifact structure

The candidate implementation uses:

```text
type = ddcar-execution-binding-v0.2
version = 0.2
binding_id
receipt_digest
action_digest
authority_root_digest
authority_leaf_digest
state_digest
tool_contract_digest
route_proof_digest
context_set_digest
policy_digest
observed_at
valid_until
closure_evidence_digest?
enforcement_digest?
worker_attestation_digest?
full_evidence_digest?
evidence_refs[]
```

All digest fields use the existing DDCAR `sha256:<hex>` representation.

The object is canonicalized with DDCAR-CJ1 and signed in the `execution-binding-v0.2` domain.

## 4. Signer binding

A cryptographically valid signature is insufficient by itself.

The verifier MUST establish externally that the signing key is bound to the stated execution-binding issuer. The candidate verifier therefore uses a distinct `execution_binding` trust namespace and key-to-issuer binding.

## 5. Tool-contract drift

`tool_contract_digest` identifies the exact policy-relevant tool contract used at execution time.

A relying party that knows the approved contract digest MUST compare it to this field. Mismatch is tool-contract drift and invalidates the execution binding for that relying party.

The digest is a commitment only. The trustworthiness of the underlying tool schema/implementation still depends on how that contract was observed and authenticated.

## 6. Route closure

`route_proof_digest`, `closure_evidence_digest`, and `enforcement_digest` allow DDC Physical Gate or another execution gate to connect the action receipt to route-closure evidence.

A signed digest does not independently prove that every bypass path was closed. It proves only that the execution-binding issuer committed to a specific route/closure evidence object.

## 7. Context and memory

`context_set_digest` binds the action to the exact set of memory/RAG/cache/context records used for the consequential decision.

The context set is evidence/data only. It must never create authority.

A verifier that relies on context integrity should separately verify source provenance, representation binding, policy/purpose, and freshness for the referenced context set.

## 8. Worker attestation

`worker_attestation_digest` is optional because not every execution environment supports hardware/workload attestation.

When present, it identifies the attestation object associated with the executor/runtime. A hash of an attestation is not itself proof of platform state; the attestation format and verifier must establish that separately.

## 9. Two-tier evidence storage

This profile supports storage minimization without evidence inflation.

### Tier 1 — compact binding

The signed execution-binding artifact is intended to remain small. It records exact digests and references.

### Tier 2 — large evidence

Large artifacts such as logs, traces, screenshots, sensor streams, tool catalogs, and diagnostic dumps are referenced through:

- `full_evidence_digest`; and/or
- `evidence_refs[]`.

These artifacts may be stored only when policy or risk requires them.

A Tier 1 binding MUST NOT imply that a referenced Tier 2 artifact is retained or retrievable unless the storage system actually guarantees that property.

## 10. v0.1 receipt reference

A v0.1 receipt can reference the signed companion package as:

```json
{
  "type": "execution-binding",
  "digest": "sha256:...",
  "observed_at": "...",
  "valid_until": "...",
  "source": "ddcar-execution-binding"
}
```

The digest is over the complete signed package, not only the inner binding payload.

This preserves the closed v0.1 schema.

## 11. Refusal records

The same companion-artifact pattern may later be used for BLOCK, HUMAN-REVIEW, route failure, stale authority, stale state, or recovery receipts.

This candidate does not change the v0.1 decision vocabulary.

## 12. Validation status

Implementation and deferred test cases exist on the candidate branch.

No conformance or PASS claim is made until the normal validation cycle is run.
