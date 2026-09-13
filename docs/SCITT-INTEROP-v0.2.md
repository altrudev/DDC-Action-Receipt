# DDCAR v0.2 — SCITT interoperability seam

**Status:** design note for a future adapter.  
**Core rule:** do not couple the DDCAR wire format to unstable Internet-Drafts.

Several 2026 SCITT Internet-Drafts now describe artifacts adjacent to DDC Action Receipt:

- pre-execution AI action authorization / Permit records;
- Agent Action Capsules covering executed, blocked, denied, errored and timed-out outcomes;
- AI-agent action receipts;
- refusal-event records;
- memory-provenance bindings;
- composite evidence verification over statement graphs.

These drafts are useful interoperability targets, but they are works in progress and are not treated here as finalized standards.

## 1. DDCAR stays internally stable

DDCAR v0.1 remains the implemented reference protocol.

The v0.2 execution-binding companion remains a DDCAR object.

Neither object should change its core semantics merely to mirror a draft profile.

## 2. Export adapter boundary

A future SCITT adapter should transform verified DDCAR objects into external statements only after local verification succeeds.

Preferred flow:

```text
DDCAR v0.1 receipt
+ optional v0.2 execution binding
+ independently verified evidence
        ↓
DDCAR verifier
        ↓
explicit export profile
        ↓
SCITT-compatible Signed Statement
        ↓
optional transparency registration / receipt
```

A SCITT receipt must not be confused with the DDC Action Receipt itself.

## 3. Candidate semantic mapping

### Pre-execution authorization

DDCAR fields that naturally map to a Permit-like object include:

- principal/agent;
- authority grant and proof;
- exact requested-action digest;
- policy identity;
- decision;
- decision expiry;
- delegation parent/lineage;
- decision proof.

### Post-action capsule / closure

DDCAR fields that naturally map to an action-capsule or closure-like object include:

- exact execution action digest;
- executor identity;
- observed outcome;
- execution time;
- execution evidence digest;
- execution proof;
- predecessor/lineage references.

### Extended execution binding

The v0.2 companion can supply references for:

- root/leaf authority;
- current state;
- tool contract;
- route proof;
- context/memory provenance;
- worker attestation;
- closure/enforcement evidence;
- full evidence graph.

## 4. Refusals are first-class

DDCAR already represents BLOCK and HUMAN-REVIEW as signed non-execution decisions.

A future export profile should preserve those outcomes as auditable refusal/hold records rather than dropping them because no execution occurred.

The exported record proves that a governed boundary recorded a refusal. It does not prove that no other bypass path executed unless route closure is independently established.

## 5. Attempt versus confirmed effect

An export adapter must preserve the distinction between:

```text
authorized
dispatched/attempted
observed effect
confirmed effect
unknown outcome
```

No translation may convert an attempt into a successful observed outcome.

## 6. Evidence graphs

Composite evidence should be represented by digest-addressed relationships rather than by copying every artifact into every exported statement.

A verifier should be able to distinguish:

- missing;
- stale;
- conflicting;
- revoked/superseded;
- valid but non-independent;
- verified under the selected profile.

A signed/registered assertion remains an assertion. Registration alone does not make its domain-specific payload true.

## 7. Deterministic subject identity

Where multiple issuers need to refer to the same action, tool, worker, or evidence object, the adapter should derive the subject identity from explicit canonical semantics rather than an issuer-local random identifier.

This should be a profile-level rule so independent issuers can arrive at the same subject identifier without sharing an allocator.

## 8. No automatic publication

Transparency registration may disclose metadata and can create irreversible public or consortium-visible evidence.

DDCAR should therefore keep SCITT publication as an explicit export/policy decision. Local signing is not consent to transparency publication.

## 9. Implementation timing

Build an adapter only when:

1. the exact target profile/revision is pinned;
2. its canonicalization/signature semantics are stable enough for conformance testing;
3. DDCAR can map without weakening its existing authority/execution distinctions;
4. disclosure/privacy requirements are explicit;
5. test vectors can prove round-trip field meaning.

Until then, preserving a clean export seam is lower risk than importing draft churn into the core protocol.
