# Threat model and security boundaries

The originating agent, tool output, repository content, browser pages, model-generated text, and network responses are untrusted. Attackers may alter parameters after approval, forge lineage, replay requests, supply stale evidence, impersonate issuer names, or substitute keys. The verifier uses externally pinned role keys and principal bindings and recomputes signed commitments.

The reference profile assumes separately protected human authority, gate and executor keys, authentic trust configuration and sound cryptographic primitives. Separate keys alone do not guarantee independent operators or hardware. A single administrator controlling every key can manufacture a consistent false history. The runtime, OS, KMS/HSM, clock, network and external destination remain trust boundaries.

A trusted signer may lie about evidence, policy evaluation or outcomes. A signature is accountability, not proof of truth. Independent postconditions, attested execution, trusted timestamps, revocation proofs and transparency registration are separate integrations. Repeated verification of the same false evidence does not create independence.

The executor reserves a nonce before an effect. A crash may leave an UNKNOWN operation; retry requires destination reconciliation. SQLite is a local atomic reservation store, not distributed consensus or banking settlement. Global replay guarantees require a shared authoritative domain. Historical integrity and present-day authorization are separate decisions.

Examples make no live network calls. Production adapters require destination allowlists, SSRF protections, TLS and redirect controls, credential isolation, bounded requests/responses, exact wire-body commitments, destination idempotency, and independent outcome checks. An arbitrary callback is not a certified executor. Do not authorize customer funds, production infrastructure or physical devices with this candidate.

Evidence hashes may reveal low-entropy content through dictionary attacks. Use access-controlled evidence stores and appropriate privacy-preserving commitments. Do not publish raw credentials, wallet keys, proprietary DDC implementation or sensitive personal evidence. A digest is not encryption, and a receipt is not an access-control grant.
