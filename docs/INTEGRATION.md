# Integration contracts

## DDC Action Gate

The gate resolves human authority and tool identity, collects evidence, evaluates policy, and emits a signed decision commitment. The executor independently verifies it, reserves a nonce, and submits the immutable action. Gate and executor must not share signing credentials. DDC exposes only public assurance claims and evidence references.

A production integration must map existing Action Gate authority records, payment intents, policy versions, exact Base/USDC chain and asset identifiers, amounts, destinations, idempotency keys and settlement evidence into a versioned profile. It must not change Keeper custody or create spending authority. DDCAR is not a wallet, payment facilitator or substitute for independent settlement verification. The current Action Gate prohibition on production customer funds remains in force.

## MCP, HTTP and GitHub

`ddcar.adapters` contains pure constructors and an injected executor contract. MCP binds server/tool identity, schema digest and exact arguments. HTTP binds method, target, security-relevant headers and raw body bytes. GitHub mutations bind repository identity, expected predecessor SHA and exact mutation. Examples use no credentials or live effects. Live adapters must enforce the actual wire request and independently verify provider outcomes.

## DDCAL

A hosted verifier may accept receipt JSON, external trust anchors, parent bundles and optional evidence bytes. It should report cryptographic integrity, trusted signer identities, human grant validity, policy/evidence claims, exact-action equality, lineage and external-outcome verification separately. A valid signature must not be displayed as a verified physical outcome. DDCAL is optional; the open CLI supports offline verification.

## Interoperability

Reuse existing identity and authorization infrastructure. OAuth RAR can express grants; SPIFFE and enterprise identity can bind workloads; OpenTelemetry can link traces; DSSE/COSE can carry attestations; SCITT can register signed statements. These require explicit profiles and compatibility tests. Their presence in this document is not a claim of v0.1 wire compatibility.
