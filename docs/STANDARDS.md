# Standards landscape and non-duplication review

The problem is not the absence of signatures, identity, authorization or tracing. It is the missing action-specific statement that joins those inputs to exact execution and can be verified by a separate party. DDCAR should remain a narrow evidence profile, not a replacement platform.

| Existing layer | Contribution | Action-level gap |
|---|---|---|
| MCP and A2A | Tool/agent communication and authorization mechanisms | No universal exact-action assurance receipt required by transport |
| OAuth / RFC 9396 RAR | Fine-grained authorization details | Does not itself attest observed state and final execution |
| SPIFFE/SPIRE and enterprise agent identity | Workload identity and credentials | Identity does not prove a particular action was approved |
| OpenTelemetry and vendor traces | Operational spans, tool calls and handoffs | Traces are not necessarily independently signed authority/execution proof |
| in-toto, SLSA and DSSE | Signed provenance and attestation envelopes | DDCAR provides an agent-action-specific predicate and verification profile |
| SCITT / RFC 9943 | Transparent signed statements and registration receipts | Registration proof is distinct from an action-level statement |
| C2PA | Content provenance and credential chains | Different subject and execution assurance semantics |
| RFC 9421 | HTTP Message Signatures | Does not define the human/policy/evidence/action lifecycle |

References: https://www.rfc-editor.org/rfc/rfc8785.html (JCS); https://www.rfc-editor.org/rfc/rfc8032.html (Ed25519); https://www.rfc-editor.org/rfc/rfc9396.html (RAR); https://www.rfc-editor.org/rfc/rfc9421.html (HTTP signatures); https://www.rfc-editor.org/rfc/rfc9052.html (COSE); https://www.rfc-editor.org/rfc/rfc9943.html (SCITT architecture). Additional relevant specifications include MCP, A2A, SPIFFE, OpenTelemetry, in-toto, SLSA, DSSE, Sigstore and C2PA. The reference implementation claims only its documented profile, not implementation of every listed standard.
