# DDCAR Decision-State Evidence Profile v1

This profile adds historical decision-state evidence to DDC Action Receipt without silently changing the v0.1 receipt wire format.

The decision state is a canonical JSON sidecar. Its SHA-256 digest is included in the signed receipt's existing `evidence` array with:

`type = "ddc-decision-state-v1"`

Because the evidence digest is inside the signed decision payload, the decision-time snapshot is cryptographically committed without adding undeclared top-level fields to v0.1.

## Why this profile exists

A later fact may prove what happened while still being unavailable to the actor when the decision was made.

The profile therefore separates:

- what evidence existed,
- what was reachable,
- what was discoverable,
- what was fresh enough,
- what the actor could access,
- what was trusted,
- what was actually consulted,
- what evidence policy required,
- and what remained unresolved.

It also records event time, evidence creation time, evidence availability time, and decision time.

## Verification rules

When a receipt includes a `ddc-decision-state-v1` evidence item and the verifier is given the corresponding external evidence bytes, verification checks:

1. the external bytes hash to the digest committed in the receipt;
2. the sidecar matches the receipt id, exact requested-action digest, issuer, and decision time;
3. consulted evidence is part of the available evidence set;
4. consulted evidence is also committed in the receipt evidence set;
5. evidence claimed as consulted was available no later than the decision time;
6. evidence creation cannot occur after its claimed availability time;
7. an ALLOW cannot omit evidence explicitly marked as required by the decision-state profile;
8. contradictions and unresolved assumptions remain represented rather than rewritten.

This is not proof that a source was truthful, that a timestamp was independently trusted, or that a remote physical consequence occurred.

## DDC Radial invariants

- later truth is not retroactive knowledge;
- dispatch is not consequence;
- observation is not reconstruction;
- available, required, and consulted evidence are distinct;
- actor compliance and evidence-channel adequacy are distinct;
- missing evidence is not automatically evidence of absence;
- confidence must remain scoped to a claim and boundary;
- truthful incompleteness is preferred to false completeness.

## Attribution

DDC Action Receipt and the broader DDC architecture are designed and developed by **Valentyn Rukhaylo / Altru.dev**.

This evidence-state profile was materially sharpened through Valentyn Rukhaylo's public technical engagement with **Jason McGill**, particularly around downstream consequence boundaries, contemporaneous versus later evidence, the three-clock model, actor-specific evidence horizons, and consequence versus decision reconstruction.

DDC Radial analysis extended those refinements into available-versus-required-versus-consulted evidence, evidence-channel adequacy, causal evidence provenance, post-action contamination, and branch preservation.
