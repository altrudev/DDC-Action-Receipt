"""Decision-time evidence profile for DDC Action Receipt v0.1.

The profile is carried as external canonical JSON whose digest is committed
inside the signed receipt evidence list. This preserves the v0.1 wire format
while allowing an independent verifier to inspect the historical evidence
state used by the decision.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from .canonical import canonical_bytes, loads
from .crypto import sha256_bytes


PROFILE = "ddcar-decision-state-v1"
EVIDENCE_TYPE = "ddc-decision-state-v1"


def make_decision_state(
    *,
    receipt_id: str,
    requested_action_digest: str,
    decision_actor: str,
    decision_time: str,
    available_evidence: list[dict[str, Any]],
    required_evidence: list[str],
    consulted_evidence: list[str],
    unresolved_assumptions: list[str] | None = None,
    contradictions: list[str] | None = None,
    authority_valid_from: str | None = None,
    authority_valid_until: str | None = None,
    evidence_channel_notes: list[str] | None = None,
) -> dict[str, Any]:
    state = {
        "profile": PROFILE,
        "receipt_id": receipt_id,
        "requested_action_digest": requested_action_digest,
        "decision_actor": decision_actor,
        "decision_time": decision_time,
        "authority_valid_from": authority_valid_from,
        "authority_valid_until": authority_valid_until,
        "available_evidence": deepcopy(available_evidence),
        "required_evidence": list(required_evidence),
        "consulted_evidence": list(consulted_evidence),
        "unresolved_assumptions": list(unresolved_assumptions or []),
        "contradictions": list(contradictions or []),
        "evidence_channel_notes": list(evidence_channel_notes or []),
    }
    from .schema import validate_decision_state
    validate_decision_state(state)
    canonical_bytes(state)
    return state


def decision_state_bytes(state: dict[str, Any]) -> bytes:
    from .schema import validate_decision_state
    validate_decision_state(state)
    return canonical_bytes(state)


def decision_state_digest(state: dict[str, Any]) -> str:
    return sha256_bytes(decision_state_bytes(state))


def decision_state_evidence_entry(
    state: dict[str, Any],
    *,
    valid_until: str,
    source: str = "ddcar-decision-state",
) -> dict[str, Any]:
    return {
        "type": EVIDENCE_TYPE,
        "digest": decision_state_digest(state),
        "observed_at": state["decision_time"],
        "valid_until": valid_until,
        "source": source,
    }


def parse_decision_state(data: bytes) -> dict[str, Any]:
    state = loads(data)
    if not isinstance(state, dict):
        raise ValueError("decision-state evidence must be a JSON object")
    from .schema import validate_decision_state
    validate_decision_state(state)
    return state
