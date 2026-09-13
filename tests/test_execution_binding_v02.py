from datetime import datetime, timezone

from ddcar.canonical import canonical_bytes
from ddcar.crypto import generate_keypair, public_from_private, sha256_bytes
from ddcar.execution_binding import (
    binding_evidence_entry,
    make_execution_binding,
    sign_execution_binding,
    verify_execution_binding,
)


def d(seed):
    return "sha256:" + seed * 64


def test_execution_binding_round_trip_and_expected_bindings():
    private, public = generate_keypair()
    key_id = "binding-key"
    binding = make_execution_binding(
        binding_id="binding-1",
        receipt_digest=d("1"),
        action_digest=d("2"),
        authority_root_digest=d("3"),
        authority_leaf_digest=d("4"),
        state_digest=d("5"),
        tool_contract_digest=d("6"),
        route_proof_digest=d("7"),
        context_set_digest=d("8"),
        policy_digest=d("9"),
        observed_at="2026-09-13T20:00:00Z",
        valid_until="2026-09-13T21:00:00Z",
        closure_evidence_digest=d("a"),
        enforcement_digest=d("b"),
        worker_attestation_digest=d("c"),
        full_evidence_digest=d("d"),
        evidence_refs=[d("e"), d("f")],
    )
    package = sign_execution_binding(binding, private, key_id, "executor:one")
    errors = verify_execution_binding(
        package,
        trust={
            "execution_binding": {key_id: public},
            "bindings": {"execution_binding": {key_id: "executor:one"}},
        },
        now=datetime(2026, 9, 13, 20, 30, tzinfo=timezone.utc),
        expected_receipt_digest=d("1"),
        expected_action_digest=d("2"),
        expected_policy_digest=d("9"),
        expected_tool_contract_digest=d("6"),
        expected_route_proof_digest=d("7"),
        expected_context_set_digest=d("8"),
        expected_worker_attestation_digest=d("c"),
    )
    assert errors == []


def test_execution_binding_rejects_tool_contract_drift():
    private, public = generate_keypair()
    key_id = "binding-key"
    binding = make_execution_binding(
        binding_id="binding-1",
        receipt_digest=d("1"),
        action_digest=d("2"),
        authority_root_digest=d("3"),
        authority_leaf_digest=d("4"),
        state_digest=d("5"),
        tool_contract_digest=d("6"),
        route_proof_digest=d("7"),
        context_set_digest=d("8"),
        policy_digest=d("9"),
        observed_at="2026-09-13T20:00:00Z",
        valid_until="2026-09-13T21:00:00Z",
    )
    package = sign_execution_binding(binding, private, key_id, "executor:one")
    errors = verify_execution_binding(
        package,
        trust={
            "execution_binding": {key_id: public},
            "bindings": {"execution_binding": {key_id: "executor:one"}},
        },
        now=datetime(2026, 9, 13, 20, 30, tzinfo=timezone.utc),
        expected_tool_contract_digest=d("f"),
    )
    assert "tool_contract_digest mismatch" in errors


def test_v01_receipt_can_reference_binding_without_wire_format_change():
    private, _ = generate_keypair()
    binding = make_execution_binding(
        binding_id="binding-1",
        receipt_digest=d("1"),
        action_digest=d("2"),
        authority_root_digest=d("3"),
        authority_leaf_digest=d("4"),
        state_digest=d("5"),
        tool_contract_digest=d("6"),
        route_proof_digest=d("7"),
        context_set_digest=d("8"),
        policy_digest=d("9"),
        observed_at="2026-09-13T20:00:00Z",
        valid_until="2026-09-13T21:00:00Z",
    )
    package = sign_execution_binding(binding, private, "binding-key", "executor:one")
    evidence = binding_evidence_entry(
        package,
        observed_at="2026-09-13T20:00:00Z",
        valid_until="2026-09-13T21:00:00Z",
    )
    assert evidence["digest"] == sha256_bytes(canonical_bytes(package))
    assert evidence["type"] == "execution-binding"
