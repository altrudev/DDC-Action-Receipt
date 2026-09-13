"""DDCAR v0.2 candidate companion execution-binding artifact.

The v0.1 receipt wire format remains unchanged. This module creates a separate,
content-addressed artifact that can be referenced from a v0.1 evidence entry.

It binds authority continuity, state, tool contract, execution route, context,
worker attestation, and optional high-volume evidence references without forcing
those large artifacts into every receipt.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import re

from .canonical import canonical_bytes
from .crypto import sha256_bytes, sha256_digest, sign_obj, verify_obj


VERSION = "0.2"
ARTIFACT_TYPE = "ddcar-execution-binding-v0.2"
DOMAIN = "execution-binding-v0.2"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _timestamp(value):
    if not isinstance(value, str):
        raise ValueError("timestamp required")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone required")
    return parsed.astimezone(timezone.utc)


def _digest(value, field):
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(field + " must be sha256 digest")
    return value


def make_execution_binding(
    *,
    binding_id,
    receipt_digest,
    action_digest,
    authority_root_digest,
    authority_leaf_digest,
    state_digest,
    tool_contract_digest,
    route_proof_digest,
    context_set_digest,
    policy_digest,
    observed_at,
    valid_until,
    closure_evidence_digest=None,
    enforcement_digest=None,
    worker_attestation_digest=None,
    dispatch_request_digest=None,
    observed_effect_digest=None,
    confirmed_effect_digest=None,
    full_evidence_digest=None,
    evidence_refs=None,
):
    if not isinstance(binding_id, str) or not binding_id:
        raise ValueError("binding_id required")
    observed = _timestamp(observed_at)
    valid = _timestamp(valid_until)
    if valid <= observed:
        raise ValueError("binding validity must be positive")

    artifact = {
        "type": ARTIFACT_TYPE,
        "version": VERSION,
        "binding_id": binding_id,
        "receipt_digest": _digest(receipt_digest, "receipt_digest"),
        "action_digest": _digest(action_digest, "action_digest"),
        "authority_root_digest": _digest(authority_root_digest, "authority_root_digest"),
        "authority_leaf_digest": _digest(authority_leaf_digest, "authority_leaf_digest"),
        "state_digest": _digest(state_digest, "state_digest"),
        "tool_contract_digest": _digest(tool_contract_digest, "tool_contract_digest"),
        "route_proof_digest": _digest(route_proof_digest, "route_proof_digest"),
        "context_set_digest": _digest(context_set_digest, "context_set_digest"),
        "policy_digest": _digest(policy_digest, "policy_digest"),
        "observed_at": observed_at,
        "valid_until": valid_until,
        "closure_evidence_digest": None,
        "enforcement_digest": None,
        "worker_attestation_digest": None,
        "dispatch_request_digest": None,
        "observed_effect_digest": None,
        "confirmed_effect_digest": None,
        "full_evidence_digest": None,
        "evidence_refs": list(evidence_refs or []),
    }
    for field, value in (
        ("closure_evidence_digest", closure_evidence_digest),
        ("enforcement_digest", enforcement_digest),
        ("worker_attestation_digest", worker_attestation_digest),
        ("dispatch_request_digest", dispatch_request_digest),
        ("observed_effect_digest", observed_effect_digest),
        ("confirmed_effect_digest", confirmed_effect_digest),
        ("full_evidence_digest", full_evidence_digest),
    ):
        if value is not None:
            artifact[field] = _digest(value, field)

    if len(artifact["evidence_refs"]) > 256:
        raise ValueError("too many evidence references")
    if len(set(artifact["evidence_refs"])) != len(artifact["evidence_refs"]):
        raise ValueError("duplicate evidence reference")
    for index, value in enumerate(artifact["evidence_refs"]):
        _digest(value, "evidence_refs[" + str(index) + "]")

    canonical_bytes(artifact)
    return artifact


def binding_digest(binding):
    return sha256_digest(binding)


def sign_execution_binding(binding, private_key, key_id, issuer_id):
    if not isinstance(key_id, str) or not key_id:
        raise ValueError("key_id required")
    if not isinstance(issuer_id, str) or not issuer_id:
        raise ValueError("issuer_id required")
    binding = deepcopy(binding)
    canonical_bytes(binding)
    return {
        "binding": binding,
        "issuer": {"id": issuer_id},
        "proof": {
            "type": "ddcar-ed25519-v1",
            "key_id": key_id,
            "signature": sign_obj(binding, private_key, DOMAIN),
        },
    }


def signed_binding_digest(package):
    return sha256_digest(package)


def binding_evidence_entry(package, *, observed_at, valid_until, source="ddcar-execution-binding"):
    observed = _timestamp(observed_at)
    valid = _timestamp(valid_until)
    if valid <= observed:
        raise ValueError("evidence validity must be positive")
    return {
        "type": "execution-binding",
        "digest": sha256_bytes(canonical_bytes(package)),
        "observed_at": observed_at,
        "valid_until": valid_until,
        "source": source,
    }


def verify_execution_binding(
    package,
    *,
    trust,
    now=None,
    expected_receipt_digest=None,
    expected_action_digest=None,
    expected_authority_root_digest=None,
    expected_authority_leaf_digest=None,
    expected_state_digest=None,
    expected_policy_digest=None,
    expected_tool_contract_digest=None,
    expected_route_proof_digest=None,
    expected_context_set_digest=None,
    expected_closure_evidence_digest=None,
    expected_enforcement_digest=None,
    expected_worker_attestation_digest=None,
    expected_dispatch_request_digest=None,
    expected_observed_effect_digest=None,
    expected_confirmed_effect_digest=None,
    expected_full_evidence_digest=None,
):
    errors = []

    def fail(value):
        errors.append(str(value)[:512])

    try:
        if not isinstance(package, dict):
            return ["binding package must be object"]
        if set(package) != {"binding", "issuer", "proof"}:
            return ["binding package fields"]
        binding = package["binding"]
        issuer = package["issuer"]
        proof = package["proof"]
        canonical_bytes(binding)
        if binding.get("type") != ARTIFACT_TYPE or binding.get("version") != VERSION:
            fail("binding type/version")
        if not isinstance(issuer, dict) or set(issuer) != {"id"} or not issuer.get("id"):
            fail("binding issuer")
        if not isinstance(proof, dict) or proof.get("type") != "ddcar-ed25519-v1":
            fail("binding proof")
        key_id = proof.get("key_id")
        public_key = trust["execution_binding"][key_id]
        if trust.get("bindings", {}).get("execution_binding", {}).get(key_id) != issuer["id"]:
            fail("binding key is not bound to issuer")
        verify_obj(binding, proof["signature"], public_key, DOMAIN)

        observed = _timestamp(binding["observed_at"])
        valid = _timestamp(binding["valid_until"])
        if valid <= observed:
            fail("invalid binding time interval")
        now_value = now or datetime.now(timezone.utc)
        if now_value.tzinfo is None:
            fail("verifier clock must be timezone-aware")
        elif now_value < observed:
            fail("binding not yet valid")
        elif now_value >= valid:
            fail("binding expired")

        digest_fields = (
            "receipt_digest",
            "action_digest",
            "authority_root_digest",
            "authority_leaf_digest",
            "state_digest",
            "tool_contract_digest",
            "route_proof_digest",
            "context_set_digest",
            "policy_digest",
        )
        for field in digest_fields:
            try:
                _digest(binding.get(field), field)
            except ValueError as exc:
                fail(exc)

        for field in (
            "closure_evidence_digest",
            "enforcement_digest",
            "worker_attestation_digest",
            "dispatch_request_digest",
            "observed_effect_digest",
            "confirmed_effect_digest",
            "full_evidence_digest",
        ):
            if binding.get(field) is not None:
                try:
                    _digest(binding.get(field), field)
                except ValueError as exc:
                    fail(exc)

        expected = {
            "receipt_digest": expected_receipt_digest,
            "action_digest": expected_action_digest,
            "authority_root_digest": expected_authority_root_digest,
            "authority_leaf_digest": expected_authority_leaf_digest,
            "state_digest": expected_state_digest,
            "policy_digest": expected_policy_digest,
            "tool_contract_digest": expected_tool_contract_digest,
            "route_proof_digest": expected_route_proof_digest,
            "context_set_digest": expected_context_set_digest,
            "closure_evidence_digest": expected_closure_evidence_digest,
            "enforcement_digest": expected_enforcement_digest,
            "worker_attestation_digest": expected_worker_attestation_digest,
            "dispatch_request_digest": expected_dispatch_request_digest,
            "observed_effect_digest": expected_observed_effect_digest,
            "confirmed_effect_digest": expected_confirmed_effect_digest,
            "full_evidence_digest": expected_full_evidence_digest,
        }
        for field, value in expected.items():
            if value is not None and binding.get(field) != value:
                fail(field + " mismatch")

        refs = binding.get("evidence_refs")
        if not isinstance(refs, list) or len(refs) > 256 or len(refs) != len(set(refs)):
            fail("evidence_refs invalid")
        else:
            for index, value in enumerate(refs):
                try:
                    _digest(value, "evidence_refs[" + str(index) + "]")
                except ValueError as exc:
                    fail(exc)
    except Exception as exc:
        fail("binding verification: " + str(exc))

    return errors
