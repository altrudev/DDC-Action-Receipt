# DDC Action Receipt (DDCAR)

**An experimental, vendor-neutral action-evidence protocol and reference implementation.**

DDCAR binds an explicit human/organizational grant, agent and tool identities, exact structured action, evidence and policy commitments, assurance decision, and independently signed execution claim. Its purpose is to make an agent action inspectable by a verifier that does not trust the originating agent. It is not an identity provider, a policy engine, a logging replacement, or proof that a remote physical outcome occurred.

**Status:** v0.1 reference candidate. Not a ratified standard, security certification, or production payment authorization. Live consequential execution is not enabled by default. The reference implementation is Apache-2.0; private DDC/Crystalline internals are not included.

## Start locally

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m pip install pytest
python -m pytest -q
python examples/make_example.py
python -m ddcar.cli verify examples/receipt.json --trust examples/trust.json
```

The example generator creates disposable demonstration keys in memory and writes only public keys and signed artifacts. Never use demo identities or keys for real authority. `ddcar keygen` prints a private key, so redirect it only to a protected local file and never commit it.

To verify independently, install the wheel on a different machine and supply your own trusted public-key configuration. A receipt's embedded identities are not trust anchors. Verification fails closed when required keys, authority proofs, chain parents, or structured constraints are missing. Use `--decision-only` for a pre-execution decision; use `--replay-db` for durable audit duplicate detection. The executor uses the same durable reservation mechanism before an external effect.

## Architecture

```text
Human/organization -- signed exact-action grant
          ↓
Agent → Action Gate -- signed decision commitment
          ↓ ALLOW only
Independent executor -- verifies commitment and reserves nonce
          ↓
External system → outcome evidence → executor signature
          ↓
Portable receipt → independent verifier / DDCAL
```

The public protocol is independent of DDC. DDC Action Gate can act as an issuer; DDCAL can verify and report on receipts. Neither service is required to run the open verifier. See `spec/`, `docs/THREAT-MODEL.md`, `docs/DDC-ASSURANCE.md`, and `docs/INTEGRATION.md`.

## Scope and limitations

The reference profile supports exact human grants, bounded decimal amounts, destination/currency/tool/operation constraints, separate signing identities, immutable action commitments, evidence digests, historical/preflight time checks, explicit lineage and delegation edges, and SQLite replay reservation. MCP, HTTP, and GitHub adapter constructors are provided with an injected transport boundary. They do not silently execute live requests or acquire credentials.

A valid signature proves a trusted key signed the statement, not that the signer was honest, the clock was trustworthy, the policy was correct, or the external world changed as claimed. Production adapters require independently established trust, immutable transport binding, externally enforceable idempotency and predecessor checks, revocation/time evidence, and independent postcondition verification. See the release gates before connecting to customer funds or production infrastructure.

## Contributing

Issues, threat-model reviews, independent implementations, interoperability vectors, and proposed profiles are welcome. Please do not submit private DDC algorithms or credentials. A protocol change needs a specification update, deterministic test vectors, adversarial tests, and a documented compatibility decision. Security reports should follow `SECURITY.md` rather than public exploit disclosure.

## Release status

The 0.1.1 reference implementation includes bounded lineage verification and remains experimental. The v0.1 wire format is unchanged. See docs/RELEASE-0.1.1.md for assurance scope and limitations. No production payment, cloud, or physical-device execution is authorized by this release.
