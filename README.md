# DDC Action Receipt

DDC Action Receipt (DDCAR) is an experimental, vendor-neutral reference protocol for binding human authority, an agent decision, exact action parameters, and signed execution evidence. It is not a production-certified execution system.

The public protocol is independently usable without proprietary DDC logic. A valid signature proves that a trusted key signed a statement; it does not by itself prove human consent, policy correctness, an external outcome, or physical safety.

## Release status

The v0.1 wire format is unchanged. The v0.1.2 maintenance candidate corrects preflight evidence freshness and includes bounded lineage verification. See `docs/RELEASE-0.1.2.md` and `docs/PREFLIGHT-FRESHNESS-ACCEPTANCE.md`. Production payment, cloud, and physical-device execution remain outside this reference release's acceptance scope.

## Source and verification

Install the Python package in an isolated environment and run `python -m pytest -q`. The reference verifier requires independently established trust anchors and separates historical verification from execution preflight. Its CLI and adapter contracts do not constitute a trusted external executor.

## Contributing

Issues, threat-model reviews, independent implementations, interoperability vectors, and proposed profiles are welcome. Do not submit private DDC algorithms or credentials. Protocol changes require specification updates, deterministic test vectors, adversarial tests, and a compatibility decision. Security reports should follow `SECURITY.md`.
