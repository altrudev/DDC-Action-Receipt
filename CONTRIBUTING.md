# Contributing

Use issues for proposed profiles, interoperability gaps, threat-model findings and independently reproducible defects. Keep changes scoped to public protocol properties. Do not submit private DDC/Crystalline implementation, credentials, or proprietary third-party code.

Run `python -m pytest -q`, build the wheel, and test installation outside the source directory. A protocol change should include specification/schema changes, positive and negative vectors, compatibility notes and a DDC assurance disposition. New authority or execution capabilities must fail closed until their policy and trust profiles are defined. Avoid live network or payment tests in the default suite.
