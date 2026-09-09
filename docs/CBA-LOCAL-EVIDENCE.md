# CBA/0.1 isolated validation — 2026-09-09

The prototype was executed locally in the ChatGPT container, not on ASUS, OptiPlex, DDCRE, or the VPS. Python, pytest, cryptography, and jsonschema were available. The container could not resolve github.com, so the original repository was not cloned and its complete regression suite was not executed. The CBA implementation and tests were constructed and tested in an isolated package, then published through the authenticated GitHub connection.

`python -m pytest -q`: 12 passed, 11 subtests passed. `python -m compileall -q ddcar tests`: passed. The initial test run exposed a missing comparison between the commitment and an independently supplied baseline; this was corrected before publication and covered by a regression test.

The deterministic fixture benchmark ran 100 repetitions per case: 10 true positives, 0 false negatives, 0 false positives, 1 true negative. Mean analysis time across the 11 cases was approximately 737,314 ns (0.737 ms) on the available container. This is a diagnostic measurement, not a calibrated performance benchmark. No baseline implementation, real adversary, independent evidence producer, or production workload was evaluated. The fixtures deliberately contain detectable differences, and these results do not establish general detection accuracy or novelty.

Source SHA-256 (local tested copies):
- `ddcar/cba.py`: `e28bcaaf3c3022c1b26c556023b0a993dd5aa9e33e7a23368663d9673b8000d7`
- `tests/test_cba.py`: `f6ccaa63e40acf08484747e8f2d08489a6942b979268ca130c305aee3ac1ff6a`

The published branch must be independently checked against these hashes before treating this as evidence for its exact bytes. No GitHub Actions were started. No existing production authorization, receipt schema, or executor policy was changed. Full repository regression, integration, independent trust validation, and representative baseline comparison remain release gates.
