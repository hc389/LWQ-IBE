# Publication validation, 27 October 2026

This validation concerns packaging, naming compatibility and small self-tests.
It does not create new full-length timing trials or new attack estimates.

| Check | Observed result |
|---|---|
| Original source provenance | All 343 frozen inputs match both the frozen package hashes and their original project files; originals were not modified. |
| Release scope | 339 source/evidence files retained; four internal analysis reports omitted. One internal writing-workflow paragraph was removed from a protocol copy. |
| C++ build entries | Full-length Enc/Dec, optimized fragment and reference fragment builds all succeed on native macOS. Each produces `build/local/lwq_ibe_bench`. |
| Full-length executable self-test | Pass: arithmetic/sampling, matrix tile invariance, cross-provider AES, independent small `u0 = M e` oracle, both-message encryption/decryption. |
| Optimized/reference fragment self-tests | Both pass: arithmetic, RNG, posterior/SC, Gaussian sampler, codec and matrix streaming. |
| Exact finite codec tests | 328 integer inverse checks, 2,456 predictable-XOR checks, 656 exact Fraction kernel equalities and 14 exhaustive lattice-coset checks pass; expected rejection/counterexample controls pass. |
| Saved small-instance replay | All six saved pilot cases reproduce their complete serialized ciphertext bytes and hashes exactly: three 7,437-byte cases and three 7,502-byte cases. |
| Compatibility domains | All eight source occurrences encode the original bytes; C++ implicit terminating NUL and `sizeof` semantics are preserved. |
| Syntax | All 44 Python files parse; all three shell build helpers pass `bash -n`. |
| Normalized metadata | Numeric JSON leaves, long hex seeds and recorded run hashes are unchanged in the three normalized JSON records. Historical MD command labels were also normalized. |
| Publication names | Current source, text and file names use the release name; no former project-name literals remain in public text. |

The plan-only native run reports ciphertext lengths of 13,019,115 bytes and
12,189,318 bytes, with guarded allocation estimates of 244.2 MB and 237.1 MB.
These are configuration checks, not newly measured full-length runtimes.

Builds used the available native Clang/SageMath dependency installation. Existing
warnings in external GMP headers and unused harness helpers remain; they did not
prevent compilation or the tests. No Windows/Linux build, full Extract run,
full-length benchmark, complete-IBE security validation, constant-time audit or
fresh estimator run was performed during this release check.

`tools/check_release_replay.py` documents the saved-case replay. The recorded
historical results remain separate from these publication checks. Some public
metadata files normalize historical path/program labels; they must not be called
byte-identical raw files. Their original and release hashes and the reason for
normalization appear in `RELEASE_PROVENANCE.json`.
