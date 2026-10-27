# LWQ-IBE research artifacts

Repository: <https://github.com/hc389/LWQ-IBE>

Code and frozen experimental evidence accompanying **Native Polar-Lattice
Compression in Yamada's Anonymous IBE Framework**. The implementation follows
the paper's LWQ-based honest quantization route while retaining the stated
Gaussian-reference security interface. This is a research prototype, not a
deployable or complete IBE implementation.

## What is included

| Directory | Purpose |
|---|---|
| `project/Revision_20261020_Merged/analysis/unified_modulus_20261023/` | Common finite parameter checks, separate modulus searches, original-format JKN21/Abla24 comparisons and saved attack estimates. |
| `project/Revision_20261014_Polar/analysis/abla_borrowing_round2_20261016/experiments/` | Classical selected profiles, polar certificates, block-length/precision controls and saved parameter-search evidence. |
| `project/Revision_20261020_Merged/analysis/quantum_parameter_update_20261021/` | Quantum-cost candidate records and archived MITM completion evidence. These are retained results, not newly run attacks. |
| `project/Revision_20261013_Native/analysis/polar_validation_20261014/` | Finite polar-certificate implementation and dependency tests. |
| `project/Revision_20261014_Polar/Code/` | Carry-aware integer codec, exact finite tests and recorded small pilots with replay tapes. |
| `fragment_optimization/` | The local reference and optimized fragment sources, configurations and recorded timing comparison. |
| `project/Revision_20261020_Merged/Experiments/R46_EncDec_20261023/` | Full-length fixed-identity online encryption/decryption code, configurations and six recorded trials using algebraic test keys. |
| `project/Revision_20261020_Merged/analysis/r46_encdec_20261023/` | Frozen protocol, numerical summary and statistical accounting for the full-length trials. |

The dated directory names retain the dependency layout and identify historical
research stages. Intermediate candidates are not additional recommended profiles.
Internal claim-drafting reports have been omitted; the exclusion list is recorded
in `RELEASE_PROVENANCE.json`.

## Scope and interpretation

The full-length runs use disposable dense Gaussian **test keys**, with
`u0 = M e mod q` established before online timing. They are not Extract outputs.
Setup, Extract and public identity evaluation are not implemented or benchmarked.
The streamed matrix supplier is a synthetic test-input generator, not a new
seeded-MPK construction. A few successful messages do not measure a negligible
decryption-failure probability.

Recorded times are elapsed seconds or milliseconds as labeled, not CPU cycles.
Matrix supply is reported separately. Base-LWE attack estimates, conditional
statistical bounds and complete-IBE security are distinct. The repository does
not certify complete-IBE 128-bit security, constant-time execution, uniform
sampler termination, deployment readiness or independent cross-platform
reproduction.

## Dependencies

- SageMath **10.9**, including Arb `RealBallField`, for the small codec and
  exact tests. The finite polar certificate itself uses Python's standard library.
- External [lattice-estimator](https://github.com/malb/lattice-estimator), commit
  `53da5982597709ba0fdf94ea37a84d822310fd84`, for the archived attack workflows.
  It is not vendored. Classical records use the stated ADPS16 classical
  Core-SVP cost and primal GSA models; quantum records retain their own scope.
- Native C++17 compiler, FLINT **3**, GMP/MPFR and OpenSSL development files.
  The recorded environment used Apple M2, Apple Clang 21.0.0, GMP 6.3.0,
  MPFR 4.2.2 and FLINT 3.4.0; see each historical `metadata.json`.
- The statistical-analysis scripts additionally use NumPy, SciPy and Matplotlib.

Set `FLINT_PREFIX` to a native dependency prefix or provide `pkg-config` files.
`CXX` selects the compiler. The macOS matrix supplier uses CommonCrypto. Build
helpers have macOS/Linux branches; other platforms are not newly certified by
this release.

## Quick local checks

From the repository root:

```sh
sage -python project/Revision_20261014_Polar/Code/test_integer_polar_codec.py

cd project/Revision_20261020_Merged/Experiments/R46_EncDec_20261023
bash build_local.sh
build/local/lwq_ibe_bench --selftest
build/local/lwq_ibe_bench --mode encdec --data data --plan
```

The plan command does not run a full benchmark. Full-length runs require
`--allow-long-run`; do not run profiles concurrently. For a deliberately selected
new run, use a fresh output directory, for example:

```sh
build/local/lwq_ibe_bench --mode encdec --profiles ours_mpk \
  --repetitions 3 --warmup 0 --tile-mib 32 --memory-limit-mb 1400 \
  --allow-long-run --data data --output results/new_ours_mpk
```

The other measured profile is `ours_ct`. The historical full-length fixture and
ciphertext `.bin` files are omitted; their hashes and diagnostics remain. To
verify an existing full-length ciphertext, first generate a fresh fixture and
ciphertext. Do not overwrite or relabel the saved CSV results as new trials.

For the local fragment comparison, build `fragment_optimization/build_local.sh`
and `fragment_optimization/baseline/build_local.sh`. Both produce
`build/local/lwq_ibe_bench` relative to their respective directories. Only `blocks`
mode is relevant to the reported fragment-optimization table; the saved trials
and configurations define that comparison.

## Paths, naming and replay integrity

The release uses **LWQ-IBE** for the project and `lwq_ibe_bench` for the executable.
Historical path/program labels and the former project label in a pilot schema
have been normalized for publication. Numerical values, seeds and recorded run
hashes are preserved. These published metadata files are therefore not
byte-identical copies of the original local records; original and release file
hashes are tracked separately, with a normalization reason for each changed file.

Domain-separation octets used to generate recorded random streams and frozen
bits are unchanged. The release spells them as explicit hexadecimal constants
so renaming does not silently alter fixed-seed replay or the C++ string-length
semantics. `RELEASE_PROVENANCE.json` separates original source hashes from release
hashes and records those byte-identity checks. Historical source/executable
hashes in old run records are not rewritten to pretend the renamed release was
the binary that produced the old timings.

Several parameter/search orchestration scripts retain absolute historical
workspace/Sage paths and references to an external estimator checkout. Configure
these constants in a separate working copy before rerunning them. The preserved
layout supplies the numerical dependency chain, but this is not an out-of-the-box
reproduction of every historical orchestration step. Workspace-only reports may
also be referenced by historical audit scripts.

`SHA256SUMS.txt` checks the released payload. `PACKAGE_SCOPE.json` describes
omissions and remaining boundaries. Original research files outside this release
directory were not modified.

## License

Author-owned research code is licensed under **PolyForm Noncommercial 1.0.0**;
see `LICENSE`. It permits noncommercial research, testing and education under
its terms. Commercial permission must be obtained separately. This is a
source-available noncommercial license, not an OSI-approved open-source license.
External dependencies keep their own licenses and are not relicensed here.
The project-owned numerical helper's provenance is recorded separately.

No new attack estimates or full-length benchmark results are created by the
naming/license release. Any local build, self-test and replay checks performed
for this release are documented in `RELEASE_VALIDATION.md`, separately from the
historical measurements. `tools/check_release_replay.py` repeats the six saved
small-instance cases without overwriting their recorded outputs.
