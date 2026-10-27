# R4-6: full-length fixed-identity Enc/Dec tests

This independent local experiment implements the complete fixed-identity encryption and decryption arithmetic using **dense Gaussian test keys**, not outputs of Extract. It does not change the earlier `R46_Local_20261023` or `WindowsNative` experiments.

## What the keys mean

For each profile, the offline fixture samples every coordinate of `e` using the unchanged scalar discrete-Gaussian sampler at the profile's exact `sigma`. It then computes `u0 = M e mod q` by a full matrix traversal. This is a consistent algebraic test pair. It is not a sign key, a zero key, or an output of implemented Setup/Extract/PubEval. Its joint distribution is not asserted to match those algorithms. Successful message recovery tests the online implementation; a few successful trials do not estimate a negligible decryption-failure probability.

All theoretical parameter values, frozen sets, and the original Gaussian/quantizer implementation are retained. Profile files are checked against frozen SHA-256 hashes. This publication version changes project labels and spells compatibility domains as identical hexadecimal bytes in `sampler.cpp` and `core_arithmetic.cpp`. Original source hashes and release hashes are tracked separately in the root provenance manifest; the historical run hashes identify the original executed sources and binaries.

## Matrix supply and memory

Only the synthetic matrix supplier uses AES-256-CTR. A test-specific key is derived with SHAKE256 from a versioned profile domain and a fresh matrix seed. The AES IV is `BE64(global_column) || BE64(0)`. The low counter half cannot overflow for the bounded column length, so columns do not reuse counter blocks. Bytes are masked to the exact `a` bits for `q = 2^a`.

On macOS, CommonCrypto supplies the AES stream; selftests compare its residues with the OpenSSL reference stream at both real bit widths, nonzero columns, and different tile sizes. This is a reproducible **test-input generator**, not a new seeded-MPK construction or a change to private sampling. Key and quantizer random tapes remain unchanged.

The full key, public vector, ciphertext, and matrix tiles fit in memory. The guarded plans including a 128 MB reserve are approximately 244.2 MB for C-MPK and 237.1 MB for C-CT. Runtime RSS monitoring is enabled. macOS does not provide the Windows hard-commit limit, so no OS-enforced hard-cap claim is made.

## Build and selftest

From this directory:

```sh
bash build_local.sh
build/local/lwq_ibe_bench --selftest
build/local/lwq_ibe_bench --mode encdec --data data --plan
```

Selftests cover the unchanged arithmetic and sampling routines, matrix tile invariance, cross-provider AES equality, an independent `mpz` calculation of the small-instance `u0 = M e` relation, and message-0/message-1 encryption/decryption roundtrips.

## Short preflight only

The micro mode retains the real `n`, `q`, noise/key widths and frozen sets, but processes only `blocks × 256` coordinates. It is explicitly not a complete-dimensional result.

```sh
build/local/lwq_ibe_bench --mode micro --profiles ours_mpk,ours_ct --blocks 8 --repetitions 2 --warmup 0 --data data --output results/new_micro
```

Initial OpenSSL-supplier micro results are retained in `results/micro4_initial`. The validated CommonCrypto runs are `results/micro4_native` and `results/micro8_native`. They are engineering preflights, not formal full-length results.

## Full experiments

Run profiles sequentially, without competing CPU-heavy work. The locked protocol uses three trials per profile, no full-length warmup, 32 MiB tiles, and a new output directory for each profile. It has an external 3600-second timeout per profile. The executable requires explicit `--allow-long-run`:

```sh
build/local/lwq_ibe_bench --mode encdec --profiles ours_mpk --repetitions 3 --warmup 0 --tile-mib 32 --memory-limit-mb 1400 --allow-long-run --data data --output results/new_ours_mpk
```

Repeat with `--profiles ours_ct` and another new output directory. Trials encrypt messages 0, 1, 0 using fresh secrets, scalar noise, private quantizer tapes, and public seeds. Both profiles use their complete dimensions. The expected full ciphertext sizes are 13,019,115 and 12,189,318 bytes, respectively.

## Timing definitions

- `preparation.csv`: one offline cost per fixture; coordinate key sampling, matrix supply, tile transpose and `u0 = M e` multiplication are separate. Preparation harness time includes allocation and monitoring. Validation and artifact I/O are separately reported. Do not multiply this one-time cost by the trial count.
- `enc_core_seconds`: full scalar calculation, fresh secret, all matrix products, all quantization blocks, and complete serialization. Test-matrix generation and resource/progress controls are excluded. `matrix_seconds`, `quant_seconds`, `scalar_seconds`, `pack_seconds`, and `enc_other_seconds` partition it. Packing includes the scalar/seed header once.
- `enc_feed_seconds`: synthetic matrix supply, not real MPK reads or PubEval.
- `enc_harness_seconds`: actual function wall time, including matrix-object allocation, supply, and controls. Consequently its difference from core plus feed is small harness overhead, not a negative or hidden algorithm cost.
- `dec_seconds`: actual complete parsing, vector reconstruction, full private-key inner product, and message decision. Its unpack/dot/decision/other columns partition the total. It is not a codec-only timing.
- `artifact_io_seconds` and `validation_seconds`: file write/read, exact readback checks, and artifact hashes, outside Enc/Dec timing.
- All timings are wall-clock seconds. No CPU cycles are inferred from frequency.

Raw sampling columns separate scalar and vector decisions. Precision begins at 384 bits and can rise to 768/1536; retained Bernoulli coins use 256 bits with a `2^-300` enclosure criterion. Zero observed retries is not a constant-time or universal termination guarantee.

## Saved artifacts and recovery

Each profile's `_fixture.bin` stores the matrix seed, offline key seed, every canonical private-key residue and the public vector in a versioned, little-endian format. It is read back and checked against the in-memory vectors before trials. Diagnostics record exact centered-key squared norm, maximum absolute value, all disposable test seeds, and hashes. The CSV records the key's nonzero-coordinate count and bit lengths.

Every ciphertext is saved, read back, compared byte-for-byte, and then decrypted. A failed message recovery is retained as a failed CSV row with its artifact and seeds before the run stops; it is not replaced by another random trial.

Full artifacts can be checked again:

```sh
build/local/lwq_ibe_bench --mode verify --profiles ours_mpk --data data --fixture-dir results/new_ours_mpk --ciphertext results/new_ours_mpk/ours_mpk_trial_0.bin --expected-message 0
```

`--fixture-dir` may also be supplied to a new EncDec run to reuse a saved fixture. Such a run records its preparation source as `loaded`; zero newly executed sampling time must not be interpreted as zero extraction cost. All persisted keys and seeds are public, disposable experiment data, not production secrets.

The complete-dimensional `u0 = M e` relation is established by construction. The independent arithmetic oracle is a small-instance selftest, not a second full matrix traversal. The experiment does not implement Extract, prove the full Setup/Extract joint distribution, certify deployment readiness, or measure the entire adaptive IBE system.
