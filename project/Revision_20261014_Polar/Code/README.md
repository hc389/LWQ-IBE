# Carry-aware integer polar codec

`integer_polar_codec.py` implements the coefficient-frozen Construction-D
quantizer. Its integer generator is `G=F^(tensor log2 B)`. Frozen bits specify
the low bits of `w=x G^-1 mod q`; carries adjust the raw-digit SC frozen bits
during honest generation. Encoding serializes all free coefficient bits.

The interval-posterior and stochastic-SC helper is included locally
at `vendor/polar_codec.py`. Its original and release hashes are recorded in
`vendor/PROVENANCE.json`. The release changes only naming and the hex spelling
of unchanged compatibility-domain bytes; the original project source was not
modified. The codec and validation runner import only this
local helper and do not require the previous revision's directory at runtime.
No large datasets were copied. The implementation requires Sage Python and
its Arb `RealBallField`; dependency hashes are also recorded in each run.

Run exact finite tests from the workspace root:

```
sage -python project/Revision_20261014_Polar/Code/test_integer_polar_codec.py
```

Run three fresh 512-dimensional pilots and saved-tape SC replays, choosing an
unused output directory:

```
sage -python project/Revision_20261014_Polar/Code/run_integer_polar_validation.py --recommendation project/Revision_20261014_Polar/analysis/parameters/recommendation.json --output project/Revision_20261014_Polar/Code/validation_margin_fresh
```

The runner refuses an existing output directory before writing any result.
The completed margin-candidate run is
`validation_margin_20261014/validation.json`, with `n=12288`, `a=228`,
`Sbits=113`, and executed dimension 512. Its zero, uniform, and identity_graph
cases each serialize **14,621 raw bytes to 7,502 bytes**, including the scalar,
seed, every information bit, and padding. All three pass exact round-trip,
saved-private-tape SC replay with byte-identical output, and 57,208 frozen
coefficient seed-bit checks per case. Each uses 3,720 private random draws and
takes about 0.92–0.93 seconds including replay; these are local prototype
measurements, not full IBE performance.

The earlier candidate remains recorded, unchanged, in
`validation_20261014/validation.json` with 14,236→7,437 bytes per case.
After vendoring, the exact tests were rerun successfully: 328 integer inverse
checks, 2,456 predictable-XOR bit checks, 656 exact rational reconstructed-kernel
equalities, and 14 exhaustive lattice-coset checks. The full-dimensional
certificate is inherited by the proved predictable-XOR kernel identity;
full-dimensional quantization was not executed.

This is a quantizer and codec prototype, not a complete IBE. Sources and scalar
are diagnostic inputs, private keys are not generated, and no empirical DFR is
claimed. The executable SHAKE seed is an instantiation; statistical analysis
uses independent frozen bits plus a separate classical-ROM argument. Fixed
256-dimensional block products are genuine lattices but are not claimed to
become quantization-good merely by increasing the number of blocks.

The mathematical and source audit is in
the original research workspace; that writing-oriented source note is not bundled.
