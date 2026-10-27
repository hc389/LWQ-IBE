"""Small executed integer-polar pilots plus inherited full-dimensional bounds."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import time

from integer_polar_codec import (VENDOR, integer_transform, lattice_exponents,
    new_private_tape, pack_ciphertext, public_frozen_bits, sample_vector,
    unpack_ciphertext)
from test_integer_polar_codec import run as exact_tests


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_vector(kind, a, D, seed):
    if kind == "zero":
        return [0] * D
    width = (a + 7) // 8
    raw = hashlib.shake_256(b"integer-polar-source/" + kind.encode() + seed).digest(width * D)
    values = [int.from_bytes(raw[j * width:(j + 1) * width], "big") % (1 << a) for j in range(D)]
    if kind == "uniform":
        return values
    if kind == "identity_graph":
        h = D // 2
        return values[:h] + [(values[j] + values[(j + 1) % h]) % (1 << a) for j in range(h)]
    raise ValueError(kind)


def pilot(row, folder, kind):
    p = row["parameters"]
    a, s, F, D, B = p["q_bits"], p["S_bits"], row["polar"]["frozen_sets"], 512, 256
    case = folder / kind
    case.mkdir(parents=True, exist_ok=False)
    seed, source_seed = os.urandom(32), os.urandom(32)
    y = source_vector(kind, a, D, source_seed)
    tape = new_private_tape(D, B, F, min(a, s + 6))
    scalar = int.from_bytes(hashlib.shake_256(b"scalar/" + source_seed).digest((a + 7) // 8), "big") % (1 << a)
    start = time.time()
    x, details = sample_vector(y, a, s, F, seed, tape, B)
    payload = pack_ciphertext(scalar, x, seed, a, F, B)
    assert unpack_ciphertext(payload, D, a, F, B) == (scalar, x, seed)
    expected = ((D + 1) * a - (D // B) * sum(map(len, F)) + 256 + 7) // 8
    assert len(payload) == expected
    checks = 0
    for block in range(D // B):
        w = [v % (1 << a) for v in integer_transform(x[block * B:(block + 1) * B], inverse=True)]
        for l, frozen in enumerate(F):
            expected_f = public_frozen_bits(seed, block, l + 1, len(frozen))
            for j, bit in zip(frozen, expected_f):
                assert ((w[j] >> l) & 1) == bit
                checks += 1
    (case / "ciphertext.bin").write_bytes(payload)
    (case / "private_random_tape.bin").write_bytes(tape)
    # Re-run the actual SC quantizer from saved bytes, not just re-pack x.
    replay_x, replay_details = sample_vector(y, a, s, F, seed,
        (case / "private_random_tape.bin").read_bytes(), B)
    replay_payload = pack_ciphertext(scalar, replay_x, seed, a, F, B)
    assert replay_payload == (case / "ciphertext.bin").read_bytes()
    assert replay_details == details
    result = {"source_kind": kind, "public_seed": seed.hex(), "source_seed": source_seed.hex(),
        "q_bits": a, "S_bits": s, "executed_dimension": D, "block_dimension": B,
        "full_certificate_dimension": p["D"], "raw_bytes": ((D + 1) * a + 7) // 8,
        "actual_serialized_bytes": len(payload), "exact_roundtrip": True,
        "saved_tape_SC_replay_byte_identical": True, "coefficient_seed_bit_checks": checks,
        "sha256": sha(case / "ciphertext.bin"), "tape_sha256": sha(case / "private_random_tape.bin"),
        "details": details, "seconds_including_replay": time.time() - start,
        "scalar_is_test_value": True, "source_is_actual_FMAH": False,
        "full_IBE_encryption_executed": False, "empirical_DFR_claim": False}
    (case / "case.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--recommendation", type=Path,
        default=Path(__file__).resolve().parents[1] / "analysis/parameters/recommendation.json",
        help="Read the recommended row from a parameter recommendation JSON.")
    parser.add_argument("--kinds", nargs="+", default=["zero", "uniform", "identity_graph"])
    args = parser.parse_args()
    # Refuse an existing run directory before writing anything, preserving old records.
    args.output.mkdir(parents=True, exist_ok=False)
    certificates = args.recommendation.resolve()
    previous = json.loads(certificates.read_text())
    row = previous["recommended"]
    p, cert = row["parameters"], row["polar"]
    h = lattice_exponents(p["q_bits"], cert["frozen_sets"], 256)
    assert sum(h) == cert["frozen_bits_per_block"]
    output = {"scope": "Construction-D coefficient codec; 512D executed pilots, inherited full-D analytic certificate",
        "command": sys.argv, "python_version": platform.python_version(),
        "source_sha256": {str(path): sha(path) for path in [Path(__file__),
            Path(__file__).with_name("integer_polar_codec.py"), Path(__file__).with_name("test_integer_polar_codec.py"),
            VENDOR / "polar_codec.py", VENDOR / "PROVENANCE.json", certificates]},
        "selected_recommendation": str(certificates),
        "vendored_helper_provenance": json.loads((VENDOR / "PROVENANCE.json").read_text()),
        "exact_tests": exact_tests(), "parameters": p,
        "inherited_polar_certificate": cert, "inherited_finite_kernel": row["finite_kernel"],
        "inheritance_basis": "predictable XOR preserves exact output kernel; same per-coin numerical budget and high-lift tail; new coefficient labels only",
        "lattice_generator": "diag(2^h_j) times integer F^(tensor 8), independently on each block",
        "lattice_exponents_per_block": h, "pilots": [],
        "full_dimension_quantization_executed": False, "complete_IBE_security_certified": False}
    report = args.output / "validation.json"
    report.write_text(json.dumps(output, indent=2) + "\n")
    for kind in args.kinds:
        result = pilot(row, args.output, kind)
        output["pilots"].append(result)
        report.write_text(json.dumps(output, indent=2) + "\n")
        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
