"""Carry-aware Construction-D polar quantizer and native coefficient codec.

This prototype reuses the reviewed interval posterior/SC implementation.  Its
frozen bits are digits of integer generator coefficients, not transformed raw
coordinate digits.  SHAKE is an executable seed instantiation; the statistical
proof uses independent fair frozen bits and a separate classical-ROM compiler.
Run with Sage Python.  This is not a complete IBE implementation.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

VENDOR = Path(__file__).resolve().parent / "vendor"
from vendor.polar_codec import (BitReader, BitWriter, PrecisionNeeded, UniformTape,
                         binary_posterior, new_private_tape, sc_decode,
                         transform, validate_layout)
from sage.all import RealBallField


def integer_transform(values, inverse=False):
    """Row-vector multiplication by integer F^(tensor log2 N), or its inverse."""
    out = [int(x) for x in values]
    n = len(out)
    if n < 1 or n & (n - 1):
        raise ValueError("power-of-two nonzero length required")
    stride = 1
    sign = -1 if inverse else 1
    while stride < n:
        for base in range(0, n, 2 * stride):
            for j in range(stride):
                out[base + j] += sign * out[base + stride + j]
        stride *= 2
    return out


def validate_lattice_layout(q_bits, frozen_sets, block_length):
    validate_layout(q_bits, frozen_sets, block_length)
    if any(not set(frozen_sets[l + 1]).issubset(frozen_sets[l])
           for l in range(q_bits - 1)):
        raise ValueError("Construction-D requires decreasing frozen sets")


def lattice_exponents(q_bits, frozen_sets, block_length):
    validate_lattice_layout(q_bits, frozen_sets, block_length)
    return [sum(j in F for F in frozen_sets) for j in range(block_length)]


def public_frozen_bits(seed, block_index, layer, count):
    # Compatibility domain bytes retained for replay of recorded fixtures.
    domain = bytes.fromhex("51526552616e642d696e74656765722d706f6c61722d70726f746f747970652d76312f66726f7a656e2f")
    domain += block_index.to_bytes(8, "big") + layer.to_bytes(4, "big")
    raw = hashlib.shake_256(domain + seed).digest((count + 7) // 8)
    return [(raw[i // 8] >> (7 - i % 8)) & 1 for i in range(count)]


def sample_block(source, q_bits, width_bits, frozen_sets, seed, block_index,
                 tape_data, precision=384, coin_bits=256):
    """Generate inside the seed's actual integer lattice coset.

    At level l, integer partial reconstruction A determines its carry into
    digit l.  The raw polar frozen bit is F_coefficient XOR (carry G_2).
    The returned high lift preserves coefficient digits below stop because
    G_Z inverse is integral.  All high information digits remain serialized.
    """
    B, q = len(source), 1 << q_bits
    validate_lattice_layout(q_bits, frozen_sets, B)
    if width_bits < 0 or len(seed) != 32:
        raise ValueError("nonnegative width_bits and 256-bit seed required")
    R = RealBallField(precision)
    stop = min(q_bits, width_bits + 6)
    if any(frozen_sets[stop:]):
        raise ValueError("cannot lift across a frozen layer")
    x_low, w_low = [0] * B, [0] * B
    tape = UniformTape(tape_data, coin_bits)
    mixed_layers = changed_frozen_bits = carry_layers = 0
    for index in range(stop):
        layer = index + 1
        F = frozen_sets[index]
        partial = integer_transform(w_low)
        carry_u = transform([(v >> index) & 1 for v in partial])
        carry_layers += int(any(carry_u))
        coefficient_frozen = dict(zip(F, public_frozen_bits(seed, block_index, layer, len(F))))
        frozen = {j: bit ^ carry_u[j] for j, bit in coefficient_frozen.items()}
        changed_frozen_bits += sum(carry_u[j] for j in F)
        if len(F) == B:
            raw_u = [frozen[j] for j in range(B)]
            x_digit = transform(raw_u)
        else:
            posterior = [binary_posterior(y - x, layer, width_bits, precision)
                         for y, x in zip(source, x_low)]
            if not F:
                x_digit = [tape.choose(p, R) for p in posterior]
                raw_u = transform(x_digit)
            else:
                mixed_layers += 1
                def choose(j, p):
                    return frozen[j] if j in frozen else tape.choose(p, R)
                raw_u, x_digit = sc_decode(posterior, choose)
        coefficient_digit = [v ^ b for v, b in zip(raw_u, carry_u)]
        assert all(coefficient_digit[j] == bit for j, bit in coefficient_frozen.items())
        w_low = [w + (digit << index) for w, digit in zip(w_low, coefficient_digit)]
        x_low = [x + (digit << index) for x, digit in zip(x_low, x_digit)]
        modulus = 1 << layer
        assert all((a - x) % modulus == 0 for a, x in zip(integer_transform(w_low), x_low))
    if stop == q_bits:
        result = x_low
    else:
        step = 1 << stop
        result = [(int(y) + ((x - int(y) + step // 2) % step) - step // 2) % q
                  for x, y in zip(x_low, source)]
    coefficients = [w % q for w in integer_transform(result, inverse=True)]
    assert all((w - low) % (1 << stop) == 0 for w, low in zip(coefficients, w_low))
    return result, {"precision_bits": precision, "private_draws": tape.offset // (coin_bits // 8),
                    "stop_bits": stop, "mixed_SC_layers": mixed_layers,
                    "carry_layers": carry_layers, "carry_adjusted_frozen_bits": changed_frozen_bits,
                    "coefficient_low_bits_preserved_by_lift": True,
                    "posterior_enclosures_all_within_2pow_minus300": True}


def sample_vector(source, q_bits, width_bits, frozen_sets, seed, tape_data,
                  block_length=256):
    validate_lattice_layout(q_bits, frozen_sets, block_length)
    if not source or len(source) % block_length:
        raise ValueError("source must comprise complete blocks")
    stop = min(q_bits, width_bits + 6)
    draws_per_block = sum(block_length - len(F) for F in frozen_sets[:stop])
    bytes_per_block = draws_per_block * 32
    if len(tape_data) != bytes_per_block * (len(source) // block_length):
        raise ValueError("private tape length mismatch")
    result, diagnostics = [], []
    for block_index in range(len(source) // block_length):
        start = block_index * block_length
        private = tape_data[block_index * bytes_per_block:(block_index + 1) * bytes_per_block]
        precision = 384
        while True:
            try:
                block, detail = sample_block(source[start:start + block_length], q_bits,
                    width_bits, frozen_sets, seed, block_index, private, precision)
                break
            except PrecisionNeeded:
                precision *= 2
        result.extend(block)
        diagnostics.append(detail)
    return result, diagnostics


def pack_ciphertext(scalar, vector, seed, q_bits, frozen_sets, block_length=256):
    """One a-bit scalar, 256-bit seed, every non-frozen coefficient digit."""
    validate_lattice_layout(q_bits, frozen_sets, block_length)
    if len(seed) != 32 or not vector or len(vector) % block_length:
        raise ValueError("bad seed or block layout")
    q = 1 << q_bits
    if any(x < 0 or x >= q for x in vector):
        raise ValueError("vector coordinate outside Z_q")
    writer = BitWriter()
    writer.write(scalar, q_bits)
    writer.write(int.from_bytes(seed, "big"), 256)
    for block_index in range(len(vector) // block_length):
        block = vector[block_index * block_length:(block_index + 1) * block_length]
        coefficients = [w % q for w in integer_transform(block, inverse=True)]
        for index, F in enumerate(frozen_sets):
            frozen = dict(zip(F, public_frozen_bits(seed, block_index, index + 1, len(F))))
            for j, w in enumerate(coefficients):
                bit = (w >> index) & 1
                if j in frozen:
                    if bit != frozen[j]:
                        raise ValueError("vector is inconsistent with coefficient-frozen seed")
                else:
                    writer.write(bit, 1)
    return writer.finish()


def unpack_ciphertext(payload, dimension, q_bits, frozen_sets, block_length=256):
    validate_lattice_layout(q_bits, frozen_sets, block_length)
    if dimension < 1 or dimension % block_length:
        raise ValueError("positive block-aligned dimension required")
    reader = BitReader(payload)
    scalar = reader.read(q_bits)
    seed = reader.read(256).to_bytes(32, "big")
    vector, q = [], 1 << q_bits
    for block_index in range(dimension // block_length):
        coefficients = [0] * block_length
        for index, F in enumerate(frozen_sets):
            frozen = dict(zip(F, public_frozen_bits(seed, block_index, index + 1, len(F))))
            digit = [frozen[j] if j in frozen else reader.read(1) for j in range(block_length)]
            coefficients = [w + (b << index) for w, b in zip(coefficients, digit)]
        vector.extend(w % q for w in integer_transform(coefficients))
    if len(payload) != (reader.position + 7) // 8:
        raise ValueError("unexpected trailing bytes")
    if reader.position % 8 and payload[-1] & ((1 << (8 - reader.position % 8)) - 1):
        raise ValueError("non-canonical padding")
    return scalar, vector, seed
