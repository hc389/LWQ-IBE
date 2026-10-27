"""Executable finite stochastic multilevel polar quantizer, with Arb intervals.

Run with Sage Python. This is a quantization/codec prototype, NOT a complete
IBE implementation. The source can be arbitrary; exact SC targets an additive
wrapped integer Gaussian. No additive Gaussian vector is sampled afterward.
Frozen bits use a public SHAKE seed (a practical instantiation of the separate
classical random-oracle compiler, not an information-theoretic PRG claim).
"""
from __future__ import annotations

import hashlib
import os
from fractions import Fraction
from functools import lru_cache
from sage.all import RealBallField


class PrecisionNeeded(Exception):
    pass


def validate_layout(q_bits, frozen_sets, block_length):
    if q_bits < 1 or block_length < 1 or block_length & (block_length - 1):
        raise ValueError("positive q_bits and power-of-two block length required")
    if len(frozen_sets) != q_bits:
        raise ValueError("one frozen-index list is required for every q bit")
    for F in frozen_sets:
        if len(set(F)) != len(F) or any(not isinstance(i, int) or i < 0 or i >= block_length for i in F):
            raise ValueError("frozen indices must be unique and in range")


def transform(bits):
    """Row-vector F^(tensor log2 N); no bit reversal; self-inverse over F2."""
    out = list(bits)
    n = len(out)
    if n < 1 or n & (n - 1):
        raise ValueError("power-of-two nonzero length required")
    stride = 1
    while stride < n:
        for base in range(0, n, 2 * stride):
            for j in range(stride):
                out[base + j] ^= out[base + stride + j]
        stride *= 2
    return out


def sc_decode(prob_zero, choose, offset=0):
    """Stochastic SC. choose(index, posterior_p0) supplies frozen/info bits.

    This recursion depends only on already sampled bits, never future frozen
    bits. Works on both exact Fractions (tests) and certified real balls.
    Returns the sampled u and its transformed coordinate digits x.
    """
    n = len(prob_zero)
    if n == 1:
        bit = choose(offset, prob_zero[0])
        return [bit], [bit]
    h = n // 2
    left, right = prob_zero[:h], prob_zero[h:]
    minus = [p * r + (1 - p) * (1 - r) for p, r in zip(left, right)]
    ul, xl = sc_decode(minus, choose, offset)
    plus = []
    for p, r, parity in zip(left, right, xl):
        if parity == 0:
            numerator, other = p * r, (1 - p) * (1 - r)
        else:
            numerator, other = (1 - p) * r, p * (1 - r)
        denom = numerator + other
        if hasattr(denom, "contains_zero") and denom.contains_zero():
            raise PrecisionNeeded("SC denominator interval contains zero")
        if denom == 0:
            raise ValueError("zero-probability prefix")
        plus.append(numerator / denom)
    ur, xr = sc_decode(plus, choose, offset + h)
    return ul + ur, [a ^ b for a, b in zip(xl, xr)] + xr


class UniformTape:
    """Saved independent OS random bits, also usable for exact replay.

    At most one 256-bit grid draw per non-frozen bit through stop_bits.
    A certified lower probability threshold incurs TV at most
    2^-256 + 2^-300 per draw versus an ideal coin, including exact ties.
    """
    def __init__(self, data, coin_bits=256):
        if coin_bits % 8:
            raise ValueError("byte-aligned coin width required")
        self.data = data
        self.coin_bits = coin_bits
        self.offset = 0

    def choose(self, p_zero, field):
        lower, upper = p_zero.lower(), p_zero.upper()
        width = field(upper) - field(lower)
        if not width <= field(2) ** -300:
            raise PrecisionNeeded("posterior enclosure wider than certified budget")
        count = self.coin_bits // 8
        raw = self.data[self.offset:self.offset + count]
        if len(raw) != count:
            raise ValueError("private randomness exhausted")
        self.offset += count
        u = field(int.from_bytes(raw, "big")) / field(1 << self.coin_bits)
        # Both endpoints here are exact dyadics in MPFR. An equality is
        # deliberately sent to bit 1; strict interval separation is not
        # required (it would fail forever when u=p=1/2 exactly).
        assert u.lower() == u.upper()
        return 0 if u.lower() < lower else 1


@lru_cache(maxsize=32768)
def wrapped_weight(z, layer, width_bits, precision):
    """Interval proportional to the exact wrapped Gaussian residue weight.

    Fourier/spatial series tails are explicitly enclosed; there is no silently
    truncated likelihood and no double-precision Bernoulli threshold.
    """
    R = RealBallField(precision)
    M, S = 1 << layer, 1 << width_bits
    z = ((int(z) + M // 2) % M) - M // 2
    pi = R.pi()
    relative_goal = R(2) ** (-precision - 24)
    if S >= M:
        ratio2 = R(S * S) / R(M * M)
        theta = R(2) * pi * R(z) / R(M)
        weight = R(1)
        K = 0
        while True:
            # All omitted |k|>=K+1; successive squared exponents differ by
            # at least 2K+3. Divide out S/M, common to both binary weights.
            tail = 2 * (-pi * ratio2 * (K + 1) ** 2).exp()
            tail /= 1 - (-pi * ratio2 * (2 * K + 3)).exp()
            if tail < relative_goal:
                return weight.add_error(tail)
            k = K + 1
            weight += 2 * (-pi * ratio2 * k * k).exp() * (theta * k).cos()
            K += 1
    else:
        invratio2 = R(M * M) / R(S * S)
        center = R(z) / R(M)
        leading = (-pi * invratio2 * center * center).exp()
        weight = leading
        K = 0
        while True:
            # |z/M|<=1/2: omitted terms start at K+1/2; the ratio
            # between consecutive tail terms is at most exp(-c(2K+2)).
            tail = 2 * (-pi * invratio2 * R(2 * K + 1) ** 2 / 4).exp()
            tail /= 1 - (-pi * invratio2 * (2 * K + 2)).exp()
            if tail < relative_goal * leading:
                return weight.add_error(tail)
            k = K + 1
            weight += (-pi * invratio2 * (center + k) ** 2).exp()
            weight += (-pi * invratio2 * (center - k) ** 2).exp()
            K += 1


def binary_posterior(z, layer, width_bits, precision):
    M = 1 << layer
    p = wrapped_weight(z % M, layer, width_bits, precision)
    r = wrapped_weight((z - M // 2) % M, layer, width_bits, precision)
    denominator = p + r
    if denominator.contains_zero():
        raise PrecisionNeeded("partition likelihood interval contains zero")
    return p / denominator


def public_frozen_bits(seed, block_index, layer, count):
    # Compatibility domain bytes retained for replay of recorded fixtures.
    domain = bytes.fromhex("51526552616e642d706f6c61722d70726f746f747970652d76312f66726f7a656e2f")
    domain += block_index.to_bytes(8, "big") + layer.to_bytes(4, "big")
    raw = hashlib.shake_256(domain + seed).digest((count + 7) // 8)
    return [(raw[i // 8] >> (7 - i % 8)) & 1 for i in range(count)]


def sample_block(source, q_bits, width_bits, frozen_sets, seed, block_index,
                 tape_data, precision=384, coin_bits=256):
    """Return X and diagnostics. Gaussian reference matching is conditional.

    All high information digits are sent, including those obtained by the
    nearest consistent lift. Only sampling work, NOT payload size, is skipped.
    """
    B, q = len(source), 1 << q_bits
    validate_layout(q_bits, frozen_sets, B)
    if width_bits < 0 or len(seed) != 32:
        raise ValueError("nonnegative width_bits and 256-bit seed required")
    R = RealBallField(precision)
    stop = min(q_bits, width_bits + 6)
    if any(frozen_sets[stop:]):
        raise ValueError("cannot lift across a frozen layer")
    x_low = [0] * B
    tape = UniformTape(tape_data, coin_bits)
    mixed_layers = 0
    for index in range(stop):
        layer = index + 1
        F = frozen_sets[index]
        frozen = dict(zip(F, public_frozen_bits(seed, block_index, layer, len(F))))
        if len(F) == B:
            u = [frozen[j] for j in range(B)]
            x_digit = transform(u)
        else:
            posterior = [binary_posterior(y - x, layer, width_bits, precision)
                         for y, x in zip(source, x_low)]
            if not F:
                # When every u is information, independent coordinate
                # sampling is exactly the same joint distribution as SC.
                x_digit = [tape.choose(p, R) for p in posterior]
            else:
                mixed_layers += 1
                def choose(j, p):
                    return frozen[j] if j in frozen else tape.choose(p, R)
                _, x_digit = sc_decode(posterior, choose)
        x_low = [x + (digit << index) for x, digit in zip(x_low, x_digit)]
    if stop == q_bits:
        result = x_low
    else:
        step = 1 << stop
        # Residual in [-step/2, step/2), nearest to y; fixed lower tie rule.
        result = [(int(y) + ((x - int(y) + step // 2) % step) - step // 2) % q
                  for x, y in zip(x_low, source)]
    return result, {"precision_bits": precision, "private_draws": tape.offset // (coin_bits // 8),
                    "stop_bits": stop, "mixed_SC_layers": mixed_layers,
                    "posterior_enclosures_all_within_2pow_minus300": True}


def sample_vector(source, q_bits, width_bits, frozen_sets, seed, tape_data,
                  block_length=256):
    validate_layout(q_bits, frozen_sets, block_length)
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


class BitWriter:
    def __init__(self):
        self.output = bytearray()
        self.accumulator = self.count = self.total_bits = 0

    def write(self, value, width):
        if value < 0 or value >= (1 << width):
            raise ValueError("field out of range")
        self.accumulator = (self.accumulator << width) | value
        self.count += width
        self.total_bits += width
        while self.count >= 8:
            self.count -= 8
            self.output.append((self.accumulator >> self.count) & 255)
        self.accumulator &= (1 << self.count) - 1

    def finish(self):
        if self.count:
            self.output.append(self.accumulator << (8 - self.count))
        return bytes(self.output)


class BitReader:
    def __init__(self, data):
        self.data, self.position = data, 0

    def read(self, width):
        result = 0
        for _ in range(width):
            if self.position >= 8 * len(self.data):
                raise ValueError("short payload")
            result = (result << 1) | ((self.data[self.position // 8] >> (7 - self.position % 8)) & 1)
            self.position += 1
        return result


def pack_ciphertext(scalar, vector, seed, q_bits, frozen_sets, block_length=256):
    """Exactly one a-bit scalar + 256-bit public seed + all information bits."""
    validate_layout(q_bits, frozen_sets, block_length)
    if len(seed) != 32 or not vector or len(vector) % block_length:
        raise ValueError("bad seed or block layout")
    if any(x < 0 or x >= (1 << q_bits) for x in vector):
        raise ValueError("vector coordinate outside Z_q")
    writer = BitWriter()
    writer.write(scalar, q_bits)
    writer.write(int.from_bytes(seed, "big"), 256)
    for block_index in range(len(vector) // block_length):
        block = vector[block_index * block_length:(block_index + 1) * block_length]
        for index, F in enumerate(frozen_sets):
            u = transform([(x >> index) & 1 for x in block])
            frozen = dict(zip(F, public_frozen_bits(seed, block_index, index + 1, len(F))))
            for j, bit in enumerate(u):
                if j in frozen:
                    if bit != frozen[j]:
                        raise ValueError("vector is inconsistent with public frozen seed")
                else:
                    writer.write(bit, 1)
    return writer.finish()


def unpack_ciphertext(payload, dimension, q_bits, frozen_sets, block_length=256):
    validate_layout(q_bits, frozen_sets, block_length)
    if dimension < 1 or dimension % block_length:
        raise ValueError("positive block-aligned dimension required")
    reader = BitReader(payload)
    scalar = reader.read(q_bits)
    seed = reader.read(256).to_bytes(32, "big")
    vector = []
    for block_index in range(dimension // block_length):
        block = [0] * block_length
        for index, F in enumerate(frozen_sets):
            frozen = dict(zip(F, public_frozen_bits(seed, block_index, index + 1, len(F))))
            u = [frozen[j] if j in frozen else reader.read(1) for j in range(block_length)]
            digit = transform(u)
            block = [x + (b << index) for x, b in zip(block, digit)]
        vector.extend(block)
    if len(payload) != (reader.position + 7) // 8:
        raise ValueError("unexpected trailing bytes")
    if reader.position % 8 and payload[-1] & ((1 << (8 - reader.position % 8)) - 1):
        raise ValueError("non-canonical padding")
    return scalar, vector, seed


def new_private_tape(dimension, block_length, frozen_sets, stop_bits):
    draws = (dimension // block_length) * sum(block_length - len(F) for F in frozen_sets[:stop_bits])
    return os.urandom(draws * 32)


def exact_sc_tests():
    """Exhaustively compare every conditional to an independent product law."""
    checked = 0
    for B in (2, 4, 8):
        ps = [Fraction((j * 2 + 1) % 7 + 1, 9) for j in range(B)]
        words, weights = [], []
        for value in range(1 << B):
            u = [(value >> (B - 1 - j)) & 1 for j in range(B)]
            x = transform(u)
            assert transform(x) == u
            weight = Fraction(1)
            for p, b in zip(ps, x):
                weight *= p if b == 0 else 1 - p
            words.append(u)
            weights.append(weight)
        assert sum(weights) == 1
        for wanted in words:
            prefix = []
            def choose(j, posterior):
                nonlocal checked
                valid = [(u, w) for u, w in zip(words, weights) if u[:j] == prefix]
                expected = sum(w for u, w in valid if u[j] == 0) / sum(w for _, w in valid)
                assert posterior == expected, (B, j, prefix, posterior, expected)
                bit = wanted[j]
                prefix.append(bit)
                checked += 1
                return bit
            u, x = sc_decode(ps, choose)
            assert u == wanted and x == transform(wanted)
    return {"exact_fraction_posterior_comparisons": checked, "lengths": [2, 4, 8]}


if __name__ == "__main__":
    import json
    print(json.dumps(exact_sc_tests(), indent=2))
