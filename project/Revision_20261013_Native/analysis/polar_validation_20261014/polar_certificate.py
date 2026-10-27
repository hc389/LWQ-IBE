"""Conservative frozen-set certificate for exact stochastic binary polar SC.

The certificate concerns Gaussian matching, not an entire IBE security proof.
Only Decimal is required.  Directed rounding, 3 < pi < 22/7, and ln(2)<7/10
make all reported errors upper bounds for the explicitly stated exact model.
See frozen_certificate.md for derivations and limits of the certificate.
"""

from __future__ import annotations

import argparse
import json
from decimal import Context, Decimal, ROUND_CEILING, ROUND_FLOOR, ROUND_HALF_EVEN


class Outward:
    def __init__(self, precision: int = 110):
        common = dict(prec=precision, Emin=-999999999, Emax=999999999)
        self.up = Context(rounding=ROUND_CEILING, **common)
        self.down = Context(rounding=ROUND_FLOOR, **common)
        self.near = Context(rounding=ROUND_HALF_EVEN, **common)
        self.zero, self.one, self.two = map(Decimal, (0, 1, 2))

    def exp_upper(self, x: Decimal) -> Decimal:
        # Decimal.exp is correctly rounded (half-even); one adjacent number
        # outward therefore encloses the exact transcendental result.
        return self.near.next_plus(self.near.exp(x))

    def exp_lower(self, x: Decimal) -> Decimal:
        return max(self.zero, self.near.next_minus(self.near.exp(x)))

    def sqrt_lower(self, x: Decimal) -> Decimal:
        if x <= 0:
            return self.zero
        return max(self.zero, self.near.next_minus(self.near.sqrt(x)))

    def sqrt_upper(self, x: Decimal) -> Decimal:
        if x == 0:
            return self.zero
        return self.near.next_plus(self.near.sqrt(x))

    def square(self, x: Decimal) -> Decimal:
        return self.up.multiply(x, x)

    def capacity_cost(self, d: Decimal) -> Decimal:
        """Upper bound 1-Z^2 when d is an upper bound on 1-Z."""
        return min(self.one, self.up.multiply(d, self.up.subtract(self.two, d)))

    def deficit_from_bias(self, b: Decimal) -> Decimal:
        if b >= 1:
            return self.one
        b2 = self.square(b)
        rad = self.down.subtract(self.one, b2)
        denom = self.down.add(self.one, self.sqrt_lower(rad))
        return min(self.one, self.up.divide(b2, denom))

    def base_deficit(self, layer: int, width: Decimal) -> Decimal:
        """Upper bound 1-Z for 2^(layer-1) Z / 2^layer Z.

        Higher binary digits are marginalized, lower ones are conditioned on.
        S/2^layer >=16 is clipped to16, losing tightness but retaining validity.
        """
        modulus = Decimal(1 << layer)
        ratio = min(Decimal(16), self.down.divide(width, modulus))
        r2 = self.down.multiply(ratio, ratio)
        exponent = self.down.multiply(Decimal(3), r2).copy_negate()
        t = self.exp_upper(exponent)  # exp(-pi*r^2) <= exp(-3*r^2).
        t2 = self.square(t)
        t4 = self.square(t2)
        t8 = self.square(t4)
        t12 = self.up.multiply(t8, t4)
        odd_denom = self.down.subtract(self.one, t8)
        even_denom = self.down.subtract(self.one, t12)
        fourier_d = self.one
        if odd_denom > 0 and even_denom > 0:
            odd = self.up.divide(self.up.multiply(self.two, t), odd_denom)
            even = self.up.divide(self.up.multiply(self.two, t4), even_denom)
            bias_denom = self.down.subtract(self.one, even)
            if bias_denom > 0:
                bias = self.up.divide(odd, bias_denom)
                fourier_d = self.deficit_from_bias(bias)

        # Wrapping cannot decrease Bhattacharyya overlap.  When layer>=2,
        # half the shift 2^(layer-1) is integral, so the discrete-Gaussian
        # normalizers cancel exactly.  Z >= exp(-pi/(16*r^2)).
        overlap_d = self.one
        if layer >= 2 and r2 > 0:
            denominator = self.down.multiply(Decimal(112), r2)
            arg = self.up.divide(Decimal(22), denominator)
            if arg <= 10000:  # Otherwise use the valid but trivial Z>=0.
                z_lower = self.exp_lower(arg.copy_negate())
                overlap_d = min(self.one, self.up.subtract(self.one, z_lower))
        return min(fourier_d, overlap_d)

    def polar_children(self, d: Decimal) -> tuple[Decimal, Decimal]:
        # Z+ = Z^2; Z- >= Z*sqrt(2-Z^2).  A cancellation-free version is
        # d- <= c^2 / (1+sqrt(1-c^2)), where c=2*d-d^2.
        c = self.capacity_cost(d)
        c2 = self.square(c)
        rad = self.down.subtract(self.one, c2)
        denom = self.down.add(self.one, self.sqrt_lower(rad))
        minus = min(self.one, self.up.divide(c2, denom))
        return minus, c

    def polarized_deficits(self, d: Decimal, block_length: int) -> list[Decimal]:
        current = [d]
        while len(current) < block_length:
            current = [child for x in current for child in self.polar_children(x)]
        return current


def certify_frozen_sets(
    q_bits: int,
    block_length: int,
    gaussian_width: int | str | Decimal,
    security_bits: int = 160,
    total_dimension: int | None = None,
    seed_bits: int = 256,
    precision: int = 110,
) -> dict:
    """Return repeatable block frozen sets and a rigorous exact-model TV bound.

    gaussian_width is S in exp(-pi*x*x/S**2), not the standard deviation.
    total_dimension defaults to block_length and must be a positive multiple.
    Frozen indices are zero-based Arikan path order, '- then +' at each step.
    The decoder must use the identical polar transform / index convention.
    """
    if q_bits < 1 or block_length < 1 or block_length & (block_length - 1):
        raise ValueError("q_bits>=1 and block_length a positive power of two required")
    total_dimension = block_length if total_dimension is None else total_dimension
    if total_dimension < 1 or total_dimension % block_length:
        raise ValueError("total_dimension must be a positive multiple of block_length")
    if seed_bits < 0 or precision < 30:
        raise ValueError("seed_bits must be nonnegative and precision at least 30")
    if isinstance(gaussian_width, float):
        raise TypeError("Pass an exact integer, Decimal, or decimal string width")
    width = Decimal(gaussian_width)
    if width <= 0 or not width.is_finite() or security_bits < 1:
        raise ValueError("finite positive width and security_bits>=1 required")
    ar = Outward(precision)
    repeats = total_dimension // block_length
    candidates = []
    base_bounds = []
    for layer in range(1, q_bits + 1):
        d0 = ar.base_deficit(layer, width)
        base_bounds.append(str(d0))
        for bit, d in enumerate(ar.polarized_deficits(d0, block_length)):
            block_cost = ar.capacity_cost(d)
            global_cost = ar.up.multiply(Decimal(repeats), block_cost)
            candidates.append((global_cost, layer - 1, bit))
    # TV^2 <= (ln2/2)*sum(1-Z_i^2) < (7/20)*sum(cost_i).
    target_squared = ar.down.divide(Decimal(1), Decimal(1 << (2 * security_bits)))
    budget = ar.down.divide(ar.down.multiply(Decimal(20), target_squared), Decimal(7))
    total_cost = Decimal(0)
    frozen_sets = [[] for _ in range(q_bits)]
    for cost, layer, bit in sorted(candidates):
        new_cost = ar.up.add(total_cost, cost)
        if new_cost > budget:
            break
        total_cost = new_cost
        frozen_sets[layer].append(bit)
    for row in frozen_sets:
        row.sort()
    counts = [len(row) for row in frozen_sets]
    frozen_per_block = sum(counts)
    frozen_total = repeats * frozen_per_block
    raw_bits = (total_dimension + 1) * q_bits
    compressed_bits = raw_bits - frozen_total + seed_bits
    raw_bytes, compressed_bytes = (raw_bits + 7) // 8, (compressed_bits + 7) // 8
    tv_squared = ar.up.divide(ar.up.multiply(Decimal(7), total_cost), Decimal(20))
    tv_bound = ar.sqrt_upper(tv_squared)
    return {
        "certificate_scope": "exact posterior SC, independent fair frozen bits; not complete IBE security",
        "q_bits": q_bits,
        "block_length": block_length,
        "total_dimension": total_dimension,
        "block_repetitions": repeats,
        "gaussian_width": str(width),
        "requested_tv_bits": security_bits,
        "global_tv_upper": str(tv_bound),
        "global_entropy_cost_upper": str(total_cost),
        "global_entropy_cost_budget_lower": str(budget),
        "base_deficit_upper": base_bounds,
        "frozen_sets": frozen_sets,
        "per_level_frozen": counts,
        "partial_levels": [i + 1 for i, n in enumerate(counts) if 0 < n < block_length],
        "fully_frozen_levels": [i + 1 for i, n in enumerate(counts) if n == block_length],
        "frozen_bits_per_block": frozen_per_block,
        "frozen_bits_total": frozen_total,
        "information_bits_per_block": q_bits * block_length - frozen_per_block,
        "seed_bits": seed_bits,
        "raw_bits": raw_bits,
        "compressed_bits": compressed_bits,
        "raw_bytes": raw_bytes,
        "compressed_bytes": compressed_bytes,
        "complete_byte_saving_fraction": (raw_bytes - compressed_bytes) / raw_bytes,
        "nested_frozen_sets": all(set(frozen_sets[i + 1]).issubset(frozen_sets[i]) for i in range(q_bits - 1)),
        "rounding": "Decimal outward enclosures; pi lower 3 / upper 22/7; ln2 upper 7/10",
        "precision_decimal_digits": precision,
    }


def completion_tail_upper(
    total_dimension: int,
    gaussian_width: int | str | Decimal,
    stop_bits: int,
    precision: int = 110,
) -> str:
    """Upper bound Pr[||E||_infty >= 2^(stop_bits-1)] for integer Gaussian E.

    Combines a monotone-sum / Gaussian-tail integral bound with rho_S(Z)>=S.
    A nearest-consistent high-layer completion has matching error at most
    twice the exact-SC certificate plus this tail (before implementation costs).
    """
    if total_dimension < 1 or stop_bits < 2:
        raise ValueError("positive dimension and stop_bits>=2 required")
    if isinstance(gaussian_width, float):
        raise TypeError("Pass an exact integer, Decimal, or decimal string width")
    width = Decimal(gaussian_width)
    if width <= 0 or not width.is_finite():
        raise ValueError("finite positive width required")
    ar = Outward(precision)
    t_minus_one = Decimal((1 << (stop_bits - 1)) - 1)
    ratio_lower = ar.down.divide(t_minus_one, width)
    square_lower = ar.down.multiply(ratio_lower, ratio_lower)
    exponent = ar.down.multiply(Decimal(3), square_lower).copy_negate()
    prefactor = ar.up.divide(width, ar.down.multiply(Decimal(3), t_minus_one))
    one_coordinate = ar.up.multiply(prefactor, ar.exp_upper(exponent))
    return str(min(Decimal(1), ar.up.multiply(Decimal(total_dimension), one_coordinate)))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--q-bits", type=int, default=24)
    parser.add_argument("--block-length", type=int, default=256)
    parser.add_argument("--width-bits", type=int, default=12)
    parser.add_argument("--total-dimension", type=int, default=2048)
    parser.add_argument("--security-bits", type=int, default=160)
    parser.add_argument("--seed-bits", type=int, default=256)
    parser.add_argument("--include-indices", action="store_true")
    args = parser.parse_args()
    result = certify_frozen_sets(
        q_bits=args.q_bits,
        block_length=args.block_length,
        gaussian_width=1 << args.width_bits,
        security_bits=args.security_bits,
        total_dimension=args.total_dimension,
        seed_bits=args.seed_bits,
    )
    if not args.include_indices:
        result.pop("frozen_sets")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
