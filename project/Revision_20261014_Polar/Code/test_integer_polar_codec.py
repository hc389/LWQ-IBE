"""Independent exact finite checks for the changed mathematical interface."""
from collections import defaultdict
from fractions import Fraction
from itertools import product
import json
from integer_polar_codec import (integer_transform, transform, lattice_exponents,
                                 validate_lattice_layout)


def labels(x, a, integer):
    q = 1 << a
    if integer:
        w = [v % q for v in integer_transform(x, inverse=True)]
        return tuple((v >> l) & 1 for l in range(a) for v in w)
    return tuple(b for l in range(a) for b in transform([(v >> l) & 1 for v in x]))


def exact_kernel(xwords, weights, a, B, frozen, integer):
    codes = [labels(x, a, integer) for x in xwords]
    prefixes = defaultdict(Fraction)
    for code, w in zip(codes, weights):
        for k in range(a * B + 1):
            prefixes[code[:k]] += w
    result = []
    for code in codes:
        mass = Fraction(1)
        for k, bit in enumerate(code):
            mass *= Fraction(1, 2) if k % B in frozen[k // B] else prefixes[code[:k + 1]] / prefixes[code[:k]]
        result.append(mass)
    assert sum(result) == 1
    return result


def run():
    inverse_checks = prefix_checks = kernel_checks = coset_checks = 0
    for B, a in [(1, 3), (2, 3), (4, 2)]:
        q = 1 << a
        words = list(product(range(q), repeat=B))
        for x in words:
            assert integer_transform(integer_transform(x), inverse=True) == list(x)
            raw, coef = labels(x, a, False), labels(x, a, True)
            w_low = [0] * B
            for l in range(a):
                carry = transform([(v >> l) & 1 for v in integer_transform(w_low)])
                assert list(raw[l * B:(l + 1) * B]) == [v ^ b for v, b in zip(coef[l * B:(l + 1) * B], carry)]
                w_low = [v + (b << l) for v, b in zip(w_low, coef[l * B:(l + 1) * B])]
                prefix_checks += B
            inverse_checks += 1
        frozen = [[0] for _ in range(a)] if B > 1 else [[0]] + [[] for _ in range(a - 1)]
        # Positive, nonuniform rational additive channel; it need not be Gaussian
        # because the predictable-XOR identity is channel-independent.
        noise = [Fraction(j + 1, q * (q + 1) // 2) for j in range(q)]
        for y in [tuple(0 for _ in range(B)), tuple((3 * j + 1) % q for j in range(B))]:
            weights = []
            for x in words:
                weight = Fraction(1)
                for xx, yy in zip(x, y):
                    weight *= noise[(yy - xx) % q]
                weights.append(weight)
            old = exact_kernel(words, weights, a, B, frozen, False)
            new = exact_kernel(words, weights, a, B, frozen, True)
            assert old == new
            kernel_checks += len(words)
        h = lattice_exponents(a, frozen, B)
        groups = defaultdict(list)
        for x in words:
            w = [v % q for v in integer_transform(x, inverse=True)]
            groups[tuple(v % (1 << hh) for v, hh in zip(w, h))].append(x)
        zero = set(groups[tuple(0 for _ in range(B))])
        assert len(groups) == 1 << sum(h)
        for f, members in groups.items():
            shift = integer_transform(f)
            assert {tuple((v - d) % q for v, d in zip(x, shift)) for x in members} == zero
            coset_checks += 1
        for x, y in product(zero, repeat=2):
            assert tuple((xx + yy) % q for xx, yy in zip(x, y)) in zero
    # Explicit raw-digit counterexample, even with nested information sets.
    x, y = (1, 1, 0, 0), (1, 0, 1, 0)
    z = tuple((xx + yy) % 4 for xx, yy in zip(x, y))
    frozen = [[0], [0]]
    allowed = lambda v: all(labels(v, 2, False)[l * 4] == 0 for l in range(2))
    assert allowed(x) and allowed(y) and not allowed(z)
    try:
        validate_lattice_layout(2, [[], [0]], 2)
        raise AssertionError("nonnested frozen sets accepted")
    except ValueError:
        pass
    return {"integer_inverse_checks": inverse_checks, "predictable_xor_bit_checks": prefix_checks,
            "exact_fraction_output_kernel_equalities": kernel_checks,
            "exhaustive_lattice_cosets_checked": coset_checks,
            "raw_digit_nonlattice_counterexample": {"x": x, "y": y, "sum_mod4": z},
            "nested_layout_rejection": True,
            "scope": "exact small finite algebra/distribution checks, not IBE security"}


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
