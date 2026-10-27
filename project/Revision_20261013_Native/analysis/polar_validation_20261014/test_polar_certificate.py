"""Independent finite-channel and outward-bound checks for polar_certificate."""

import itertools
import math

import numpy as np

from polar_certificate import Outward, certify_frozen_sets


def wrapped_gaussian(s, modulus):
    radius = math.ceil(15 * s)
    z = np.arange(-radius, radius + 1)
    weights = np.exp(-math.pi * z.astype(float) ** 2 / s**2)
    p = np.bincount(z % modulus, weights=weights, minlength=modulus)
    return p / p.sum()


def polar_transform(u):
    x = np.asarray(u, dtype=np.int64).copy()
    step = 1
    while step < len(x):
        for start in range(0, len(x), 2 * step):
            x[start : start + step] ^= x[start + step : start + 2 * step]
        step *= 2
    return x


def exact_small_channel(s, layer, n):
    modulus = 1 << layer
    p = wrapped_gaussian(s, modulus)
    ys = np.array(list(itertools.product(range(modulus), repeat=n)))
    us = list(itertools.product((0, 1), repeat=n))
    joint = []
    for u in us:
        x = polar_transform(u) * (modulus // 2)
        joint.append(np.prod(p[(ys - x) % modulus], axis=1) / 2**n)
    joint = np.asarray(joint)
    out = []
    for bit in range(n):
        grouped = joint.reshape(2**bit, 2, 2 ** (n - bit - 1), -1).sum(axis=2)
        z = 2 * np.sqrt(grouped[:, 0, :] * grouped[:, 1, :]).sum()
        entropy = 0.0
        total = grouped.sum(axis=1)
        for b in (0, 1):
            entries = grouped[:, b, :]
            keep = entries > 0
            entropy -= np.sum(entries[keep] * np.log2(entries[keep] / total[keep]))
        out.append((float(z), float(entropy)))
    return out


def main():
    from decimal import Decimal

    ar = Outward()
    base_count = 0
    for s in (1, 2, 3, 4, 8, 16):
        for layer in range(1, 9):
            modulus = 1 << layer
            p = wrapped_gaussian(s, modulus)
            z = np.sqrt(p * np.roll(p, modulus // 2)).sum()
            deficit_bound = float(ar.base_deficit(layer, Decimal(s)))
            assert 1 - z <= deficit_bound + 5e-15, (s, layer, z, deficit_bound)
            base_count += 1
    channel_count = 0
    for s, layer, n in ((1, 1, 2), (1, 2, 4), (2, 3, 4), (3, 3, 4)):
        actual = exact_small_channel(s, layer, n)
        bounds = ar.polarized_deficits(ar.base_deficit(layer, Decimal(s)), n)
        for (z, entropy), d in zip(actual, bounds):
            assert 1 - z <= float(d) + 5e-15, (s, layer, n, z, d)
            assert entropy + 5e-15 >= z * z, (entropy, z)
            channel_count += 1
    a = certify_frozen_sets(24, 256, 4096, total_dimension=2048, precision=110)
    b = certify_frozen_sets(24, 256, 4096, total_dimension=2048, precision=160)
    assert a["frozen_sets"] == b["frozen_sets"]
    assert a["nested_frozen_sets"] and b["nested_frozen_sets"]
    assert Decimal(a["global_tv_upper"]) < Decimal(2) ** -160
    assert a["partial_levels"] == [10, 11, 12]
    assert a["complete_byte_saving_fraction"] > 0.3
    print({"base_channels_checked": base_count, "synthetic_channels_checked": channel_count,
           "precision_agreement": [110, 160], "partial_levels": a["partial_levels"],
           "small_model_saving": a["complete_byte_saving_fraction"], "status": "PASS"})


if __name__ == "__main__":
    main()
