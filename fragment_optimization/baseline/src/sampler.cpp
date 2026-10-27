#include "core.hpp"
#include <flint/arb.h>
#include <flint/arf.h>
#include <flint/fmpz.h>
#include <flint/fmpq.h>
#include <algorithm>
#include <functional>
#include <stdexcept>
#include <utility>

namespace bench {
namespace {

// All likelihoods and all Bernoulli thresholds are certified Arb intervals.
// No double-precision value influences a sample. This research sampler is
// variable-time; it is not a constant-time or deployment-ready implementation.
constexpr unsigned initial_precision = 384;
constexpr unsigned maximum_precision = 1536;
constexpr unsigned coin_bits = 256;
constexpr unsigned enclosure_bits = 300;
constexpr std::uint64_t maximum_proposals = 1000000;

struct PrecisionNeeded : std::runtime_error {
    explicit PrecisionNeeded(const char* text) : std::runtime_error(text) {}
};

struct Ball {
    arb_t value;
    Ball() { arb_init(value); }
    Ball(const Ball& other) { arb_init(value); arb_set(value, other.value); }
    Ball(Ball&& other) noexcept { arb_init(value); arb_swap(value, other.value); }
    Ball& operator=(const Ball& other) { arb_set(value, other.value); return *this; }
    Ball& operator=(Ball&& other) noexcept { arb_swap(value, other.value); return *this; }
    ~Ball() { arb_clear(value); }
};

struct Endpoint {
    arf_t value;
    Endpoint() { arf_init(value); }
    ~Endpoint() { arf_clear(value); }
    Endpoint(const Endpoint&) = delete;
    Endpoint& operator=(const Endpoint&) = delete;
};

Ball integer_ball(const Big& value) {
    fmpz_t f;
    fmpz_init(f);
    fmpz_set_mpz(f, value.get_mpz_t());
    Ball out;
    arb_set_fmpz(out.value, f);
    fmpz_clear(f);
    return out;
}

Ball small_ball(unsigned long value) {
    Ball out;
    arb_set_ui(out.value, value);
    return out;
}

Ball add(const Ball& a, const Ball& b, unsigned prec) {
    Ball out; arb_add(out.value, a.value, b.value, prec); return out;
}
Ball subtract(const Ball& a, const Ball& b, unsigned prec) {
    Ball out; arb_sub(out.value, a.value, b.value, prec); return out;
}
Ball multiply(const Ball& a, const Ball& b, unsigned prec) {
    Ball out; arb_mul(out.value, a.value, b.value, prec); return out;
}
Ball divide(const Ball& a, const Ball& b, unsigned prec) {
    if (!arb_is_positive(b.value)) throw PrecisionNeeded("nonpositive likelihood denominator enclosure");
    Ball out; arb_div(out.value, a.value, b.value, prec); return out;
}
Ball complement(const Ball& a, unsigned prec) {
    Ball out; arb_neg(out.value, a.value); arb_add_ui(out.value, out.value, 1, prec); return out;
}
Ball exp_negative(const Ball& positive, unsigned prec) {
    Ball out;
    arb_neg(out.value, positive.value);
    arb_exp(out.value, out.value, prec);
    return out;
}
Ball scaled(const Ball& value, unsigned long numerator, unsigned shift, unsigned prec) {
    Ball out;
    arb_mul_ui(out.value, value.value, numerator, prec);
    arb_mul_2exp_si(out.value, out.value, -static_cast<slong>(shift));
    return out;
}
Ball pow2_ball(long exponent) {
    Ball out;
    arb_one(out.value);
    arb_mul_2exp_si(out.value, out.value, exponent);
    return out;
}

Big modulo_pow2(const Big& value, unsigned exponent) {
    Big result;
    mpz_fdiv_r_2exp(result.get_mpz_t(), value.get_mpz_t(), exponent);
    return result;
}

unsigned ceil_log2(const Big& positive) {
    if (positive <= 0) throw std::invalid_argument("Gaussian width must be a positive integer");
    Big v = positive - 1;
    return v == 0 ? 0U : static_cast<unsigned>(mpz_sizeinbase(v.get_mpz_t(), 2));
}

std::vector<unsigned> binary_transform(std::vector<unsigned> bits) {
    const std::size_t n = bits.size();
    if (!n || (n & (n - 1))) throw std::invalid_argument("binary transform length is not a power of two");
    for (std::size_t stride = 1; stride < n; stride *= 2)
        for (std::size_t base = 0; base < n; base += 2 * stride)
            for (std::size_t j = 0; j < stride; ++j)
                bits[base + j] ^= bits[base + stride + j];
    return bits;
}

// Strict threshold comparison on exact dyadics. The enclosing interval width
// must first be <= 2^-300. The resulting coin differs from the ideal coin by
// at most 2^-256 + 2^-300, including exact ties. A negative lower endpoint is
// harmless: it accepts no grid values, as required by clipping to [0,1].
unsigned choose_bit(const Ball& probability_zero, Rng& rng, SampleStats& stats, unsigned prec) {
    if (!arb_is_finite(probability_zero.value)) throw PrecisionNeeded("non-finite probability");
    Endpoint lower, upper, width, tolerance, uniform;
    arb_get_interval_arf(lower.value, upper.value, probability_zero.value, prec);
    arf_sub(width.value, upper.value, lower.value, ARF_PREC_EXACT, ARF_RND_UP);
    arf_one(tolerance.value);
    arf_mul_2exp_si(tolerance.value, tolerance.value, -static_cast<slong>(enclosure_bits));
    if (arf_cmp(width.value, tolerance.value) > 0)
        throw PrecisionNeeded("posterior enclosure exceeds 2^-300");
    if (arf_cmp_ui(upper.value, 0) < 0 || arf_cmp_ui(lower.value, 1) > 0)
        throw std::runtime_error("probability interval outside [0,1]");
    std::array<unsigned char, coin_bits / 8> bytes{};
    rng.fill(bytes.data(), bytes.size());
    Big k;
    mpz_import(k.get_mpz_t(), bytes.size(), 1, 1, 1, 0, bytes.data());
    fmpz_t fk;
    fmpz_init(fk);
    fmpz_set_mpz(fk, k.get_mpz_t());
    arf_set_fmpz(uniform.value, fk);
    fmpz_clear(fk);
    arf_mul_2exp_si(uniform.value, uniform.value, -static_cast<slong>(coin_bits));
    ++stats.decisions;
    return arf_cmp(uniform.value, lower.value) < 0 ? 0U : 1U;
}

// Proportional wrapped D_{Z,S} weight at residue z mod 2^layer. In the Fourier
// branch the common S/M factor is removed. Both spatial and Fourier tails are
// enclosed, never silently discarded. S is the exact integer input width.
Ball wrapped_weight(const Big& residue, unsigned layer, const Big& width, unsigned prec) {
    Big modulus = Big(1) << layer;
    Big z = modulo_pow2(residue, layer);
    if (z >= modulus / 2) z -= modulus;
    Ball pi;
    arb_const_pi(pi.value, prec);
    const Ball goal = pow2_ball(-static_cast<long>(prec) - 24);
    if (width >= modulus) {
        Ball ratio = divide(integer_ball(width * width), integer_ball(modulus * modulus), prec);
        Ball c = multiply(pi, ratio, prec);
        Ball theta = divide(multiply(scaled(pi, 2, 0, prec), integer_ball(z), prec),
                            integer_ball(modulus), prec);
        Ball weight = small_ball(1);
        for (unsigned k = 0; k < 4096; ++k) {
            Ball first = exp_negative(scaled(c, (k + 1) * (k + 1), 0, prec), prec);
            Ball ratio_tail = exp_negative(scaled(c, 2 * k + 3, 0, prec), prec);
            Ball tail = divide(scaled(first, 2, 0, prec), complement(ratio_tail, prec), prec);
            if (arb_lt(tail.value, goal.value)) {
                arb_add_error(weight.value, tail.value);
                return weight;
            }
            Ball angle = scaled(theta, k + 1, 0, prec), cosine;
            arb_cos(cosine.value, angle.value, prec);
            weight = add(weight, scaled(multiply(first, cosine, prec), 2, 0, prec), prec);
        }
    } else {
        Ball ratio = divide(integer_ball(modulus * modulus), integer_ball(width * width), prec);
        Ball c = multiply(pi, ratio, prec);
        Ball center = divide(integer_ball(z), integer_ball(modulus), prec);
        Ball leading = exp_negative(multiply(c, multiply(center, center, prec), prec), prec);
        Ball weight = leading;
        for (unsigned k = 0; k < 4096; ++k) {
            Ball first = exp_negative(scaled(c, (2 * k + 1) * (2 * k + 1), 2, prec), prec);
            Ball ratio_tail = exp_negative(scaled(c, 2 * k + 2, 0, prec), prec);
            Ball tail = divide(scaled(first, 2, 0, prec), complement(ratio_tail, prec), prec);
            Ball target = multiply(goal, leading, prec);
            if (arb_lt(tail.value, target.value)) {
                arb_add_error(weight.value, tail.value);
                return weight;
            }
            Ball plus = add(center, small_ball(k + 1), prec);
            Ball minus = subtract(center, small_ball(k + 1), prec);
            weight = add(weight, exp_negative(multiply(c, multiply(plus, plus, prec), prec), prec), prec);
            weight = add(weight, exp_negative(multiply(c, multiply(minus, minus, prec), prec), prec), prec);
        }
    }
    throw std::runtime_error("wrapped Gaussian series iteration limit exceeded");
}

Ball binary_posterior(const Big& residual, unsigned layer, const Big& width, unsigned prec) {
    Ball p = wrapped_weight(residual, layer, width, prec);
    Ball r = wrapped_weight(residual - (Big(1) << (layer - 1)), layer, width, prec);
    return divide(p, add(p, r, prec), prec);
}

using Choice = std::function<unsigned(unsigned, const Ball&)>;
using BinaryWord = std::vector<unsigned>;
using SCResult = std::pair<BinaryWord, BinaryWord>;

// Only the already selected left branch enters the plus-channel posterior.
// In particular, no future frozen value is conditioned on or summed out.
SCResult successive_cancellation(const std::vector<Ball>& posterior,
                                const Choice& choose, unsigned offset, unsigned prec) {
    const std::size_t n = posterior.size();
    if (n == 1) {
        unsigned bit = choose(offset, posterior[0]);
        if (bit > 1) throw std::runtime_error("SC callback returned a non-bit");
        return {{bit}, {bit}};
    }
    const std::size_t half = n / 2;
    std::vector<Ball> minus;
    minus.reserve(half);
    for (std::size_t i = 0; i < half; ++i) {
        const Ball& p = posterior[i];
        const Ball& r = posterior[i + half];
        minus.push_back(add(multiply(p, r, prec),
                            multiply(complement(p, prec), complement(r, prec), prec), prec));
    }
    SCResult left = successive_cancellation(minus, choose, offset, prec);
    std::vector<Ball> plus;
    plus.reserve(half);
    for (std::size_t i = 0; i < half; ++i) {
        const Ball& p = posterior[i];
        const Ball& r = posterior[i + half];
        Ball numerator, other;
        if (!left.second[i]) {
            numerator = multiply(p, r, prec);
            other = multiply(complement(p, prec), complement(r, prec), prec);
        } else {
            numerator = multiply(complement(p, prec), r, prec);
            other = multiply(p, complement(r, prec), prec);
        }
        plus.push_back(divide(numerator, add(numerator, other, prec), prec));
    }
    SCResult right = successive_cancellation(plus, choose, offset + static_cast<unsigned>(half), prec);
    BinaryWord u = left.first;
    u.insert(u.end(), right.first.begin(), right.first.end());
    BinaryWord x;
    x.reserve(n);
    for (std::size_t i = 0; i < half; ++i) x.push_back(left.second[i] ^ right.second[i]);
    x.insert(x.end(), right.second.begin(), right.second.end());
    return {std::move(u), std::move(x)};
}

std::vector<Big> sample_block_at_precision(const std::vector<Big>& source,
                                         const PolarLayout& layout, const Seed& seed,
                                         std::uint64_t block, Rng& rng,
                                         SampleStats& stats, unsigned prec) {
    const unsigned n = layout.N;
    std::vector<Big> x_low(n), w_low(n);
    for (unsigned index = 0; index < layout.stop; ++index) {
        auto partial = integer_transform(w_low);
        BinaryWord carry(n);
        for (unsigned j = 0; j < n; ++j) carry[j] = mpz_tstbit(partial[j].get_mpz_t(), index);
        carry = binary_transform(std::move(carry));
        const auto& frozen = layout.frozen[index];
        const auto public_bits = frozen_bits(seed, block, index + 1, frozen.size());
        std::vector<int> raw_frozen(n, -1);
        for (std::size_t k = 0; k < frozen.size(); ++k)
            raw_frozen[frozen[k]] = static_cast<int>(public_bits[k] ^ carry[frozen[k]]);
        BinaryWord raw_u, x_digit;
        if (frozen.size() == n) {
            raw_u.resize(n);
            for (unsigned j = 0; j < n; ++j) raw_u[j] = static_cast<unsigned>(raw_frozen[j]);
            x_digit = binary_transform(raw_u);
        } else {
            std::vector<Ball> posterior;
            posterior.reserve(n);
            for (unsigned j = 0; j < n; ++j)
                posterior.push_back(binary_posterior(source[j] - x_low[j], index + 1, layout.width, prec));
            if (frozen.empty()) {
                x_digit.reserve(n);
                for (const auto& p : posterior) x_digit.push_back(choose_bit(p, rng, stats, prec));
                raw_u = binary_transform(x_digit);
            } else {
                Choice choose = [&](unsigned j, const Ball& p) {
                    return raw_frozen[j] >= 0 ? static_cast<unsigned>(raw_frozen[j]) : choose_bit(p, rng, stats, prec);
                };
                SCResult sampled = successive_cancellation(posterior, choose, 0, prec);
                raw_u = std::move(sampled.first);
                x_digit = std::move(sampled.second);
            }
        }
        for (unsigned j = 0; j < n; ++j) {
            if (raw_u[j] ^ carry[j]) mpz_setbit(w_low[j].get_mpz_t(), index);
            if (x_digit[j]) mpz_setbit(x_low[j].get_mpz_t(), index);
        }
        // This integer carry invariant is essential to the Construction-D
        // codec; transform(raw coordinate bits) alone is not the codec.
        partial = integer_transform(w_low);
        for (unsigned j = 0; j < n; ++j)
            if (modulo_pow2(partial[j] - x_low[j], index + 1) != 0)
                throw std::runtime_error("integer polar carry invariant failed");
        for (std::size_t k = 0; k < frozen.size(); ++k)
            if (static_cast<unsigned>(mpz_tstbit(w_low[frozen[k]].get_mpz_t(), index)) != public_bits[k])
                throw std::runtime_error("coefficient frozen digit mismatch");
    }
    std::vector<Big> result(n);
    if (layout.stop == layout.a) {
        result = x_low;
    } else {
        Big half_step = Big(1) << (layout.stop - 1);
        for (unsigned j = 0; j < n; ++j) {
            Big residual = modulo_pow2(x_low[j] - source[j] + half_step, layout.stop) - half_step;
            result[j] = modulo_pow2(source[j] + residual, layout.a);
        }
    }
    const auto coefficients = integer_transform(result, true);
    for (unsigned j = 0; j < n; ++j)
        if (modulo_pow2(coefficients[j] - w_low[j], layout.stop) != 0)
            throw std::runtime_error("nearest lift changed frozen coefficient digits");
    return result;
}

void add_statistics(SampleStats& destination, const SampleStats& source) {
    destination.decisions += source.decisions;
    destination.gaussian_proposals += source.gaussian_proposals;
    destination.max_precision = std::max(destination.max_precision, source.max_precision);
}

} // namespace

Big discrete_gaussian(const Big& width, Rng& rng, SampleStats& stats) {
    if (width <= 0 || mpz_sizeinbase(width.get_mpz_t(), 2) > 4096)
        throw std::invalid_argument("integer Gaussian width out of supported range");
    const Rng saved = rng;
    for (unsigned prec = initial_precision; prec <= maximum_precision; prec *= 2) {
        Rng trial = saved;
        SampleStats local;
        local.max_precision = prec;
        stats.max_precision = std::max(stats.max_precision, prec);
        try {
            Ball pi;
            arb_const_pi(pi.value, prec);
            Big radius = 16 * width, count = 2 * radius + 1;
            for (std::uint64_t proposal = 0; proposal < maximum_proposals; ++proposal) {
                Big z = trial.below(count) - radius;
                ++local.gaussian_proposals;
                Ball square_ratio = divide(integer_ball(z * z), integer_ball(width * width), prec);
                Ball acceptance = exp_negative(multiply(pi, square_ratio, prec), prec);
                if (choose_bit(acceptance, trial, local, prec) == 0) {
                    rng = trial;
                    add_statistics(stats, local);
                    return z;
                }
            }
            throw std::runtime_error("Gaussian rejection proposal limit exceeded; no sample emitted");
        } catch (const PrecisionNeeded&) {
            ++stats.retries;
        }
    }
    throw std::runtime_error("Gaussian interval precision exhausted at 1536 bits; no sample emitted");
}

void validate_layout(const PolarLayout& layout) {
    if (!layout.a || layout.a > 4096 || !layout.N || layout.N > 4096 ||
        (layout.N & (layout.N - 1)) || layout.width <= 0 ||
        mpz_sizeinbase(layout.width.get_mpz_t(), 2) > 4096 || layout.frozen.size() != layout.a)
        throw std::invalid_argument("invalid polar dimension, modulus, width, or frozen-level count");
    const unsigned expected_stop = std::min(layout.a, ceil_log2(layout.width) + 6);
    if (layout.stop != expected_stop)
        throw std::invalid_argument("polar stop must equal min(a, ceil(log2(S))+6)");
    std::vector<bool> previous(layout.N, true);
    for (unsigned layer = 0; layer < layout.a; ++layer) {
        std::vector<bool> current(layout.N, false);
        for (unsigned index : layout.frozen[layer]) {
            if (index >= layout.N || current[index] || !previous[index])
                throw std::invalid_argument("frozen sets must be unique, in range, and decreasing");
            current[index] = true;
        }
        if (layer >= layout.stop && !layout.frozen[layer].empty())
            throw std::invalid_argument("nearest lift cannot cross a frozen level");
        previous = std::move(current);
    }
}

std::vector<Big> integer_transform(const std::vector<Big>& values, bool inverse) {
    std::vector<Big> out = values;
    const std::size_t n = out.size();
    if (!n || (n & (n - 1))) throw std::invalid_argument("integer transform length is not a power of two");
    for (std::size_t stride = 1; stride < n; stride *= 2)
        for (std::size_t base = 0; base < n; base += 2 * stride)
            for (std::size_t j = 0; j < stride; ++j) {
                if (inverse) out[base + j] -= out[base + stride + j];
                else out[base + j] += out[base + stride + j];
            }
    return out;
}

std::vector<unsigned> frozen_bits(const Seed& seed, std::uint64_t block,
                                  unsigned layer, std::size_t count) {
    if (count > 4096) throw std::invalid_argument("frozen bit request exceeds block limit");
    // Compatibility domain bytes retained for replay of recorded fixtures.
    const std::string domain = "\x51\x52\x65\x52\x61\x6e\x64\x2d\x69\x6e\x74\x65\x67\x65\x72\x2d\x70\x6f\x6c\x61\x72\x2d\x70\x72\x6f\x74\x6f\x74\x79\x70\x65\x2d\x76\x31\x2f\x66\x72\x6f\x7a\x65\x6e\x2f";
    std::vector<unsigned char> input(domain.begin(), domain.end());
    for (int shift = 56; shift >= 0; shift -= 8) input.push_back(static_cast<unsigned char>(block >> shift));
    for (int shift = 24; shift >= 0; shift -= 8) input.push_back(static_cast<unsigned char>(layer >> shift));
    input.insert(input.end(), seed.begin(), seed.end());
    const auto raw = shake256(input, (count + 7) / 8);
    std::vector<unsigned> bits(count);
    for (std::size_t i = 0; i < count; ++i) bits[i] = (raw[i / 8] >> (7 - i % 8)) & 1;
    return bits;
}

std::vector<Big> polar_sample_block(const std::vector<Big>& source, const PolarLayout& layout,
                                  const Seed& seed, std::uint64_t block, Rng& rng, SampleStats& stats) {
    validate_layout(layout);
    if (source.size() != layout.N) throw std::invalid_argument("polar source block length mismatch");
    for (const auto& value : source)
        if (value < 0 || mpz_sizeinbase(value.get_mpz_t(), 2) > layout.a)
            throw std::invalid_argument("source is not a canonical residue modulo 2^a");
    const Rng saved = rng;
    for (unsigned prec = initial_precision; prec <= maximum_precision; prec *= 2) {
        Rng trial = saved;
        SampleStats local;
        local.max_precision = prec;
        stats.max_precision = std::max(stats.max_precision, prec);
        try {
            auto result = sample_block_at_precision(source, layout, seed, block, trial, local, prec);
            rng = trial;
            add_statistics(stats, local);
            return result;
        } catch (const PrecisionNeeded&) {
            ++stats.retries;
        }
    }
    throw std::runtime_error("polar interval precision exhausted at 1536 bits; no block emitted");
}

bool sampler_selftest() {
    try {
        const unsigned prec = initial_precision;
        std::vector<Big> vector = {-7, 3, Big(1) << 278, -111};
        if (integer_transform(integer_transform(vector), true) != vector) return false;

        Seed seed{};
        for (unsigned j = 0; j < 32; ++j) seed[j] = static_cast<unsigned char>(j);
        const auto bits = frozen_bits(seed, 7, 3, 64);
        const std::array<unsigned char, 8> expected = {0x29,0x07,0x72,0xbf,0x3c,0xe4,0x75,0xd3};
        for (unsigned j = 0; j < 64; ++j)
            if (bits[j] != ((expected[j / 8] >> (7 - j % 8)) & 1U)) return false;

        // At quarter-period symmetry, the exact binary posterior is 1/2 for
        // every positive integer width. Tests exercise both series branches.
        Ball half = pow2_ball(-1);
        for (unsigned width : {1U, 3U, 17U})
            for (unsigned layer : {2U, 4U, 7U}) {
                Ball p = binary_posterior(Big(1) << (layer - 2), layer, Big(width), prec);
                if (!arb_contains(p.value, half.value)) return false;
                Ball mirror = binary_posterior(-(Big(1) << (layer - 2)), layer, Big(width), prec);
                if (!arb_overlaps(p.value, mirror.value)) return false;
            }

        // Independent spatial-sum oracle at non-symmetric residues. These
        // cases include non-power-of-two widths, so rounding S to 2^k fails.
        // For M>=8, S<=17, |z|<=M/2, the omitted |k|>=65 tail is <2^-4000.
        for (unsigned width : {3U, 17U})
            for (unsigned layer : {3U, 5U}) {
                const Big modulus = Big(1) << layer;
                auto direct_weight = [&](Big z) {
                    z = modulo_pow2(z, layer);
                    if (z >= modulus / 2) z -= modulus;
                    Ball total, pi;
                    arb_const_pi(pi.value, prec);
                    for (int k = -64; k <= 64; ++k) {
                        Big residual = z + modulus * k;
                        Ball exponent = multiply(pi, divide(integer_ball(residual * residual),
                                                  integer_ball(Big(width) * width), prec), prec);
                        total = add(total, exp_negative(exponent, prec), prec);
                    }
                    arb_add_error_2exp_si(total.value, -4000);
                    return total;
                };
                Ball p0 = direct_weight(1), p1 = direct_weight(1 - modulus / 2);
                Ball oracle = divide(p0, add(p0, p1, prec), prec);
                Ball actual = binary_posterior(1, layer, Big(width), prec);
                if (!arb_overlaps(actual.value, oracle.value)) return false;
            }

        // Exhaustive N=4 SC test against independently enumerated product
        // probabilities, including all prefixes and all sixteen decisions.
        std::vector<mpq_class> ps = {mpq_class(2,9), mpq_class(4,9), mpq_class(6,9), mpq_class(8,9)};
        std::vector<Ball> probabilities;
        for (const auto& p : ps)
            probabilities.push_back(divide(integer_ball(p.get_num()), integer_ball(p.get_den()), prec));
        for (unsigned wanted = 0; wanted < 16; ++wanted) {
            BinaryWord prefix;
            Choice choose = [&](unsigned index, const Ball& posterior) {
                mpq_class all = 0, zero = 0;
                for (unsigned word = 0; word < 16; ++word) {
                    BinaryWord u(4);
                    for (unsigned j = 0; j < 4; ++j) u[j] = (word >> (3 - j)) & 1;
                    if (!std::equal(prefix.begin(), prefix.end(), u.begin())) continue;
                    auto x = binary_transform(u);
                    mpq_class weight = 1;
                    for (unsigned j = 0; j < 4; ++j) weight *= x[j] ? 1 - ps[j] : ps[j];
                    all += weight;
                    if (!u[index]) zero += weight;
                }
                mpq_class exact = zero / all;
                fmpq_t rational;
                fmpq_init(rational);
                fmpq_set_mpq(rational, exact.get_mpq_t());
                const bool contains = arb_contains_fmpq(posterior.value, rational);
                fmpq_clear(rational);
                if (!contains) throw std::runtime_error("SC conditional differs from exact enumeration");
                unsigned bit = (wanted >> (3 - index)) & 1;
                prefix.push_back(bit);
                return bit;
            };
            const auto result = successive_cancellation(probabilities, choose, 0, prec);
            if (result.first != prefix || binary_transform(result.first) != result.second) return false;
        }

        PolarLayout layout;
        layout.a = 12; layout.N = 4; layout.width = 3; layout.stop = 8;
        layout.frozen.resize(layout.a);
        layout.frozen[0] = {0,1,2,3}; layout.frozen[1] = {0,1}; layout.frozen[2] = {0};
        validate_layout(layout);
        std::vector<Big> source = {4095, 109, 2700, 1};
        Rng rng(seed, "sampler-selftest"), repeat_rng(seed, "sampler-selftest");
        SampleStats stats, repeat_stats;
        auto output = polar_sample_block(source, layout, seed, 2, rng, stats);
        if (output != polar_sample_block(source, layout, seed, 2, repeat_rng, repeat_stats)) return false;
        const auto coefficients = integer_transform(output, true);
        for (unsigned index = 0; index < layout.a; ++index) {
            auto expected_bits = frozen_bits(seed, 2, index + 1, layout.frozen[index].size());
            for (std::size_t k = 0; k < expected_bits.size(); ++k)
                if (static_cast<unsigned>(mpz_tstbit(coefficients[layout.frozen[index][k]].get_mpz_t(), index)) != expected_bits[k])
                    return false;
        }
        if (stats.decisions != 25 || stats.max_precision != initial_precision) return false;

        // Known-answer cross-check against the independently executed Sage
        // integer_polar_codec.py with the identical SHAKE private tape.
        PolarLayout fixture;
        fixture.a = 12; fixture.N = 8; fixture.stop = 9; fixture.width = 8;
        fixture.frozen.resize(12);
        fixture.frozen[0] = {0,1,2,3,4,5,6,7}; fixture.frozen[1] = {0,1,2,3};
        fixture.frozen[2] = {0,1}; fixture.frozen[3] = {0};
        Rng fixture_rng(seed, "sampler-crosscheck");
        SampleStats fixture_stats;
        const std::vector<Big> expected_output = {1,112,2698,4092,3197,2049,39,4000};
        if (polar_sample_block({4095,109,2700,1,3200,2048,36,4000}, fixture,
                               seed, 2, fixture_rng, fixture_stats) != expected_output) return false;
        if (fixture_stats.decisions != 57) return false;
        for (unsigned width : {1U, 3U, 257U}) {
            const Big sample = discrete_gaussian(Big(width), rng, stats);
            if (sample < -Big(16) * width || sample > Big(16) * width) return false;
        }
        auto bad = layout;
        bad.frozen[2] = {3};
        bool rejected = false;
        try { validate_layout(bad); } catch (const std::invalid_argument&) { rejected = true; }
        if (!rejected) return false;
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace bench
