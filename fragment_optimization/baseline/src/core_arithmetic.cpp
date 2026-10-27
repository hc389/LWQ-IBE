#include "core.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace bench {
namespace {
static_assert(GMP_NUMB_BITS == 64 && GMP_NAIL_BITS == 0,
              "This benchmark requires 64-bit GMP without nails");
static_assert(sizeof(std::size_t) <= sizeof(std::uint64_t),
              "Dot-product accumulation assumes at most 64-bit lengths");

void append_u64(std::vector<unsigned char>& out, std::uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) out.push_back(static_cast<unsigned char>(value >> (8 * i)));
}

void require_canonical(const Modulus& modulus, const Word& value) {
    for (std::size_t i = modulus.limbs; i < value.limb.size(); ++i) {
        if (value.limb[i] != 0) throw std::invalid_argument("Noncanonical residue: high limbs are set");
    }
    if (modulus.power_of_two) {
        const unsigned top_bits = modulus.bits % 64;
        if (top_bits && (value.limb[modulus.limbs - 1] >> top_bits))
            throw std::invalid_argument("Noncanonical power-of-two residue");
    } else if (mpn_cmp(value.limb.data(), modulus.qword.limb.data(), modulus.limbs) >= 0) {
        throw std::invalid_argument("Noncanonical residue: value >= q");
    }
}

Word reduce(const Modulus& modulus, const mp_limb_t* value, std::size_t length) {
    Word result;
    while (length && value[length - 1] == 0) --length;
    if (!length) return result;
    if (modulus.power_of_two) {
        std::copy_n(value, std::min(length, modulus.limbs), result.limb.begin());
        const unsigned top_bits = modulus.bits % 64;
        if (top_bits) result.limb[modulus.limbs - 1] &= (mp_limb_t(1) << top_bits) - 1;
        return result;
    }
    if (length < modulus.limbs ||
        (length == modulus.limbs && mpn_cmp(value, modulus.qword.limb.data(), modulus.limbs) < 0)) {
        std::copy_n(value, length, result.limb.begin());
        return result;
    }
    // Fixed workspace: products plus a 64-bit accumulation carry require <= 11 limbs.
    if (length > 11) throw std::overflow_error("Reduction input exceeds fixed workspace");
    std::array<mp_limb_t, 11> quotient{};
    mpn_tdiv_qr(quotient.data(), result.limb.data(), 0, value,
                static_cast<mp_size_t>(length), modulus.qword.limb.data(),
                static_cast<mp_size_t>(modulus.limbs));
    return result;
}

bool same(const Word& word, const Big& expected) { return to_big(word) == expected; }

Big normalized(const Big& value, const Big& modulus) {
    Big result;
    mpz_mod(result.get_mpz_t(), value.get_mpz_t(), modulus.get_mpz_t());
    return result;
}
} // namespace

std::vector<unsigned char> shake256(const std::vector<unsigned char>& input, std::size_t size) {
    std::vector<unsigned char> output(size);
    using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    Context context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!context || EVP_DigestInit_ex(context.get(), EVP_shake256(), nullptr) != 1 ||
        (!input.empty() && EVP_DigestUpdate(context.get(), input.data(), input.size()) != 1) ||
        (size && EVP_DigestFinalXOF(context.get(), output.data(), size) != 1))
        throw std::runtime_error("OpenSSL SHAKE256 failed");
    return output;
}

Rng::Rng(const Seed& seed, const std::string& domain) : seed_(seed), domain_(domain) {
    if (domain_.size() > 1024 * 1024) throw std::invalid_argument("RNG domain is unreasonably long");
}

void Rng::refill() {
    if (counter_ == std::numeric_limits<std::uint64_t>::max())
        throw std::overflow_error("SHAKE RNG counter exhausted");
    // Versioned unambiguous framing. Counter and byte lengths are little-endian.
    // Compatibility domain bytes retained for replay of recorded fixtures.
    static constexpr unsigned char prefix[] = "\x51\x52\x65\x52\x61\x6e\x64\x2d\x57\x69\x6e\x64\x6f\x77\x73\x4e\x61\x74\x69\x76\x65\x2d\x52\x4e\x47\x2d\x76\x31";
    std::vector<unsigned char> input;
    input.reserve(sizeof(prefix) - 1 + seed_.size() + 16 + domain_.size());
    input.insert(input.end(), prefix, prefix + sizeof(prefix) - 1);
    input.insert(input.end(), seed_.begin(), seed_.end());
    append_u64(input, static_cast<std::uint64_t>(domain_.size()));
    input.insert(input.end(), domain_.begin(), domain_.end());
    append_u64(input, counter_++);
    const auto block = shake256(input, buffer_.size());
    std::copy(block.begin(), block.end(), buffer_.begin());
    pos_ = 0;
}

void Rng::fill(unsigned char* output, std::size_t size) {
    if (size && !output) throw std::invalid_argument("Null RNG output");
    while (size) {
        if (pos_ == buffer_.size()) refill();
        const std::size_t take = std::min(size, buffer_.size() - pos_);
        std::memcpy(output, buffer_.data() + pos_, take);
        output += take;
        size -= take;
        pos_ += take;
    }
}

Big Rng::below(const Big& bound) {
    if (bound <= 0) throw std::invalid_argument("RNG bound must be positive");
    if (bound == 1) return Big(0);
    const Big maximum = bound - 1;
    const std::size_t bits = mpz_sizeinbase(maximum.get_mpz_t(), 2);
    const std::size_t bytes = (bits + 7) / 8;
    std::vector<unsigned char> buffer(bytes);
    Big result;
    do {
        fill(buffer.data(), buffer.size());
        if (bits % 8) buffer[0] &= static_cast<unsigned char>((1u << (bits % 8)) - 1u);
        mpz_import(result.get_mpz_t(), bytes, 1, 1, 1, 0, buffer.data());
    } while (result >= bound);
    return result;
}

unsigned Rng::bit() {
    unsigned char value;
    fill(&value, 1);
    return value & 1u;
}

Seed entropy_seed() {
    Seed result;
    if (RAND_bytes(result.data(), static_cast<int>(result.size())) != 1)
        throw std::runtime_error("OpenSSL entropy acquisition failed");
    return result;
}

std::string hex_seed(const Seed& seed) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (unsigned char byte : seed) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 15]);
    }
    return result;
}

Big to_big(const Word& value) {
    Big result;
    mpz_import(result.get_mpz_t(), value.limb.size(), -1, sizeof(mp_limb_t), 0, 0, value.limb.data());
    return result;
}

Word to_word(const Big& nonnegative) {
    if (nonnegative < 0 || mpz_sizeinbase(nonnegative.get_mpz_t(), 2) > 320)
        throw std::out_of_range("Integer does not fit in an unsigned 320-bit Word");
    Word result;
    std::size_t count = 0;
    mpz_export(result.limb.data(), &count, -1, sizeof(mp_limb_t), 0, 0, nonnegative.get_mpz_t());
    return result;
}

Modulus::Modulus(const std::string& decimal, unsigned a)
    : q(0), bits(a), limbs((std::size_t(a) + 63) / 64), power_of_two(false), qword{} {
    if (!a || a > 319 || q.set_str(decimal, 10) != 0 || q <= 1)
        throw std::invalid_argument("Invalid modulus or residue bit width");
    const Big ceiling = Big(1) << a;
    if (q > ceiling || q <= (ceiling >> 1))
        throw std::invalid_argument("Residue bit width must equal ceil(log2(q))");
    power_of_two = (q == ceiling);
    qword = to_word(q);
}

Word Modulus::encode(const Big& value) const { return to_word(normalized(value, q)); }
Word Modulus::uniform(Rng& rng) const {
    // Fixed-size sampling is important here: this path supplies billions of matrix entries.
    // It uses no per-entry heap allocation or mpz conversion.
    const std::size_t bytes = (bits + 7) / 8;
    std::array<unsigned char, 40> buffer{};
    for (;;) {
        Word result;
        rng.fill(buffer.data(), bytes);
        if (bits % 8) buffer[bytes - 1] &= static_cast<unsigned char>((1u << (bits % 8)) - 1u);
        const std::uint16_t one = 1;
        if (*reinterpret_cast<const unsigned char*>(&one) == 1) {
            std::memcpy(result.limb.data(), buffer.data(), bytes);
        } else {
            for (std::size_t j = 0; j < bytes; ++j)
                result.limb[j / 8] |= mp_limb_t(buffer[j]) << (8 * (j % 8));
        }
        if (power_of_two || mpn_cmp(result.limb.data(), qword.limb.data(), limbs) < 0) return result;
    }
}

Word Modulus::add(const Word& a, const Word& b) const {
    require_canonical(*this, a);
    require_canonical(*this, b);
    std::array<mp_limb_t, 6> sum{};
    sum[limbs] = mpn_add_n(sum.data(), a.limb.data(), b.limb.data(), static_cast<mp_size_t>(limbs));
    return reduce(*this, sum.data(), limbs + 1);
}

Word Modulus::sub(const Word& a, const Word& b) const {
    require_canonical(*this, a);
    require_canonical(*this, b);
    Word result;
    if (power_of_two || mpn_cmp(a.limb.data(), b.limb.data(), limbs) >= 0) {
        mpn_sub_n(result.limb.data(), a.limb.data(), b.limb.data(), static_cast<mp_size_t>(limbs));
        if (power_of_two && bits % 64) result.limb[limbs - 1] &= (mp_limb_t(1) << (bits % 64)) - 1;
    } else {
        mpn_sub_n(result.limb.data(), b.limb.data(), a.limb.data(), static_cast<mp_size_t>(limbs));
        mpn_sub_n(result.limb.data(), qword.limb.data(), result.limb.data(), static_cast<mp_size_t>(limbs));
    }
    return result;
}

Word Modulus::mul(const Word& a, const Word& b) const {
    require_canonical(*this, a);
    require_canonical(*this, b);
    std::array<mp_limb_t, 10> product{};
    mpn_mul_n(product.data(), a.limb.data(), b.limb.data(), static_cast<mp_size_t>(limbs));
    return reduce(*this, product.data(), 2 * limbs);
}

void Modulus::addmul(Word& accumulator, const Word& a, const Word& b) const {
    accumulator = add(accumulator, mul(a, b));
}

Word Modulus::dot(const Word* a, const Word* b, std::size_t length) const {
    if (length && (!a || !b)) throw std::invalid_argument("Null dot-product input");
    std::array<mp_limb_t, 11> accumulator{};
    std::array<mp_limb_t, 10> product{};
    const std::size_t wide = 2 * limbs;
    for (std::size_t i = 0; i < length; ++i) {
        require_canonical(*this, a[i]);
        require_canonical(*this, b[i]);
        mpn_mul_n(product.data(), a[i].limb.data(), b[i].limb.data(), static_cast<mp_size_t>(limbs));
        const mp_limb_t carry = mpn_add_n(accumulator.data(), accumulator.data(), product.data(),
                                         static_cast<mp_size_t>(wide));
        if (carry && accumulator[wide] == std::numeric_limits<mp_limb_t>::max())
            throw std::overflow_error("Dot-product accumulator overflow");
        accumulator[wide] += carry;
    }
    // Since length <= 2^64-1 and each product < 2^(128*limbs), one extra limb suffices.
    return reduce(*this, accumulator.data(), wide + 1);
}

bool arithmetic_selftest() {
    try {
        const auto kat = shake256({}, 64);
        const std::string expected =
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
            "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be";
        std::string actual;
        constexpr char digits[] = "0123456789abcdef";
        for (auto byte : kat) { actual += digits[byte >> 4]; actual += digits[byte & 15]; }
        if (actual != expected) return false;
        Seed seed{};
        for (unsigned i = 0; i < seed.size(); ++i) seed[i] = static_cast<unsigned char>(i);
        Rng rng(seed, "arithmetic-selftest"), rng_split(seed, "framing"), rng_whole(seed, "framing");
        std::vector<unsigned char> split(9000), whole(9000);
        rng_split.fill(split.data(), 4095);
        rng_split.fill(split.data() + 4095, split.size() - 4095);
        rng_whole.fill(whole.data(), whole.size());
        if (split != whole || rng.below(1) != 0) return false;
        Rng other_domain(seed, "framing-other");
        other_domain.fill(split.data(), split.size());
        if (split == whole) return false;

        for (const unsigned a : {135u, 143u, 192u, 196u, 219u, 239u, 256u, 270u}) {
            Big modulus;
            if (a >= 239) modulus = Big(1) << a;
            else { modulus = (Big(1) << (a - 1)) + 12345; mpz_nextprime(modulus.get_mpz_t(), modulus.get_mpz_t()); }
            Modulus field(modulus.get_str(), a);
            if (field.limbs != (a + 63) / 64) return false;
            for (unsigned j = 0; j < 100; ++j) {
                const Word uniform = field.uniform(rng);
                require_canonical(field, uniform);
                if (to_big(uniform) < 0 || to_big(uniform) >= modulus) return false;
            }
            std::vector<Big> boundary{Big(0), Big(1), Big(modulus - 1), Big(modulus / 2)};
            for (unsigned j = 0; j < 20; ++j) boundary.push_back(rng.below(modulus));
            for (const Big& x : boundary) {
                if (to_big(to_word(x)) != x || !same(field.encode(-x), normalized(-x, modulus))) return false;
                const Word wx = to_word(x);
                for (const Big& y : boundary) {
                    const Word wy = to_word(y);
                    if (!same(field.add(wx, wy), normalized(x + y, modulus)) ||
                        !same(field.sub(wx, wy), normalized(x - y, modulus)) ||
                        !same(field.mul(wx, wy), normalized(x * y, modulus))) return false;
                    Word accum = wx;
                    field.addmul(accum, wx, wy);
                    if (!same(accum, normalized(x + x * y, modulus))) return false;
                }
            }
            for (const std::size_t length : {std::size_t(0), std::size_t(1), std::size_t(2),
                                             std::size_t(31), std::size_t(129), std::size_t(12000)}) {
                std::vector<Word> x(length), y(length);
                Big direct = 0;
                for (std::size_t j = 0; j < length; ++j) {
                    const Big xb = j % 3 ? rng.below(modulus) : Big(modulus - 1);
                    const Big yb = j % 5 ? rng.below(modulus) : Big(modulus - 1);
                    x[j] = to_word(xb); y[j] = to_word(yb); direct += xb * yb;
                }
                if (!same(field.dot(x.data(), y.data(), length), normalized(direct, modulus))) return false;
                std::fill(x.begin(), x.end(), to_word(modulus - 1));
                std::fill(y.begin(), y.end(), to_word(modulus - 1));
                if (!same(field.dot(x.data(), y.data(), length), Big(static_cast<unsigned long>(length)))) return false;
            }
            bool rejected = false;
            try { field.mul(to_word(modulus), to_word(1)); } catch (const std::invalid_argument&) { rejected = true; }
            if (!rejected) return false;
        }
        bool rejected = false;
        try { to_word(Big(1) << 320); } catch (const std::out_of_range&) { rejected = true; }
        if (!rejected) return false;
        return true;
    } catch (...) {
        return false;
    }
}
} // namespace bench
