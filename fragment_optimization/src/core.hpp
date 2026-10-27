#pragma once
#include <array>
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <gmpxx.h>

namespace bench {
using Big = mpz_class;
using Seed = std::array<unsigned char,32>;
struct Word { std::array<mp_limb_t,5> limb{}; };
static_assert(sizeof(mp_limb_t)==8, "64-bit GMP required");
static_assert(sizeof(Word)==40, "Unexpected Word layout");

class Rng {
    Seed seed_; std::string domain_; std::uint64_t counter_=0;
    std::array<unsigned char,4096> buffer_{}; std::size_t pos_=4096;
    void refill();
public:
    Rng(const Seed& seed,const std::string& domain);
    void fill(unsigned char* output,std::size_t size);
    Big below(const Big& bound);
    unsigned bit();
};
Seed entropy_seed();
std::vector<unsigned char> shake256(const std::vector<unsigned char>& input,std::size_t size);
std::string hex_seed(const Seed& seed);
Big to_big(const Word& value);
Word to_word(const Big& nonnegative);

class Modulus {
public:
    Big q; unsigned bits; std::size_t limbs; bool power_of_two;
    Word qword;
    Modulus(const std::string& decimal,unsigned a);
    Word encode(const Big& value) const;
    Word uniform(Rng& rng) const;
    Word add(const Word& a,const Word& b) const;
    Word sub(const Word& a,const Word& b) const;
    Word mul(const Word& a,const Word& b) const;
    void addmul(Word& accumulator,const Word& a,const Word& b) const;
    Word dot(const Word* a,const Word* b,std::size_t length) const;
};
bool arithmetic_selftest();

struct SampleStats {
    std::uint64_t decisions=0, retries=0, gaussian_proposals=0;
    unsigned max_precision=0;
};
// Integer Gaussian with exp(-pi*z*z/width^2), truncated at 16*width.
// Interval probabilities and 256-bit Bernoulli grid, never IEEE-double noise.
Big discrete_gaussian(const Big& width,Rng& rng,SampleStats& stats);
struct PolarLayout {
    unsigned a=0, N=256, stop=0;
    Big width;
    std::vector<std::vector<unsigned>> frozen;
};
void validate_layout(const PolarLayout& layout);
std::vector<Big> integer_transform(const std::vector<Big>& values,bool inverse=false);
std::vector<unsigned> frozen_bits(const Seed&,std::uint64_t block,unsigned layer,std::size_t count);
std::vector<Big> polar_sample_block(const std::vector<Big>& source,const PolarLayout& layout,
                                  const Seed& seed,std::uint64_t block,Rng& rng,SampleStats& stats);
bool sampler_selftest();

struct Stamp { std::uint64_t cycles=0; double seconds=0; };
void install_memory_limit(std::uint64_t bytes);
void platform_check(std::uint64_t planned_bytes);
Stamp clock_stamp();
std::uint64_t peak_memory_bytes();
std::string platform_description();
std::string cycle_counter_name();
bool cycle_counter_available();
void set_single_thread_affinity(int core);
}
