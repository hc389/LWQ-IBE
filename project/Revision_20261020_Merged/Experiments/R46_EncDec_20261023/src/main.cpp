#include "core.hpp"
#include "profile_hashes.hpp"
#include <flint/flint.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <mpfr.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <numeric>
#include <set>
#include <sstream>
#include <stdexcept>
#include <cstring>
#ifdef __APPLE__
#include <CommonCrypto/CommonCryptor.h>
#endif

namespace fs = std::filesystem;
using namespace bench;
namespace {
const std::vector<std::string> profile_ids = {"ours_mpk", "ours_mid", "ours_ct", "jkn_low", "jkn_joint", "abla_I_low", "abla_I_high", "abla_II"};
struct Options {
    std::string mode, profiles="ours_mpk,ours_ct";
    fs::path data, output, fixture_dir, ciphertext;
    unsigned repetitions=3, warmup=0, tile_mib=32, blocks=4, expected_message=0;
    std::uint64_t block_offset=std::numeric_limits<std::uint64_t>::max();
    std::uint64_t limit=1400000000ULL;
    int core=-1;
    bool plan=false, selftest=false, allow_long=false;
};
struct Profile {
    std::string id, scheme;
    unsigned n=0, m=0, a=0;
    Big q, r, S, sigma;
    bool polar=false;
    PolarLayout layout;
    std::uint64_t reference_bytes=0;
    std::uint64_t d() const { return 2ULL*m; }
    std::uint64_t bits_for(std::uint64_t dimension) const {
        if (!dimension || dimension>d() || dimension%layout.N) throw std::invalid_argument("Invalid fragment dimension");
        std::uint64_t bits=(dimension+1)*a;
        if (polar) {
            std::uint64_t frozen=0;
            for (const auto& layer:layout.frozen) frozen+=layer.size();
            bits+=256;
            bits-=(dimension/layout.N)*frozen;
        }
        return bits;
    }
    std::uint64_t ct_bits() const {return bits_for(d());}
    std::uint64_t ct_bytes() const { return (ct_bits()+7)/8; }
};
struct Duration {
    std::uint64_t cycles=0; double seconds=0;
    void add(const Stamp& begin, const Stamp& end) {
        if (end.cycles<begin.cycles || end.seconds<begin.seconds)
            throw std::runtime_error("Nonmonotonic timer");
        cycles+=end.cycles-begin.cycles; seconds+=end.seconds-begin.seconds;
    }
};
template<class F> void timed(Duration& total, F&& function) {
    const auto start=clock_stamp(); function(); total.add(start,clock_stamp());
}
struct Metrics {
    Duration enc, dec, feed, prepare, quant, scalar, noise, serialization, matvec, unpack, dec_dot, decision;
    SampleStats sampling;
    std::uint64_t scalar_decisions=0;
    Seed scalar_seed{},vector_seed{};
    bool decoded=false;
};
std::uint64_t decimal(const std::string& text) {
    if (text.empty() || text.find_first_not_of("0123456789")!=std::string::npos)
        throw std::invalid_argument("Invalid nonnegative integer: "+text);
    std::size_t used=0; const auto value=std::stoull(text,&used);
    if (used!=text.size()) throw std::invalid_argument("Invalid integer");
    return value;
}
std::string trim(std::string s) {
    const auto first=s.find_first_not_of(" \t\r\n");
    return first==std::string::npos ? "" : s.substr(first,s.find_last_not_of(" \t\r\n")-first+1);
}
std::vector<std::string> split(const std::string& s,char delimiter=',') {
    std::istringstream input(s); std::string value; std::vector<std::string> out;
    while (std::getline(input,value,delimiter)) out.push_back(trim(value));
    return out;
}
std::string json(const std::string& s) {
    std::ostringstream out; out<<'"';
    for (unsigned char c:s) {
        if (c=='"' || c=='\\') out<<'\\'<<c;
        else if (c=='\n') out<<"\\n";
        else if (c=='\r') out<<"\\r";
        else if (c<32) out<<"\\u"<<std::hex<<std::setw(4)<<std::setfill('0')<<unsigned(c)<<std::dec;
        else out<<c;
    }
    out<<'"'; return out.str();
}
std::string file_sha256(const fs::path& path) {
    std::ifstream input(path,std::ios::binary);
    if (!input) throw std::runtime_error("Cannot read file: "+path.string());
    EVP_MD_CTX* ctx=EVP_MD_CTX_new();
    if (!ctx) throw std::bad_alloc();
    if (EVP_DigestInit_ex(ctx,EVP_sha256(),nullptr)!=1) {
        EVP_MD_CTX_free(ctx); throw std::runtime_error("SHA256 initialization failed");
    }
    char buffer[16384];
    while (input.read(buffer,sizeof buffer) || input.gcount()) {
        if (EVP_DigestUpdate(ctx,buffer,static_cast<std::size_t>(input.gcount()))!=1) {
            EVP_MD_CTX_free(ctx); throw std::runtime_error("SHA256 update failed");
        }
    }
    unsigned char hash[32]; unsigned length=0;
    const int ok=EVP_DigestFinal_ex(ctx,hash,&length); EVP_MD_CTX_free(ctx);
    if (ok!=1 || length!=32 || !input.eof()) throw std::runtime_error("SHA256 read/finalize failed");
    std::ostringstream out;
    for (auto c:hash) out<<std::hex<<std::setw(2)<<std::setfill('0')<<unsigned(c);
    return out.str();
}
Profile read_profile(const fs::path& path) {
    std::ifstream input(path); if (!input) throw std::runtime_error("Cannot open "+path.string());
    std::map<std::string,std::string> kv; std::string line;
    while (std::getline(input,line)) {
        if (line.size()>20000) throw std::runtime_error("Oversized profile line");
        line=trim(line); if (line.empty() || line[0]=='#') continue;
        const auto pos=line.find('=');
        if (pos==std::string::npos || !kv.emplace(trim(line.substr(0,pos)),trim(line.substr(pos+1))).second)
            throw std::runtime_error("Invalid or duplicate profile field");
    }
    auto get=[&](const std::string& key)->std::string {
        const auto it=kv.find(key); if (it==kv.end()) throw std::runtime_error("Missing profile field "+key);
        return it->second;
    };
    auto uint=[&](const std::string& key,unsigned max)->unsigned {
        auto x=decimal(get(key)); if (x>max) throw std::runtime_error("Out-of-range profile field "+key);
        return static_cast<unsigned>(x);
    };
    Profile p; p.id=get("id"); p.scheme=get("scheme");
    p.n=uint("n",12000); p.m=uint("m",5000000); p.a=uint("a",320);
    p.q=Big(get("q")); p.r=Big(get("r")); p.S=Big(get("S")); p.sigma=Big(get("sigma"));
    p.polar=uint("polar",1)!=0;
    p.reference_bytes=decimal(get("expected_ct_bytes"));
    p.layout.a=p.a; p.layout.N=uint("N",256); p.layout.stop=uint("stop",320); p.layout.width=p.S;
    if (!p.n || !p.m || p.a<2 || p.layout.N!=256 || p.d()%256 || p.layout.stop>p.a ||
        p.r<=0 || p.S<=0 || p.sigma<=0 || p.r>=p.q || p.S>=p.q || p.sigma>=p.q)
        throw std::runtime_error("Invalid profile dimensions or widths");
    Modulus check(p.q.get_str(),p.a); (void)check;
    p.layout.frozen.resize(p.a);
    const std::set<std::string> fields={"id","scheme","n","m","a","q","r","S","sigma","polar","N","stop","expected_ct_bytes","minimum_attack_bits"};
    for (const auto& item:kv) {
        if (fields.count(item.first)) continue;
        if (item.first.rfind("frozen_",0)!=0 || decimal(item.first.substr(7))>=p.layout.stop)
            throw std::runtime_error("Unknown or inactive profile field: "+item.first);
    }
    for (unsigned i=0;i<p.layout.stop;++i) {
        const auto value=get("frozen_"+std::to_string(i)); auto& layer=p.layout.frozen[i];
        if (value=="all") { layer.resize(256); std::iota(layer.begin(),layer.end(),0U); }
        else if (value!="none") {
            for (const auto& item:split(value)) {
                const auto j=decimal(item); if (j>=256) throw std::runtime_error("Frozen index out of range");
                layer.push_back(static_cast<unsigned>(j));
            }
        }
        if (!std::is_sorted(layer.begin(),layer.end()) || std::adjacent_find(layer.begin(),layer.end())!=layer.end())
            throw std::runtime_error("Frozen indices must be strictly increasing");
    }
    if (p.polar) {
        validate_layout(p.layout);
        if (p.q!=(Big(1)<<p.a)) throw std::runtime_error("Polar codec requires q=2^a");
    } else if (p.layout.stop) throw std::runtime_error("Baseline has unexpected polar layout");
    if (p.ct_bytes()!=p.reference_bytes) throw std::runtime_error("Ciphertext formula disagrees with profile reference");
    return p;
}
Options parse_options(int argc,char** argv) {
    Options o;
    o.data=fs::absolute(fs::path(argv[0])).parent_path()/"data";
    for (int i=1;i<argc;++i) {
        const std::string arg=argv[i];
        auto next=[&](){if (++i>=argc) throw std::invalid_argument("Missing argument for "+arg); return std::string(argv[i]);};
        auto bounded=[&](std::uint64_t lo,std::uint64_t hi){auto x=decimal(next());if (x<lo||x>hi) throw std::invalid_argument("Argument out of range: "+arg);return x;};
        if (arg=="--selftest") o.selftest=true;
        else if (arg=="--plan") o.plan=true;
        else if (arg=="--allow-long-run") o.allow_long=true;
        else if (arg=="--mode") o.mode=next();
        else if (arg=="--profiles") o.profiles=next();
        else if (arg=="--data") o.data=next();
        else if (arg=="--output") o.output=next();
        else if (arg=="--fixture-dir") o.fixture_dir=next();
        else if (arg=="--ciphertext") o.ciphertext=next();
        else if (arg=="--expected-message") o.expected_message=static_cast<unsigned>(bounded(0,1));
        else if (arg=="--repetitions") o.repetitions=static_cast<unsigned>(bounded(1,100));
        else if (arg=="--warmup") o.warmup=static_cast<unsigned>(bounded(0,10));
        else if (arg=="--blocks") o.blocks=static_cast<unsigned>(bounded(1,32));
        else if (arg=="--block-offset") o.block_offset=bounded(0,10000000);
        else if (arg=="--tile-mib") o.tile_mib=static_cast<unsigned>(bounded(1,64));
        else if (arg=="--memory-limit-mb") o.limit=bounded(256,1500)*1000000ULL;
        else if (arg=="--core") {
            const auto text=next();
            if (text=="-1") o.core=-1;
            else {const auto value=decimal(text);if(value>63)throw std::invalid_argument("Invalid logical CPU");o.core=static_cast<int>(value);}
        }
        else if (arg=="--help") {o.mode="help";}
        else throw std::invalid_argument("Unknown option: "+arg);
    }
    if ((o.mode=="blocks" || o.mode=="fullcodec") && o.profiles=="representative") o.profiles="ours_mpk,ours_ct";
    return o;
}
std::vector<Profile> selected_profiles(const Options& o) {
    auto ids=o.profiles=="ours" ? std::vector<std::string>{"ours_mpk","ours_mid","ours_ct"} : o.profiles=="all" ? profile_ids : o.profiles=="representative" ?
        std::vector<std::string>{"ours_ct","jkn_low","abla_II"} : split(o.profiles);
    if (ids.empty() || ids.size()>8) throw std::invalid_argument("Empty or excessive profile selection");
    std::set<std::string> seen; std::vector<Profile> result;
    for (const auto& id:ids) {
        if ((id!="ours_mpk"&&id!="ours_ct") || !seen.insert(id).second)
            throw std::invalid_argument("Unknown or repeated profile: "+id);
        const auto file=o.data/(id+".cfg");
        const auto hash=expected_profile_sha256.find(id);
        if (hash==expected_profile_sha256.end() || file_sha256(file)!=hash->second)
            throw std::runtime_error("Profile hash differs from the previously verified parameter set: "+id);
        auto p=read_profile(file);
        if (!p.polar || p.scheme!="Ours") throw std::invalid_argument("This local extension measures only Ours profiles");
        if (p.id!=id) throw std::runtime_error("Profile ID mismatch"); result.push_back(std::move(p));
    }
    return result;
}
std::size_t tile_columns(const Profile& p,const Options& o) {
    return std::max<std::size_t>(1,std::min<std::size_t>(256,(std::uint64_t(o.tile_mib)<<20)/(p.n*sizeof(Word))));
}
std::uint64_t planned_memory(const Profile& p,const Options& o) {
    // One private key, one packed ciphertext, one matrix tile, small vectors,
    // and 128 MB reserved for libraries, allocator, Arb and runtime overhead.
    return p.d()*sizeof(Word)+p.ct_bytes()+2*tile_columns(p,o)*p.n*sizeof(Word)+
        4ULL*p.n*sizeof(Word)+128000000ULL;
}
void preflight(const Profile& p,const Options& o) {
    const auto budget=planned_memory(p,o); platform_check(budget);
    std::cout<<p.id<<": n="<<p.n<<", 2m="<<p.d()<<", q_bits="<<p.a
        <<", ciphertext="<<p.ct_bytes()<<" B, tile_cols="<<tile_columns(p,o)
        <<", guarded allocation budget="<<std::fixed<<std::setprecision(1)<<budget/1000000.0<<" MB\n";
    std::cout<<std::defaultfloat<<std::setprecision(6);
}

// Exact MSB-first byte packing; no vector<bool>, floating point, or full bit tape.
class Writer {
    std::uint64_t target_, pos_=0;
public:
    std::vector<unsigned char> bytes;
    explicit Writer(std::uint64_t bits):target_(bits),bytes(static_cast<std::size_t>((bits+7)/8),0) {}
    void bit(unsigned b) {
        if (b>1 || pos_>=target_) throw std::runtime_error("Bit-writer overflow");
        bytes[pos_/8]|=static_cast<unsigned char>(b<<(7-pos_%8)); ++pos_;
    }
    void word(const Word& w,unsigned bits) {
        for (unsigned j=bits;j;--j) bit(static_cast<unsigned>((w.limb[(j-1)/64]>>((j-1)%64))&1));
    }
    void seed(const Seed& s) {for (auto c:s) for (unsigned j=8;j;--j) bit((c>>(j-1))&1);}
    void finish() const {if (pos_!=target_) throw std::runtime_error("Bit-writer size mismatch");}
};
class Reader {
    const std::vector<unsigned char>& bytes_; std::uint64_t target_,pos_=0;
public:
    Reader(const std::vector<unsigned char>& bytes,std::uint64_t bits):bytes_(bytes),target_(bits) {
        if (bytes.size()!=(bits+7)/8) throw std::runtime_error("Ciphertext length mismatch");
    }
    unsigned bit() {if (pos_>=target_) throw std::runtime_error("Truncated ciphertext");auto b=(bytes_[pos_/8]>>(7-pos_%8))&1;++pos_;return b;}
    Word word(unsigned bits) {Word w;for (unsigned j=bits;j;--j) w.limb[(j-1)/64]|=mp_limb_t(bit())<<((j-1)%64);return w;}
    Seed seed() {Seed s{};for (auto& c:s) for (unsigned j=0;j<8;++j) c=static_cast<unsigned char>((c<<1)|bit());return s;}
    void finish() const {
        if (pos_!=target_) throw std::runtime_error("Unread ciphertext bits");
        if (target_%8 && (bytes_.back()&((1U<<(8-target_%8))-1))) throw std::runtime_error("Noncanonical padding");
    }
};
void pack_polar(Writer& out,const std::vector<Big>& b,const Profile& p,const Seed& seed,std::uint64_t block) {
    auto coeff=integer_transform(b,true); for (auto& z:coeff) mpz_fdiv_r_2exp(z.get_mpz_t(),z.get_mpz_t(),p.a);
    for (unsigned i=0;i<p.a;++i) {
        const auto& F=p.layout.frozen[i];
        const auto fixed=F.empty() ? std::vector<unsigned>{} : frozen_bits(seed,block,i+1,F.size());
        std::size_t index=0;
        for (unsigned j=0;j<p.layout.N;++j) {
            const unsigned bit=mpz_tstbit(coeff[j].get_mpz_t(),i)!=0;
            if (index<F.size() && F[index]==j) {
                if (bit!=fixed[index++]) throw std::runtime_error("Frozen coefficient/seed mismatch");
            } else out.bit(bit);
        }
    }
}
std::vector<Word> unpack_polar(Reader& in,const Profile& p,const Modulus& mod,const Seed& seed,std::uint64_t block) {
    std::vector<Big> coeff(p.layout.N);
    for (unsigned i=0;i<p.a;++i) {
        const auto& F=p.layout.frozen[i];
        const auto fixed=F.empty() ? std::vector<unsigned>{} : frozen_bits(seed,block,i+1,F.size());
        std::size_t index=0;
        for (unsigned j=0;j<p.layout.N;++j) {
            const unsigned bit=(index<F.size() && F[index]==j) ? fixed[index++] : in.bit();
            if (bit) mpz_setbit(coeff[j].get_mpz_t(),i);
        }
    }
    auto b=integer_transform(coeff); std::vector<Word> result; result.reserve(p.layout.N);
    for (const auto& z:b) result.push_back(mod.encode(z)); return result;
}

class MatrixStream {
    const Profile& p_; const Modulus& mod_; std::size_t capacity_;
    std::array<unsigned char,32> key_{};
    std::vector<unsigned char> zeros_,buffer_;
    EVP_CIPHER_CTX* context_=nullptr;
    bool reference_backend_=false;
public:
    std::vector<Word> tile;
    MatrixStream(const Profile& p,const Modulus& mod,const Seed& seed,std::size_t cols,bool reference_backend=false):
        p_(p),mod_(mod),capacity_(cols),zeros_(std::size_t(p.n)*((p.a+7)/8),0),buffer_(zeros_.size()+16),reference_backend_(reference_backend),tile(cols*p.n) {
        if(!mod.power_of_two || zeros_.size()>std::size_t(std::numeric_limits<int>::max()))
            throw std::invalid_argument("AES fixture only supports bounded q=2^a columns");
        const std::string domain="R46-EncDec-test-matrix-AES256CTR-v1/"+p.id+"/";
        std::vector<unsigned char> input(domain.begin(),domain.end());input.insert(input.end(),seed.begin(),seed.end());
        const auto derived=shake256(input,32);std::copy(derived.begin(),derived.end(),key_.begin());
        context_=EVP_CIPHER_CTX_new();
        if(!context_)throw std::bad_alloc();
    }
    ~MatrixStream(){EVP_CIPHER_CTX_free(context_);}
    MatrixStream(const MatrixStream&)=delete;
    MatrixStream& operator=(const MatrixStream&)=delete;
    std::size_t fill(std::uint64_t offset,std::uint64_t remaining=std::numeric_limits<std::uint64_t>::max()) {
        if (offset>=p_.d()) throw std::invalid_argument("Matrix stream offset outside profile");
        const auto count=static_cast<std::size_t>(std::min<std::uint64_t>(capacity_,std::min(p_.d()-offset,remaining)));
        for (std::size_t c=0;c<count;++c) {
            // High 64 bits identify the global column, low 64 bits count AES
            // blocks. A bounded column uses fewer than 2^64 blocks, so distinct
            // columns never share a counter. This is ONLY a test-data supplier.
            std::array<unsigned char,16> iv{};const auto column=offset+c;
            for(unsigned j=0;j<8;++j)iv[j]=static_cast<unsigned char>(column>>(56-8*j));
#ifdef __APPLE__
            if(!reference_backend_){
                CCCryptorRef cryptor=nullptr;std::size_t written=0;
                if(CCCryptorCreateWithMode(kCCEncrypt,kCCModeCTR,kCCAlgorithmAES,ccNoPadding,iv.data(),key_.data(),key_.size(),nullptr,0,0,kCCModeOptionCTR_BE,&cryptor)!=kCCSuccess)
                    throw std::runtime_error("Native AES fixture initialization failed");
                const auto status=CCCryptorUpdate(cryptor,zeros_.data(),zeros_.size(),buffer_.data(),buffer_.size(),&written);
                CCCryptorRelease(cryptor);
                if(status!=kCCSuccess||written!=zeros_.size())throw std::runtime_error("Native AES fixture generation failed");
            }else
#endif
            {
                int written=0,tail=0;
                if(EVP_EncryptInit_ex(context_,EVP_aes_256_ctr(),nullptr,key_.data(),iv.data())!=1 ||
                   EVP_EncryptUpdate(context_,buffer_.data(),&written,zeros_.data(),static_cast<int>(zeros_.size()))!=1 ||
                   EVP_EncryptFinal_ex(context_,buffer_.data()+written,&tail)!=1 ||
                   written+tail!=static_cast<int>(zeros_.size()))throw std::runtime_error("AES fixture generation failed");
            }
            const auto bytes=(p_.a+7)/8;
            for(unsigned row=0;row<p_.n;++row){
                Word value;const auto* begin=buffer_.data()+std::size_t(row)*bytes;
                const std::uint16_t one=1;
                if(*reinterpret_cast<const unsigned char*>(&one)==1)std::memcpy(value.limb.data(),begin,bytes);
                else for(unsigned j=0;j<bytes;++j)value.limb[j/8]|=mp_limb_t(begin[j])<<(8*(j%8));
                if(p_.a%64)value.limb[mod_.limbs-1]&=(mp_limb_t(1)<<(p_.a%64))-1;
                tile[c*p_.n+row]=value;
            }
        }
        return count;
    }
};
struct Fixture {
    std::vector<Word> e,u;Seed matrix_seed{},key_seed{};
    Duration key_sampling,feed,transpose,matvec,validation,io,total;
    SampleStats key_stats;
};
void heartbeat(const char* stage,std::uint64_t done,std::uint64_t total,double& previous) {
    const auto now=clock_stamp().seconds;
    if (now-previous>=5 || done==total) {
        std::cout<<"  "<<stage<<" "<<done<<"/"<<total<<std::endl; previous=now;
    }
}
Fixture prepare_fixture(const Profile& p,const Modulus& mod,const Options& o,Duration& duration,SampleStats& stats) {
    // Valid algebraic key relation, NOT a replacement implementation of
    // TrapGen/Extract. This synthetic fixture is declared in every CSV row.
    const auto start=clock_stamp(); Fixture f;
    f.matrix_seed=entropy_seed();f.key_seed=entropy_seed();f.e.resize(static_cast<std::size_t>(p.d()));f.u.resize(p.n);
    Rng key_rng(f.key_seed,"offline-algebraic-key/"+p.id); double progress=start.seconds;
    for (std::uint64_t i=0;i<p.d();++i) {
        timed(f.key_sampling,[&]{f.e[i]=mod.encode(discrete_gaussian(p.sigma,key_rng,stats));});
        if (!(i%4096)) {platform_check(planned_memory(p,o));heartbeat("offline key",i,p.d(),progress);}
    }
    MatrixStream matrix(p,mod,f.matrix_seed,tile_columns(p,o));
    std::vector<Word> rows(matrix.tile.size());
    for (std::uint64_t offset=0;offset<p.d();) {
        std::size_t count=0;timed(f.feed,[&]{count=matrix.fill(offset);});
        timed(f.transpose,[&]{for(unsigned row=0;row<p.n;++row)for(std::size_t c=0;c<count;++c)rows[std::size_t(row)*count+c]=matrix.tile[c*p.n+row];});
        timed(f.matvec,[&]{for(unsigned row=0;row<p.n;++row)f.u[row]=mod.add(f.u[row],mod.dot(rows.data()+std::size_t(row)*count,f.e.data()+offset,count));});
        offset+=count; platform_check(planned_memory(p,o)); heartbeat("offline u=M e",offset,p.d(),progress);
    }
    duration.add(start,clock_stamp());f.total=duration;f.key_stats=stats;return f;
}
std::vector<unsigned char> encrypt(const Profile& p,const Modulus& mod,const Options& o,const Fixture& f,
                                  unsigned& message,Seed& public_seed,Metrics& metrics) {
    // Matrix allocation is outside compute time; ciphertext allocation and
    // fresh encryption randomness are inside. Matrix generation is measured
    // separately and subtracted, never a precomputation of M^T s.
    MatrixStream matrix(p,mod,f.matrix_seed,tile_columns(p,o));
    const auto overall=clock_stamp(); Writer writer(p.ct_bits());
    std::vector<Word> s(p.n); Word scalar;
    timed(metrics.scalar,[&]{
        metrics.scalar_seed=entropy_seed();Rng rng(metrics.scalar_seed,"fresh-secret-scalar/"+p.id);
        if (p.scheme=="JKN21") message=rng.bit(); // Original single-bit KEM payload.
        for (auto& z:s) z=mod.uniform(rng);
        scalar=mod.add(mod.dot(f.u.data(),s.data(),p.n),mod.encode(discrete_gaussian(p.r,rng,metrics.sampling)));
        if (message) scalar=mod.add(scalar,mod.encode(p.q/2));
        if (p.polar) public_seed=entropy_seed();
    });
    metrics.scalar_decisions=metrics.sampling.decisions;
    metrics.vector_seed=entropy_seed();Rng private_rng(metrics.vector_seed,"fresh-vector-randomness/"+p.id);
    timed(metrics.serialization,[&]{writer.word(scalar,p.a);if (p.polar) writer.seed(public_seed);});
    std::vector<Word> pending; pending.reserve(p.layout.N); std::uint64_t block=0;
    std::array<Word,256> projected{};
    double previous=overall.seconds; Duration progress_time;
    for (std::uint64_t offset=0;offset<p.d();) {
        std::size_t count=0;
        timed(metrics.feed,[&]{count=matrix.fill(offset);});
        timed(metrics.matvec,[&]{
            for (std::size_t c=0;c<count;++c)
                projected[c]=mod.dot(matrix.tile.data()+c*p.n,s.data(),p.n);
        });
        for (std::size_t c=0;c<count;++c) {
            pending.push_back(projected[c]);
            if (pending.size()==p.layout.N) {
                if (p.polar) {
                    std::vector<Big> b;
                    timed(metrics.quant,[&]{
                        std::vector<Big> source;source.reserve(p.layout.N);
                        for (const auto& z:pending) source.push_back(to_big(z));
                        b=polar_sample_block(source,p.layout,public_seed,block,private_rng,metrics.sampling);
                    });
                    timed(metrics.serialization,[&]{pack_polar(writer,b,p,public_seed,block);});
                } else {
                    timed(metrics.noise,[&]{
                        for (auto& b:pending) b=mod.add(b,mod.encode(discrete_gaussian(p.S,private_rng,metrics.sampling)));
                    });
                    timed(metrics.serialization,[&]{for (const auto& b:pending) writer.word(b,p.a);});
                }
                ++block; pending.clear();
            }
        }
        offset+=count;
        timed(progress_time,[&]{platform_check(planned_memory(p,o));heartbeat("online encrypt",offset,p.d(),previous);});
    }
    if (!pending.empty()) throw std::runtime_error("Incomplete vector block"); writer.finish();
    metrics.enc.add(overall,clock_stamp());
    if (metrics.enc.cycles<metrics.feed.cycles+progress_time.cycles || metrics.enc.seconds<metrics.feed.seconds+progress_time.seconds)
        throw std::runtime_error("Invalid nested timing subtraction");
    metrics.enc.cycles-=metrics.feed.cycles+progress_time.cycles;
    metrics.enc.seconds-=metrics.feed.seconds+progress_time.seconds;
    return std::move(writer.bytes);
}
unsigned decrypt(const Profile& p,const Modulus& mod,const Fixture& f,const std::vector<unsigned char>& ciphertext,Metrics& metrics) {
    unsigned message=0;
    timed(metrics.dec,[&]{
        Reader reader(ciphertext,p.ct_bits());Word scalar,inner;Seed seed{};
        timed(metrics.unpack,[&]{scalar=reader.word(p.a);if(to_big(scalar)>=p.q)throw std::runtime_error("Noncanonical scalar");seed=reader.seed();});
        for (std::uint64_t offset=0;offset<p.d();offset+=p.layout.N) {
            std::vector<Word> b;
            timed(metrics.unpack,[&]{b=unpack_polar(reader,p,mod,seed,offset/p.layout.N);});
            timed(metrics.dec_dot,[&]{inner=mod.add(inner,mod.dot(b.data(),f.e.data()+offset,p.layout.N));});
        }
        timed(metrics.decision,[&]{
            reader.finish();const Big v=to_big(mod.sub(scalar,inner)),half=p.q/2;
            Big distance0=std::min(v,Big(p.q-v));Big distance1=abs(v-half);
            distance1=std::min(distance1,Big(p.q-distance1));message=distance1<distance0?1U:0U;
        });
    });
    return message;
}
bool codec_selftest() {
    Profile p; p.id="test";p.polar=true;p.n=2;p.m=4;p.a=13;p.q=Big(1)<<13;
    p.layout.a=13;p.layout.N=8;p.layout.stop=3;p.layout.width=2;
    p.layout.frozen.resize(13);p.layout.frozen[0]={0,1,2,3,4,5,6,7};p.layout.frozen[1]={0,1,2,3};p.layout.frozen[2]={0,1};
    Modulus mod(p.q.get_str(),p.a);Seed seed{};for (unsigned i=0;i<32;++i) seed[i]=static_cast<unsigned char>(i);
    std::vector<Big> coeff(8);Rng rng(seed,"codec-test");for (auto& z:coeff) z=rng.below(p.q);
    for (unsigned i=0;i<p.a;++i) {
        const auto& F=p.layout.frozen[i];const auto bits=frozen_bits(seed,0,i+1,F.size());
        for (unsigned j=0;j<F.size();++j) {if (bits[j])mpz_setbit(coeff[F[j]].get_mpz_t(),i);else mpz_clrbit(coeff[F[j]].get_mpz_t(),i);}
    }
    auto b=integer_transform(coeff);for (auto& z:b) z%=p.q;
    Writer writer(p.ct_bits());writer.word(mod.encode(1234),p.a);writer.seed(seed);pack_polar(writer,b,p,seed,0);writer.finish();
    Reader reader(writer.bytes,p.ct_bits());if (to_big(reader.word(p.a))!=1234||reader.seed()!=seed)return false;
    const auto recovered=unpack_polar(reader,p,mod,seed,0);reader.finish();
    for (unsigned i=0;i<8;++i)if(to_big(recovered[i])!=b[i])return false;
    auto corrupted=writer.bytes;corrupted.back()|=1;
    try {Reader bad(corrupted,p.ct_bits());for(std::uint64_t i=0;i<p.ct_bits();++i)bad.bit();bad.finish();return false;}catch(const std::runtime_error&){}
    // Matrix columns and fixture relation must be independent of tile size.
    p.polar=false;p.m=4;p.n=3;MatrixStream a(p,mod,seed,1),c(p,mod,seed,4);
    c.fill(0);for(unsigned col=0;col<4;++col){a.fill(col);for(unsigned row=0;row<3;++row)if(to_big(a.tile[row])!=to_big(c.tile[col*3+row]))return false;}
    std::vector<Word> e(4),s(3),u(3),t(4);for(auto& z:e)z=mod.uniform(rng);for(auto& z:s)z=mod.uniform(rng);
    for(unsigned col=0;col<4;++col){t[col]=mod.dot(c.tile.data()+col*3,s.data(),3);for(unsigned row=0;row<3;++row)mod.addmul(u[row],c.tile[col*3+row],e[col]);}
    return to_big(mod.dot(t.data(),e.data(),4))==to_big(mod.dot(u.data(),s.data(),3));
}
void write_metadata(const Options& o,const std::vector<Profile>& ps,const Seed& order_seed) {
    std::ofstream f(o.output/"metadata.json");if(!f)throw std::runtime_error("Cannot write metadata");
    f<<"{\n  \"schema\": 1,\n  \"platform\": "<<json(platform_description())
        <<",\n  \"cycle_counter\": "<<json(cycle_counter_name())
        <<",\n  \"cycle_counter_available\": "<<(cycle_counter_available()?"true":"false")
        <<",\n  \"compiler\": "<<json(__VERSION__)
        <<",\n  \"gmp\": "<<json(gmp_version)<<",\n  \"mpfr\": "<<json(mpfr_get_version())
        <<",\n  \"flint\": "<<json(FLINT_VERSION)<<",\n  \"openssl\": "<<json(OpenSSL_version(OPENSSL_VERSION))
        <<",\n  \"mode\": "<<json(o.mode)<<",\n  \"memory_private_commit_limit_bytes\": "<<o.limit
        <<",\n  \"tile_mib\": "<<o.tile_mib<<",\n  \"logical_cpu\": "<<o.core
        <<",\n  \"repetitions\": "<<o.repetitions<<",\n  \"warmup\": "<<o.warmup
        <<",\n  \"order_seed\": "<<json(hex_seed(order_seed))
        <<",\n  \"profile_order_policy\": \"randomized once; all repetitions grouped per profile; one fixture live\""
        <<",\n  \"fixture_kind\": \"algebraic_fixed_identity\""
        <<",\n  \"full_ibe_implementation\": false,\n  \"constant_time\": false"
        <<",\n  \"timing_scope\": \"fixed-identity online compute; matrix input generation separately timed; Setup/Extract/PubEval excluded\""
        <<",\n  \"baseline_api\": \"JKN21 single-bit encapsulation/decapsulation; Abla24 encryption/decryption\""
        <<",\n  \"security_note\": \"full profile inputs retain previous base-LWE estimator results; fixtures and smoke do not certify end-to-end IBE security\""
        <<",\n  \"profiles\": [";
    for(std::size_t i=0;i<ps.size();++i){if(i)f<<',';f<<"\n    {\"id\": "<<json(ps[i].id)<<", \"config_sha256\": "<<json(file_sha256(o.data/(ps[i].id+".cfg")))<<'}';}
    f<<"\n  ]\n}\n";
}
void csv_header(std::ostream& out) {
    out<<"trial,order,mode,profile,scheme,n,m,a,dimension,ct_bytes,enc_cycles,dec_cycles,enc_seconds,dec_seconds,feed_seconds,prepare_seconds,peak_memory_bytes,quant_cycles,quant_seconds,scalar_cycles,scalar_seconds,baseline_noise_cycles,baseline_noise_seconds,serialization_cycles,serialization_seconds,matvec_cycles,matvec_seconds,seed_fresh,decoded_ok,full_dimensions,fixture_kind,status\n";
}
void csv_row(std::ostream& out,int trial,std::size_t order,const Options& o,const Profile& p,const Metrics& m,std::size_t ct_bytes) {
    auto cycles=[&](const Duration& d){return cycle_counter_available()?std::to_string(d.cycles):std::string();};
    out<<std::setprecision(12)<<trial<<','<<order<<','<<o.mode<<','<<p.id<<','<<p.scheme<<','<<p.n<<','<<p.m<<','<<p.a<<','<<p.d()<<','<<ct_bytes
        <<','<<cycles(m.enc)<<','<<cycles(m.dec)<<','<<m.enc.seconds<<','<<m.dec.seconds<<','<<m.feed.seconds<<','<<m.prepare.seconds
        <<','<<peak_memory_bytes()<<','<<cycles(m.quant)<<','<<m.quant.seconds<<','<<cycles(m.scalar)<<','<<m.scalar.seconds
        <<','<<cycles(m.noise)<<','<<m.noise.seconds<<','<<cycles(m.serialization)<<','<<m.serialization.seconds
        <<','<<cycles(m.matvec)<<','<<m.matvec.seconds<<",1,"<<(m.decoded?1:0)<<','<<(o.mode=="full"?1:0)<<",algebraic_fixed_identity,PASS\n";out.flush();
    if(!out)throw std::runtime_error("Cannot write result CSV");
}
// Real n/q/noise/layout, but only a selected window of complete polar blocks. This is
// not a reduced-n smoke test, a complete ciphertext, or an IBE decryption test.
std::uint64_t block_memory(const Profile& p,const Options& o) {
    const auto dimension=std::uint64_t(o.blocks)*p.layout.N;
    return tile_columns(p,o)*p.n*sizeof(Word)+4ULL*p.n*sizeof(Word)+
        2*dimension*sizeof(Word)+(p.bits_for(dimension)+7)/8+128000000ULL;
}
void block_preflight(const Profile& p,const Options& o) {
    platform_check(block_memory(p,o));
    std::cout<<p.id<<": REAL n="<<p.n<<", q_bits="<<p.a<<", full 2m="<<p.d()
        <<", measured="<<o.blocks<<" x "<<p.layout.N<<" coordinates; guarded budget="
        <<block_memory(p,o)/1000000.0<<" MB\n";
}
struct BlockResult {
    Metrics metrics; Duration validation,other,header,remainder;
    Seed private_seed{},public_seed{};
    std::size_t fragment_bytes=0;
    std::uint64_t block_offset=0;
    std::uint64_t scalar_decisions=0;
};
BlockResult encrypt_blocks(const Profile& p,const Modulus& mod,const Options& o,const Fixture& f,std::uint64_t block_offset) {
    BlockResult result; auto& m=result.metrics;
    result.block_offset=block_offset;
    const auto dimension=std::uint64_t(o.blocks)*p.layout.N;
    if(block_offset+o.blocks>p.d()/p.layout.N)throw std::invalid_argument("Selected block window is out of range");
    MatrixStream matrix(p,mod,f.matrix_seed,tile_columns(p,o));
    std::vector<Word> expected(static_cast<std::size_t>(dimension)); // validation-only storage
    Duration controls;
    const auto start=clock_stamp();
    Writer writer(p.bits_for(dimension));std::vector<Word> s(p.n);Word scalar;
    timed(m.scalar,[&]{
        result.private_seed=entropy_seed();result.public_seed=entropy_seed();
        Rng rng(result.private_seed,"block-secret-scalar/"+p.id);
        const unsigned message=rng.bit();
        for(auto& z:s)z=mod.uniform(rng);
        scalar=mod.add(mod.dot(f.u.data(),s.data(),p.n),mod.encode(discrete_gaussian(p.r,rng,m.sampling)));
        if(message)scalar=mod.add(scalar,mod.encode(p.q/2));
    });
    result.scalar_decisions=m.sampling.decisions;
    Rng private_rng(result.private_seed,"block-vector-randomness/"+p.id);
    timed(result.header,[&]{writer.word(scalar,p.a);writer.seed(result.public_seed);});
    std::vector<Word> pending;pending.reserve(p.layout.N);std::array<Word,256> projected{};
    std::uint64_t block=0;double progress=start.seconds;
    for(std::uint64_t offset=0;offset<dimension;){
        std::size_t count=0;
        timed(m.feed,[&]{count=matrix.fill(block_offset*p.layout.N+offset,dimension-offset);});
        timed(m.matvec,[&]{
            for(std::size_t c=0;c<count;++c)projected[c]=mod.dot(matrix.tile.data()+c*p.n,s.data(),p.n);
        });
        for(std::size_t c=0;c<count;++c){
            pending.push_back(projected[c]);
            if(pending.size()==p.layout.N){
                std::vector<Big> b;
                timed(m.quant,[&]{
                    std::vector<Big> source;source.reserve(p.layout.N);
                    for(const auto& z:pending)source.push_back(to_big(z));
                    b=polar_sample_block(source,p.layout,result.public_seed,block_offset+block,private_rng,m.sampling);
                });
                timed(m.serialization,[&]{pack_polar(writer,b,p,result.public_seed,block_offset+block);});
                timed(result.validation,[&]{
                    for(unsigned j=0;j<p.layout.N;++j)expected[block*p.layout.N+j]=mod.encode(b[j]);
                });
                ++block;pending.clear();
            }
        }
        offset+=count;
        timed(controls,[&]{platform_check(block_memory(p,o));heartbeat("real-parameter block encryption",offset,dimension,progress);});
    }
    if(!pending.empty()||block!=o.blocks)throw std::runtime_error("Incomplete block encryption");
    writer.finish();m.enc.add(start,clock_stamp());
    const auto excluded_cycles=m.feed.cycles+result.validation.cycles+controls.cycles;
    const auto excluded_seconds=m.feed.seconds+result.validation.seconds+controls.seconds;
    if(m.enc.cycles<excluded_cycles || m.enc.seconds<excluded_seconds)throw std::runtime_error("Invalid block timer partition");
    m.enc.cycles-=excluded_cycles;m.enc.seconds-=excluded_seconds;
    if(m.enc.cycles<m.matvec.cycles+m.quant.cycles || m.enc.seconds<m.matvec.seconds+m.quant.seconds)
        throw std::runtime_error("Negative other-operation time");
    result.other.cycles=m.enc.cycles-m.matvec.cycles-m.quant.cycles;
    result.other.seconds=m.enc.seconds-m.matvec.seconds-m.quant.seconds;
    const auto components=m.scalar.seconds+result.header.seconds+m.serialization.seconds;
    if(result.other.seconds<components)throw std::runtime_error("Negative block remainder timer");
    result.remainder.seconds=result.other.seconds-components;
    result.remainder.cycles=result.other.cycles-m.scalar.cycles-result.header.cycles-m.serialization.cycles;
    result.fragment_bytes=writer.bytes.size();
    timed(result.validation,[&]{
        Reader reader(writer.bytes,p.bits_for(dimension));
        if(to_big(reader.word(p.a))!=to_big(scalar)||reader.seed()!=result.public_seed)
            throw std::runtime_error("Fragment scalar/seed roundtrip failed");
        for(std::uint64_t b=0;b<o.blocks;++b){
            const auto recovered=unpack_polar(reader,p,mod,result.public_seed,block_offset+b);
            for(unsigned j=0;j<p.layout.N;++j)
                if(to_big(recovered[j])!=to_big(expected[b*p.layout.N+j]))
                    throw std::runtime_error("Fragment codec roundtrip failed");
        }
        reader.finish();
    });
    return result;
}
void block_header(std::ostream& f) {
    f<<"trial,order,mode,profile,n,m,a,full_dimension,blocks,block_length,processed_dimension,fragment_bytes,matrix_cycles,quant_cycles,other_cycles,total_cycles,matrix_seconds,quant_seconds,other_seconds,total_seconds,feed_seconds,validation_seconds,matrix_pct,quant_pct,other_pct,peak_memory_bytes,codec_ok,full_parameter_dimensions,complete_ciphertext,status,block_offset,scalar_seconds,header_seconds,pack_seconds,remainder_seconds,decisions,precision_retries,max_precision,gaussian_proposals,scalar_decisions,vector_decisions\n";
}
void block_row(std::ostream& out,int trial,std::size_t order,const Options& o,const Profile& p,const BlockResult& b) {
    const auto& m=b.metrics;
    auto cyc=[&](const Duration& d){return cycle_counter_available()?std::to_string(d.cycles):std::string();};
    out<<std::setprecision(14)<<trial<<','<<order<<",blocks,"<<p.id<<','<<p.n<<','<<p.m<<','<<p.a<<','<<p.d()
        <<','<<o.blocks<<','<<p.layout.N<<','<<o.blocks*p.layout.N<<','<<b.fragment_bytes
        <<','<<cyc(m.matvec)<<','<<cyc(m.quant)<<','<<cyc(b.other)<<','<<cyc(m.enc)
        <<','<<m.matvec.seconds<<','<<m.quant.seconds<<','<<b.other.seconds<<','<<m.enc.seconds
        <<','<<m.feed.seconds<<','<<b.validation.seconds
        <<','<<100*m.matvec.seconds/m.enc.seconds<<','<<100*m.quant.seconds/m.enc.seconds<<','<<100*b.other.seconds/m.enc.seconds
        <<','<<peak_memory_bytes()<<",1,1,0,PASS,"<<b.block_offset
        <<','<<m.scalar.seconds<<','<<b.header.seconds<<','<<m.serialization.seconds<<','<<b.remainder.seconds
        <<','<<m.sampling.decisions<<','<<m.sampling.retries<<','<<m.sampling.max_precision<<','<<m.sampling.gaussian_proposals
        <<','<<b.scalar_decisions<<','<<m.sampling.decisions-b.scalar_decisions<<'\n';out.flush();
    if(!out)throw std::runtime_error("Cannot write block measurement");
}
void run_block_benchmark(const Options& o,std::vector<Profile> profiles,fs::path& active_output) {
    if(o.output.empty()||fs::exists(o.output))throw std::invalid_argument("Output must name a new, nonexistent directory");
    for(const auto& p:profiles)block_preflight(p,o);
    const Seed order_seed=entropy_seed();Rng order_rng(order_seed,"block-profile-order");
    for(std::size_t i=profiles.size();i>1;--i)std::swap(profiles[i-1],profiles[order_rng.below(Big(static_cast<unsigned long>(i))).get_ui()]);
    fs::create_directories(o.output);active_output=o.output;
    std::ofstream meta(o.output/"metadata.json");
    meta<<"{\n  \"schema\": 2,\n  \"mode\": \"blocks\",\n  \"share_basis\": \"wall_time_seconds\",\n  \"platform\": "<<json(platform_description())
        <<",\n  \"cycle_counter\": "<<json(cycle_counter_name())<<",\n  \"cycle_counter_available\": "<<(cycle_counter_available()?"true":"false")
        <<",\n  \"compiler\": "<<json(__VERSION__)<<",\n  \"gmp\": "<<json(gmp_version)<<",\n  \"mpfr\": "<<json(mpfr_get_version())
        <<",\n  \"flint\": "<<json(FLINT_VERSION)<<",\n  \"openssl\": "<<json(OpenSSL_version(OPENSSL_VERSION))
        <<",\n  \"blocks\": "<<o.blocks<<",\n  \"repetitions\": "<<o.repetitions<<",\n  \"warmup\": "<<o.warmup
        <<",\n  \"configured_memory_budget_bytes\": "<<o.limit<<",\n  \"resident_stop_threshold_bytes\": 1500000000,\n  \"memory_limit_os_enforced\": false,\n  \"tile_mib\": "<<o.tile_mib<<",\n  \"logical_cpu\": "<<o.core
        <<",\n  \"fixture_kind\": \"uniform_fixed_identity_encryption_fixture\""
        <<",\n  \"order_seed\": "<<json(hex_seed(order_seed))
        <<",\n  \"profile_order_policy\": \"randomized once; repetitions grouped per profile\""
        <<",\n  \"block_selection\": \"consecutive B-block windows; stratified starts across legal full-vector range over warmup and trials, unless --block-offset is explicit\""
        <<",\n  \"full_parameter_dimensions\": true,\n  \"complete_ciphertext\": false,\n  \"full_ibe_implementation\": false,\n  \"constant_time\": false"
        <<",\n  \"scope\": \"Real n/q/r/S/frozen layout; window encryption only. Feed, validation and progress excluded. No private-key setup or decryption.\""
        <<",\n  \"other_operations\": \"scalar_seconds and header_seconds are one-time; pack_seconds is per-block; remainder includes allocation and loop/timer bookkeeping. other=total-matrix-quant.\""
        <<",\n  \"precision\": {\"initial_bits\":384,\"maximum_bits\":1536,\"coin_bits\":256,\"probability_enclosure_bits\":300}"
        <<",\n  \"seed_note\": \"diagnostics contains test-only random seeds for replay; no user secrets or production keys\""
        <<",\n  \"source_sha256\": {";
    const auto src=o.data.parent_path()/"src";
    bool first=true;
    for(const auto* name:{"main.cpp","core_arithmetic.cpp","sampler.cpp","platform.cpp","core.hpp","profile_hashes.hpp"}){
        if(fs::exists(src/name)){if(!first)meta<<',';first=false;meta<<json(name)<<':'<<json(file_sha256(src/name));}
    }
    meta<<"},\n  \"profiles\": [";
    for(std::size_t i=0;i<profiles.size();++i){const auto& p=profiles[i];if(i)meta<<',';
        meta<<"\n    {\"id\": "<<json(p.id)<<", \"config_sha256\": "<<json(file_sha256(o.data/(p.id+".cfg")))
            <<", \"n\": "<<p.n<<", \"m\": "<<p.m<<", \"a\": "<<p.a<<", \"full_dimension\": "<<p.d()<<'}';
    }
    meta<<"\n  ]\n}\n";meta.flush();if(!meta)throw std::runtime_error("Cannot write block metadata");
    std::ofstream raw(o.output/"raw.csv"),warm(o.output/"warmup.csv"),details(o.output/"diagnostics.txt");
    if(!raw||!warm||!details)throw std::runtime_error("Cannot open block output files");block_header(raw);block_header(warm);
    for(std::size_t order=0;order<profiles.size();++order){
        const auto& p=profiles[order];const Modulus mod(p.q.get_str(),p.a);Fixture f;f.matrix_seed=entropy_seed();
        Rng public_rng(f.matrix_seed,"block-public-u/"+p.id);f.u.resize(p.n);for(auto& z:f.u)z=mod.uniform(public_rng);
        details<<p.id<<" matrix_fixture_seed="<<hex_seed(f.matrix_seed)<<'\n';
        std::set<std::string> public_seeds,private_seeds;
        std::cout<<"REAL-PARAMETER BLOCKS "<<p.id<<std::endl;
        for(int trial=-static_cast<int>(o.warmup);trial<static_cast<int>(o.repetitions);++trial){
            const auto slots=o.warmup+o.repetitions;
            const auto index=static_cast<unsigned>(trial+static_cast<int>(o.warmup));
            const auto last_start=p.d()/p.layout.N-o.blocks;
            const auto block_offset=o.block_offset!=std::numeric_limits<std::uint64_t>::max() ? o.block_offset :
                (slots>1 ? (last_start*index)/(slots-1) : last_start/2);
            const auto b=encrypt_blocks(p,mod,o,f,block_offset);
            if(!public_seeds.insert(hex_seed(b.public_seed)).second||!private_seeds.insert(hex_seed(b.private_seed)).second)
                throw std::runtime_error("Repeated block encryption seed");
            block_row(trial<0?warm:raw,trial,order,o,p,b);
            details<<p.id<<" trial="<<trial<<" test_private_seed="<<hex_seed(b.private_seed)<<" public_seed="<<hex_seed(b.public_seed)
                <<" decisions="<<b.metrics.sampling.decisions<<" precision_retries="<<b.metrics.sampling.retries
                <<" max_precision="<<b.metrics.sampling.max_precision<<" block_offset="<<block_offset<<'\n';details.flush();
            std::cout<<"  PASS trial="<<trial<<" matrix="<<100*b.metrics.matvec.seconds/b.metrics.enc.seconds
                <<"%, quant="<<100*b.metrics.quant.seconds/b.metrics.enc.seconds<<"%, other="<<100*b.other.seconds/b.metrics.enc.seconds
                <<"%; measured fragment="<<b.metrics.enc.seconds<<" s; feed="<<b.metrics.feed.seconds<<" s\n";
        }
    }
    std::ofstream done(o.output/"COMPLETED.txt");done<<"All requested real-parameter BLOCK measurements completed; not complete ciphertext timing.\n";
    done.flush();if(!done)throw std::runtime_error("Cannot write block completion marker");
    std::cout<<"BLOCKS COMPLETED: "<<o.output.string()<<'\n';
}
// A streaming digest of canonical 40-byte little-endian residues checks every
// reconstructed coordinate without retaining the full quantized vector.
class CoordinateDigest {
    EVP_MD_CTX* context_=nullptr;
public:
    CoordinateDigest():context_(EVP_MD_CTX_new()) {
        if(!context_ || EVP_DigestInit_ex(context_,EVP_sha256(),nullptr)!=1)
            throw std::runtime_error("Coordinate digest initialization failed");
    }
    ~CoordinateDigest(){EVP_MD_CTX_free(context_);}
    CoordinateDigest(const CoordinateDigest&)=delete;
    CoordinateDigest& operator=(const CoordinateDigest&)=delete;
    void word(const Word& value) {
        unsigned char bytes[40];
        for(unsigned i=0;i<40;++i)bytes[i]=static_cast<unsigned char>(value.limb[i/8]>>(8*(i%8)));
        if(EVP_DigestUpdate(context_,bytes,sizeof bytes)!=1)throw std::runtime_error("Coordinate digest update failed");
    }
    std::string finish() {
        unsigned char hash[32];unsigned length=0;
        if(EVP_DigestFinal_ex(context_,hash,&length)!=1 || length!=32)throw std::runtime_error("Coordinate digest finalize failed");
        std::ostringstream out;
        for(auto c:hash)out<<std::hex<<std::setw(2)<<std::setfill('0')<<unsigned(c);
        return out.str();
    }
};
std::uint64_t codec_memory(const Profile& p) {
    return p.ct_bytes()+128000000ULL; // Only packed output + one block + library reserve.
}
struct CodecResult {
    Duration feed,scalar,header,quant,pack,unpack,validation,artifact_io,total;
    SampleStats sampling;
    Seed input_seed{},private_seed{},public_seed{};
    std::uint64_t bytes=0;
    std::uint64_t scalar_decisions=0;
    std::string coordinate_hash,artifact_hash;
};
CodecResult full_codec(const Profile& p,const Modulus& mod,const Options& o,int trial) {
    CodecResult result;Duration controls;CoordinateDigest encoded,decoded;
    const auto started=clock_stamp();
    Writer writer(p.ct_bits());Word scalar;
    timed(result.scalar,[&]{
        result.input_seed=entropy_seed();result.private_seed=entropy_seed();result.public_seed=entropy_seed();
        Rng scalar_rng(result.private_seed,"fullcodec-scalar-fixture/"+p.id);
        // The inner product is a synthetic uniform residue. This is NOT an
        // evaluated IBE scalar and this mode reports no encryption timing.
        scalar=mod.add(mod.uniform(scalar_rng),mod.encode(discrete_gaussian(p.r,scalar_rng,result.sampling)));
        if(scalar_rng.bit())scalar=mod.add(scalar,mod.encode(p.q/2));
    });
    result.scalar_decisions=result.sampling.decisions;
    Rng input_rng(result.input_seed,"fullcodec-uniform-input/"+p.id);
    Rng private_rng(result.private_seed,"fullcodec-vector-randomness/"+p.id);
    timed(result.header,[&]{writer.word(scalar,p.a);writer.seed(result.public_seed);});
    const auto blocks=p.d()/p.layout.N;double progress=started.seconds;
    for(std::uint64_t block=0;block<blocks;++block){
        std::vector<Big> source(p.layout.N),quantized;
        timed(result.feed,[&]{for(auto& z:source)z=to_big(mod.uniform(input_rng));});
        timed(result.quant,[&]{quantized=polar_sample_block(source,p.layout,result.public_seed,block,private_rng,result.sampling);});
        timed(result.pack,[&]{pack_polar(writer,quantized,p,result.public_seed,block);});
        timed(result.validation,[&]{for(const auto& z:quantized)encoded.word(mod.encode(z));});
        timed(controls,[&]{platform_check(codec_memory(p));heartbeat("full-length quantize/pack",block+1,blocks,progress);});
    }
    writer.finish();result.bytes=writer.bytes.size();
    if(result.bytes!=p.reference_bytes)throw std::runtime_error("Full codec byte count disagrees with frozen reference");
    Reader reader(writer.bytes,p.ct_bits());
    timed(result.unpack,[&]{
        if(to_big(reader.word(p.a))!=to_big(scalar) || reader.seed()!=result.public_seed)
            throw std::runtime_error("Full codec scalar/seed roundtrip failed");
    });
    for(std::uint64_t block=0;block<blocks;++block){
        std::vector<Word> reconstructed;
        timed(result.unpack,[&]{reconstructed=unpack_polar(reader,p,mod,result.public_seed,block);});
        timed(result.validation,[&]{for(const auto& z:reconstructed)decoded.word(z);});
        timed(controls,[&]{platform_check(codec_memory(p));heartbeat("full-length unpack/reconstruct",block+1,blocks,progress);});
    }
    reader.finish();
    timed(result.validation,[&]{
        result.coordinate_hash=encoded.finish();
        if(result.coordinate_hash!=decoded.finish())throw std::runtime_error("Full codec reconstructed-coordinate digest mismatch");
    });
    result.total.add(started,clock_stamp());
    result.total.seconds-=controls.seconds;
    result.total.cycles-=controls.cycles;
    if(trial==0){
        const auto artifact=o.output/(p.id+"_complete_format_test.bin");
        timed(result.artifact_io,[&]{
            std::ofstream f(artifact,std::ios::binary);
            f.write(reinterpret_cast<const char*>(writer.bytes.data()),static_cast<std::streamsize>(writer.bytes.size()));
            f.flush();if(!f)throw std::runtime_error("Cannot save full-format test artifact");
        });
        if(fs::file_size(artifact)!=result.bytes)throw std::runtime_error("Saved full-format artifact length mismatch");
        result.artifact_hash=file_sha256(artifact);
    }
    return result;
}
void codec_header(std::ostream& out) {
    out<<"trial,order,mode,profile,n,m,a,full_dimension,blocks,ct_bits,ct_bytes,scalar_fixture_seconds,header_seconds,quant_seconds,pack_seconds,unpack_reconstruct_seconds,feed_seconds,validation_seconds,total_harness_seconds,artifact_io_seconds,peak_memory_bytes,decisions,precision_retries,max_precision,gaussian_proposals,coordinate_sha256,artifact_sha256,codec_ok,complete_format,full_ibe_ciphertext,status,scalar_decisions,vector_decisions\n";
}
void codec_row(std::ostream& out,int trial,std::size_t order,const Profile& p,const CodecResult& r) {
    out<<std::setprecision(14)<<trial<<','<<order<<",fullcodec,"<<p.id<<','<<p.n<<','<<p.m<<','<<p.a<<','<<p.d()<<','<<p.d()/p.layout.N
        <<','<<p.ct_bits()<<','<<r.bytes<<','<<r.scalar.seconds<<','<<r.header.seconds<<','<<r.quant.seconds<<','<<r.pack.seconds
        <<','<<r.unpack.seconds<<','<<r.feed.seconds<<','<<r.validation.seconds<<','<<r.total.seconds<<','<<r.artifact_io.seconds
        <<','<<peak_memory_bytes()<<','<<r.sampling.decisions<<','<<r.sampling.retries<<','<<r.sampling.max_precision
        <<','<<r.sampling.gaussian_proposals<<','<<r.coordinate_hash<<','<<r.artifact_hash<<",1,1,0,PASS,"<<r.scalar_decisions
        <<','<<r.sampling.decisions-r.scalar_decisions<<'\n';
    out.flush();if(!out)throw std::runtime_error("Cannot write full codec result");
}
void run_full_codec(const Options& o,std::vector<Profile> profiles,fs::path& active_output) {
    if(o.output.empty()||fs::exists(o.output))throw std::invalid_argument("Output must name a new, nonexistent directory");
    for(const auto& p:profiles)platform_check(codec_memory(p));
    const Seed order_seed=entropy_seed();Rng order_rng(order_seed,"fullcodec-profile-order");
    for(std::size_t i=profiles.size();i>1;--i)std::swap(profiles[i-1],profiles[order_rng.below(Big(static_cast<unsigned long>(i))).get_ui()]);
    fs::create_directories(o.output);active_output=o.output;
    std::ofstream meta(o.output/"metadata.json");
    meta<<"{\n  \"schema\": 3,\n  \"mode\": \"fullcodec\",\n  \"platform\": "<<json(platform_description())
        <<",\n  \"compiler\": "<<json(__VERSION__)<<",\n  \"gmp\": "<<json(gmp_version)<<",\n  \"mpfr\": "<<json(mpfr_get_version())
        <<",\n  \"flint\": "<<json(FLINT_VERSION)<<",\n  \"openssl\": "<<json(OpenSSL_version(OPENSSL_VERSION))
        <<",\n  \"repetitions\": "<<o.repetitions<<",\n  \"warmup\": "<<o.warmup<<",\n  \"order_seed\": "<<json(hex_seed(order_seed))
        <<",\n  \"configured_memory_budget_bytes\": "<<o.limit<<",\n  \"resident_stop_threshold_bytes\": 1500000000,\n  \"memory_limit_os_enforced\": false"
        <<",\n  \"scope\": \"All 2m coordinates quantized, packed and reconstructed; synthetic uniform-residue source, synthetic scalar inner product. No Setup, Extract, PubEval, matrix multiplication or IBE decryption.\""
        <<",\n  \"complete_format\": true,\n  \"full_ibe_ciphertext\": false,\n  \"constant_time\": false"
        <<",\n  \"validation\": \"Frozen-bit checks during packing; full stream reconstruction compared using SHA-256 of canonical 40-byte LE coordinates; scalar, seed, padding and exact byte count checked.\""
        <<",\n  \"artifact\": \"Trial 0 of each profile saves a complete-format test .bin, not an output of an implemented full IBE instance.\""
        <<",\n  \"timing\": \"Separate quantization, pack and unpack/reconstruction wall time; input, digest validation, scalar fixture and I/O reported separately. No CPU-cycle estimate or decryption claim.\""
        <<",\n  \"precision\": {\"initial_bits\":384,\"maximum_bits\":1536,\"coin_bits\":256,\"probability_enclosure_bits\":300}"
        <<",\n  \"seed_note\": \"All diagnostic seeds are disposable test data, not production secrets.\""
        <<",\n  \"source_sha256\": {";
    const auto src=o.data.parent_path()/"src";bool first=true;
    for(const auto* name:{"main.cpp","core_arithmetic.cpp","sampler.cpp","platform.cpp","core.hpp","profile_hashes.hpp"}){
        if(fs::exists(src/name)){if(!first)meta<<',';first=false;meta<<json(name)<<':'<<json(file_sha256(src/name));}
    }
    meta<<"},\n  \"profiles\": [";
    for(std::size_t i=0;i<profiles.size();++i){const auto& p=profiles[i];if(i)meta<<',';
        meta<<"\n    {\"id\": "<<json(p.id)<<", \"config_sha256\": "<<json(file_sha256(o.data/(p.id+".cfg")))
            <<", \"n\": "<<p.n<<", \"m\": "<<p.m<<", \"a\": "<<p.a<<", \"full_dimension\": "<<p.d()<<'}';
    }
    meta<<"\n  ]\n}\n";meta.flush();if(!meta)throw std::runtime_error("Cannot write full codec metadata");
    std::ofstream raw(o.output/"raw.csv"),warm(o.output/"warmup.csv"),details(o.output/"diagnostics.txt");
    if(!raw||!warm||!details)throw std::runtime_error("Cannot open full codec outputs");codec_header(raw);codec_header(warm);
    for(std::size_t order=0;order<profiles.size();++order){
        const auto& p=profiles[order];const Modulus mod(p.q.get_str(),p.a);std::set<std::string> seeds;
        std::cout<<"FULL-LENGTH CODEC "<<p.id<<" blocks="<<p.d()/p.layout.N<<std::endl;
        for(int trial=-static_cast<int>(o.warmup);trial<static_cast<int>(o.repetitions);++trial){
            const auto r=full_codec(p,mod,o,trial);
            for(const auto& seed:{r.input_seed,r.private_seed,r.public_seed})
                if(!seeds.insert(hex_seed(seed)).second)throw std::runtime_error("Repeated full codec test seed");
            codec_row(trial<0?warm:raw,trial,order,p,r);
            details<<p.id<<" trial="<<trial<<" input_seed="<<hex_seed(r.input_seed)<<" private_seed="<<hex_seed(r.private_seed)
                <<" public_seed="<<hex_seed(r.public_seed)<<" coordinate_sha256="<<r.coordinate_hash
                <<" decisions="<<r.sampling.decisions<<" precision_retries="<<r.sampling.retries
                <<" max_precision="<<r.sampling.max_precision<<'\n';details.flush();
            std::cout<<"  PASS trial="<<trial<<" bytes="<<r.bytes<<" quant="<<r.quant.seconds<<" pack="<<r.pack.seconds
                <<" unpack/reconstruct="<<r.unpack.seconds<<" seconds; peak="<<peak_memory_bytes()/1000000.0<<" MB\n";
        }
    }
    std::ofstream done(o.output/"COMPLETED.txt");
    done<<"Full-length quantization/format roundtrips completed. Synthetic sources; not full IBE encryption/decryption.\n";
    done.flush();if(!done)throw std::runtime_error("Cannot write full codec completion marker");
}
bool extension_selftest() {
    Profile p;p.id="extension_selftest";p.scheme="Ours";p.n=3;p.m=8;p.a=12;
    p.q=Big(1)<<p.a;p.r=3;p.S=8;p.sigma=16;p.polar=true;
    p.layout.a=p.a;p.layout.N=8;p.layout.stop=9;p.layout.width=p.S;p.layout.frozen.resize(p.a);
    p.layout.frozen[0]={0,1,2,3,4,5,6,7};p.layout.frozen[1]={0,1,2,3};
    p.layout.frozen[2]={0,1};p.layout.frozen[3]={0};p.reference_bytes=p.ct_bytes();
    validate_layout(p.layout);const Modulus mod(p.q.get_str(),p.a);Options o;o.blocks=1;
    const auto codec=full_codec(p,mod,o,-1);
    if(codec.bytes!=p.reference_bytes||codec.coordinate_hash.size()!=64||codec.sampling.decisions-codec.scalar_decisions!=114)return false;
    Fixture f;f.matrix_seed=entropy_seed();f.u.resize(p.n);Rng rng(f.matrix_seed,"extension-test-public-u");
    for(auto& z:f.u)z=mod.uniform(rng);
    const auto block=encrypt_blocks(p,mod,o,f,1);
    if(block.block_offset!=1||block.fragment_bytes!=(p.bits_for(8)+7)/8||block.metrics.sampling.decisions-block.scalar_decisions!=57)return false;
    bool rejected=false;
    try{encrypt_blocks(p,mod,o,f,2);}catch(const std::invalid_argument&){rejected=true;}
    return rejected;
}
void write_u64(std::ostream& out,std::uint64_t value){unsigned char b[8];for(unsigned j=0;j<8;++j)b[j]=static_cast<unsigned char>(value>>(8*j));out.write(reinterpret_cast<char*>(b),8);}
std::uint64_t read_u64(std::istream& in){unsigned char b[8];in.read(reinterpret_cast<char*>(b),8);if(!in)throw std::runtime_error("Truncated fixture header");std::uint64_t value=0;for(unsigned j=0;j<8;++j)value|=std::uint64_t(b[j])<<(8*j);return value;}
void write_word(std::ostream& out,const Word& w){unsigned char b[40];for(unsigned j=0;j<40;++j)b[j]=static_cast<unsigned char>(w.limb[j/8]>>(8*(j%8)));out.write(reinterpret_cast<char*>(b),40);}
Word read_word(std::istream& in){unsigned char b[40];in.read(reinterpret_cast<char*>(b),40);if(!in)throw std::runtime_error("Truncated fixture word");Word w;for(unsigned j=0;j<40;++j)w.limb[j/8]|=mp_limb_t(b[j])<<(8*(j%8));return w;}
void save_fixture(const fs::path& path,const Profile& p,Fixture& f) {
    timed(f.io,[&]{
        std::ofstream out(path,std::ios::binary);out.write("QRFIX01\n",8);write_u64(out,p.n);write_u64(out,p.d());write_u64(out,p.a);
        out.write(reinterpret_cast<const char*>(f.matrix_seed.data()),32);out.write(reinterpret_cast<const char*>(f.key_seed.data()),32);
        for(const auto& w:f.e)write_word(out,w);for(const auto& w:f.u)write_word(out,w);
        out.flush();if(!out)throw std::runtime_error("Cannot save test fixture");
    });
    if(fs::file_size(path)!=96+40*(p.d()+p.n))throw std::runtime_error("Fixture file length mismatch");
}
Fixture load_fixture(const fs::path& path,const Profile& p) {
    Fixture f;
    timed(f.io,[&]{
        if(fs::file_size(path)!=96+40*(p.d()+p.n))throw std::runtime_error("Fixture file length does not match selected dimensions");
        std::ifstream in(path,std::ios::binary);char magic[8];in.read(magic,8);
        if(!in || std::memcmp(magic,"QRFIX01\n",8)!=0 || read_u64(in)!=p.n || read_u64(in)!=p.d() || read_u64(in)!=p.a)
            throw std::runtime_error("Fixture header/profile mismatch");
        in.read(reinterpret_cast<char*>(f.matrix_seed.data()),32);in.read(reinterpret_cast<char*>(f.key_seed.data()),32);
        f.e.resize(p.d());f.u.resize(p.n);
        for(auto& w:f.e)w=read_word(in);for(auto& w:f.u)w=read_word(in);
        if(in.peek()!=std::char_traits<char>::eof())throw std::runtime_error("Trailing fixture bytes");
    });
    return f;
}
struct KeySummary {Big norm_squared=0,max_absolute=0;std::uint64_t nonzero=0;};
KeySummary check_key(const Profile& p,Fixture& f) {
    KeySummary summary;
    timed(f.validation,[&]{
        if(f.e.size()!=p.d()||f.u.size()!=p.n)throw std::runtime_error("Fixture vector dimension mismatch");
        for(const auto& word:f.e){Big z=to_big(word);if(z>=p.q)throw std::runtime_error("Noncanonical key residue");if(z>p.q/2)z-=p.q;
            if(abs(z)>16*p.sigma)throw std::runtime_error("Test key outside declared scalar-sampler truncation");
            if(z!=0)++summary.nonzero;summary.norm_squared+=z*z;const Big magnitude=abs(z);if(magnitude>summary.max_absolute)summary.max_absolute=magnitude;
        }
        for(const auto& w:f.u)if(to_big(w)>=p.q)throw std::runtime_error("Noncanonical public vector");
    });
    return summary;
}
std::vector<unsigned char> load_ciphertext(const fs::path& file,const Profile& p) {
    if(fs::file_size(file)!=p.ct_bytes())throw std::runtime_error("Saved ciphertext file length mismatch");
    std::vector<unsigned char> result(p.ct_bytes());std::ifstream in(file,std::ios::binary);
    in.read(reinterpret_cast<char*>(result.data()),static_cast<std::streamsize>(result.size()));
    if(!in)throw std::runtime_error("Cannot read ciphertext");return result;
}
void write_encdec_metadata(const Options& o,const std::vector<Profile>& profiles) {
    std::ofstream meta(o.output/"metadata.json");
    meta<<"{\n  \"schema\": 4,\n  \"mode\": "<<json(o.mode)<<",\n  \"platform\": "<<json(platform_description())
        <<",\n  \"compiler\": "<<json(__VERSION__)<<",\n  \"gmp\": "<<json(gmp_version)<<",\n  \"mpfr\": "<<json(mpfr_get_version())
        <<",\n  \"flint\": "<<json(FLINT_VERSION)<<",\n  \"openssl\": "<<json(OpenSSL_version(OPENSSL_VERSION))
        <<",\n  \"repetitions\": "<<o.repetitions<<",\n  \"warmup\": "<<o.warmup<<",\n  \"micro_blocks\": "<<o.blocks
        <<",\n  \"tile_mib\": "<<o.tile_mib<<",\n  \"logical_cpu\": "<<o.core
        <<",\n  \"configured_memory_budget_bytes\": "<<o.limit<<",\n  \"resident_stop_threshold_bytes\":1500000000,\n  \"memory_limit_os_enforced\":false"
        <<",\n  \"fixture_kind\": \"dense_Gaussian_test_key_and_u_equals_Me; NOT Extract output\""
        <<",\n  \"matrix_supplier\": \"test-only AES-256-CTR; key=SHAKE256(version/profile/matrix_seed); 128-bit IV=BE64(global column)||BE64(0); each column uses fewer than 2^64 counter blocks; mask each residue to a bits\""
#ifdef __APPLE__
        <<",\n  \"matrix_backend\": \"macOS CommonCrypto, stream checked against OpenSSL AES-256-CTR in selftests\""
#else
        <<",\n  \"matrix_backend\": \"OpenSSL AES-256-CTR\""
#endif
        <<",\n  \"matrix_supplier_scope\": \"synthetic pseudorandom fixed-identity matrix, not implemented Setup/PubEval and not a seeded-MPK compression claim\""
        <<",\n  \"private_key\": \"independent coordinate sampler D_Z,sigma with original finite truncation and interval coins; u=M e computed, not an output of trapdoor extraction; no Setup/Extract joint-distribution claim\""
        <<",\n  \"timing_scope\": \"Enc executes all fixed-identity scalar, M^T s, polar quantization and serialization operations. Enc core excludes test-matrix supply and resource/progress controls. Dec executes parsing, reconstruction, full private-key inner product and decision. Offline preparation, file I/O and extra validation separate. PubEval excluded.\""
        <<",\n  \"message_policy\": \"trial 0 encrypts 0, trial 1 encrypts 1, then alternates; fresh s, scalar noise, private tape and public seed each time\""
        <<",\n  \"complete_dimensions\": "<<(o.mode=="encdec"?"true":"false")<<",\n  \"real_Extract_output\":false,\n  \"constant_time\":false"
        <<",\n  \"precision\": {\"initial_bits\":384,\"maximum_bits\":1536,\"coin_bits\":256,\"probability_enclosure_bits\":300}"
        <<",\n  \"seed_note\": \"Persisted fixture and diagnostic seeds are disposable synthetic test data, not real keys.\""
        <<",\n  \"source_sha256\": {";
    const auto src=o.data.parent_path()/"src";bool first=true;
    for(const auto* name:{"main.cpp","core_arithmetic.cpp","sampler.cpp","platform.cpp","core.hpp","profile_hashes.hpp"}){
        if(fs::exists(src/name)){if(!first)meta<<',';first=false;meta<<json(name)<<':'<<json(file_sha256(src/name));}
    }
    meta<<"},\n  \"profiles\": [";
    for(std::size_t i=0;i<profiles.size();++i){const auto& p=profiles[i];if(i)meta<<',';
        meta<<"\n    {\"id\": "<<json(p.id)<<", \"config_sha256\": "<<json(file_sha256(o.data/(p.id+".cfg")))
            <<", \"n\": "<<p.n<<", \"m\": "<<p.m<<", \"a\": "<<p.a<<", \"full_dimension\": "<<p.d()<<'}';
    }
    meta<<"\n  ]\n}\n";meta.flush();if(!meta)throw std::runtime_error("Cannot write metadata");
}
void encdec_header(std::ostream& out) {
    out<<"trial,mode,profile,n,m,a,full_dimension,active_dimension,blocks,message,recovered_message,ct_bytes,enc_core_seconds,enc_feed_seconds,enc_harness_seconds,matrix_seconds,quant_seconds,scalar_seconds,pack_seconds,enc_other_seconds,dec_seconds,dec_unpack_seconds,dec_dot_seconds,dec_decision_seconds,dec_other_seconds,artifact_io_seconds,validation_seconds,peak_memory_bytes,scalar_decisions,vector_decisions,precision_retries,max_precision,gaussian_proposals,decoded_ok,full_dimensions,real_extract_output,ciphertext_sha256,status\n";
}
void run_encdec(const Options& o,const std::vector<Profile>& originals,fs::path& active_output) {
    if(o.output.empty()||fs::exists(o.output))throw std::invalid_argument("Output must name a new, nonexistent directory");
    if(o.mode=="encdec"&&!o.allow_long)throw std::invalid_argument("Full EncDec requires explicit --allow-long-run");
    if(o.repetitions<2)throw std::invalid_argument("At least two trials are required to cover messages 0 and 1");
    fs::create_directories(o.output);active_output=o.output;write_encdec_metadata(o,originals);
    std::ofstream raw(o.output/"raw.csv"),warm(o.output/"warmup.csv"),prep(o.output/"preparation.csv"),details(o.output/"diagnostics.txt");
    if(!raw||!warm||!prep||!details)throw std::runtime_error("Cannot open EncDec outputs");encdec_header(raw);encdec_header(warm);
    prep<<"mode,profile,n,full_dimension,active_dimension,key_sampling_seconds,feed_seconds,transpose_seconds,matvec_seconds,prepare_harness_seconds,validation_seconds,artifact_io_seconds,key_decisions,key_gaussian_proposals,key_precision_retries,key_max_precision,key_nonzero,key_max_abs_bits,key_norm_squared_bits,peak_memory_bytes,fixture_sha256,source,status\n";
    for(const auto& original:originals){
        Profile p=original;if(o.mode=="micro"){p.m=o.blocks*p.layout.N/2;p.reference_bytes=p.ct_bytes();}
        preflight(p,o);const Modulus mod(p.q.get_str(),p.a);Duration preparation;SampleStats key_stats;
        Fixture fixture=o.fixture_dir.empty()?prepare_fixture(p,mod,o,preparation,key_stats):load_fixture(o.fixture_dir/(p.id+"_fixture.bin"),p);
        const auto key_summary=check_key(p,fixture);const auto fixture_file=o.output/(p.id+"_fixture.bin");save_fixture(fixture_file,p,fixture);
        timed(fixture.validation,[&]{
            const auto restored=load_fixture(fixture_file,p);
            if(restored.matrix_seed!=fixture.matrix_seed||restored.key_seed!=fixture.key_seed||restored.e.size()!=fixture.e.size()||restored.u.size()!=fixture.u.size())throw std::runtime_error("Restored fixture header mismatch");
            for(std::size_t j=0;j<fixture.e.size();++j)if(restored.e[j].limb!=fixture.e[j].limb)throw std::runtime_error("Restored key mismatch");
            for(std::size_t j=0;j<fixture.u.size();++j)if(restored.u[j].limb!=fixture.u[j].limb)throw std::runtime_error("Restored public vector mismatch");
        });
        std::string fixture_hash;timed(fixture.validation,[&]{fixture_hash=file_sha256(fixture_file);});
        prep<<std::setprecision(14)<<o.mode<<','<<p.id<<','<<p.n<<','<<original.d()<<','<<p.d()<<','<<fixture.key_sampling.seconds<<','<<fixture.feed.seconds
            <<','<<fixture.transpose.seconds<<','<<fixture.matvec.seconds<<','<<fixture.total.seconds<<','<<fixture.validation.seconds<<','<<fixture.io.seconds
            <<','<<fixture.key_stats.decisions<<','<<fixture.key_stats.gaussian_proposals<<','<<fixture.key_stats.retries<<','<<fixture.key_stats.max_precision
            <<','<<key_summary.nonzero<<','<<mpz_sizeinbase(key_summary.max_absolute.get_mpz_t(),2)<<','<<mpz_sizeinbase(key_summary.norm_squared.get_mpz_t(),2)
            <<','<<peak_memory_bytes()<<','<<fixture_hash<<','<<(o.fixture_dir.empty()?"generated":"loaded")<<",PASS\n";prep.flush();
        details<<p.id<<" matrix_seed="<<hex_seed(fixture.matrix_seed)<<" key_seed="<<hex_seed(fixture.key_seed)
            <<" key_norm_squared="<<key_summary.norm_squared<<" key_max_absolute="<<key_summary.max_absolute<<" fixture_sha256="<<fixture_hash<<'\n';details.flush();
        std::set<std::string> seeds;
        for(int trial=-static_cast<int>(o.warmup);trial<static_cast<int>(o.repetitions);++trial){
            Metrics m;Seed public_seed{};unsigned message=static_cast<unsigned>(trial<0?-trial:trial)%2;
            const auto start=clock_stamp();auto ciphertext=encrypt(p,mod,o,fixture,message,public_seed,m);Duration harness;harness.add(start,clock_stamp());
            for(const auto& seed:{public_seed,m.scalar_seed,m.vector_seed})if(!seeds.insert(hex_seed(seed)).second)throw std::runtime_error("Repeated encryption seed");
            details<<p.id<<" trial="<<trial<<" message="<<message<<" scalar_seed="<<hex_seed(m.scalar_seed)<<" vector_seed="<<hex_seed(m.vector_seed)<<" public_seed="<<hex_seed(public_seed)<<'\n';details.flush();
            Duration io,validation;std::string hash;std::vector<unsigned char> restored;
            const auto file=o.output/(p.id+"_trial_"+std::to_string(trial)+".bin");
            timed(io,[&]{std::ofstream f(file,std::ios::binary);f.write(reinterpret_cast<const char*>(ciphertext.data()),static_cast<std::streamsize>(ciphertext.size()));f.flush();if(!f)throw std::runtime_error("Cannot write ciphertext artifact");restored=load_ciphertext(file,p);});
            timed(validation,[&]{if(restored!=ciphertext||ciphertext.size()!=p.reference_bytes)throw std::runtime_error("Ciphertext artifact mismatch");hash=file_sha256(file);});
            const unsigned recovered=decrypt(p,mod,fixture,restored,m);m.decoded=recovered==message;
            platform_check(planned_memory(p,o));
            const double enc_other=m.enc.seconds-m.matvec.seconds-m.quant.seconds-m.scalar.seconds-m.serialization.seconds;
            const double dec_other=m.dec.seconds-m.unpack.seconds-m.dec_dot.seconds-m.decision.seconds;
            if(enc_other<0||dec_other<0)throw std::runtime_error("Timer partition is negative");
            auto& out=trial<0?warm:raw;
            out<<std::setprecision(14)<<trial<<','<<o.mode<<','<<p.id<<','<<p.n<<','<<p.m<<','<<p.a<<','<<original.d()<<','<<p.d()<<','<<p.d()/p.layout.N<<','<<message<<','<<recovered<<','<<ciphertext.size()
                <<','<<m.enc.seconds<<','<<m.feed.seconds<<','<<harness.seconds<<','<<m.matvec.seconds<<','<<m.quant.seconds<<','<<m.scalar.seconds<<','<<m.serialization.seconds<<','<<enc_other
                <<','<<m.dec.seconds<<','<<m.unpack.seconds<<','<<m.dec_dot.seconds<<','<<m.decision.seconds<<','<<dec_other<<','<<io.seconds<<','<<validation.seconds<<','<<peak_memory_bytes()
                <<','<<m.scalar_decisions<<','<<m.sampling.decisions-m.scalar_decisions<<','<<m.sampling.retries<<','<<m.sampling.max_precision<<','<<m.sampling.gaussian_proposals
                <<','<<(m.decoded?1:0)<<','<<(o.mode=="encdec"?1:0)<<",0,"<<hash<<','<<(m.decoded?"PASS":"FAIL")<<'\n';out.flush();if(!out)throw std::runtime_error("Cannot write EncDec CSV");
            details<<p.id<<" trial="<<trial<<" message="<<message<<" scalar_seed="<<hex_seed(m.scalar_seed)<<" vector_seed="<<hex_seed(m.vector_seed)<<" public_seed="<<hex_seed(public_seed)<<" ciphertext_sha256="<<hash<<'\n';details.flush();
            std::cout<<(m.decoded?"PASS ":"FAIL ")<<p.id<<" trial="<<trial<<" message="<<message<<" bytes="<<ciphertext.size()<<" Enc_core="<<m.enc.seconds<<" feed="<<m.feed.seconds<<" Dec="<<m.dec.seconds<<" seconds\n";
            if(!m.decoded)throw std::runtime_error("Message recovery failed; failed trial and artifact retained");
        }
    }
    std::ofstream done(o.output/"COMPLETED.txt");done<<"All requested fixed-identity Enc/Dec tests completed. Synthetic Gaussian test keys, NOT Extract outputs. Mode="<<o.mode<<"\n";done.flush();if(!done)throw std::runtime_error("Cannot write completion marker");
}
bool encdec_selftest() {
    // Cross-provider equality at non-byte-aligned real residue widths, with
    // multi-block columns and nonzero global column indices. The optimized
    // supplier must emit exactly the reference AES-CTR bytes/residues.
    for(unsigned bits:{239U,270U}){
        Profile v;v.id="aes-cross-provider";v.n=10072;v.m=128;v.a=bits;v.q=Big(1)<<bits;
        Modulus mod(v.q.get_str(),v.a);Seed seed{};for(unsigned j=0;j<32;++j)seed[j]=static_cast<unsigned char>(j);
        MatrixStream native(v,mod,seed,3),reference(v,mod,seed,1,true);native.fill(253);
        for(unsigned c=0;c<3;++c){reference.fill(253+c);for(unsigned row=0;row<v.n;++row)if(native.tile[c*v.n+row].limb!=reference.tile[row].limb)return false;}
    }
    Profile p;p.id="test";p.scheme="Ours";p.n=3;p.m=8;p.a=16;p.q=Big(1)<<16;p.r=1;p.S=2;p.sigma=2;p.polar=true;
    p.layout.a=p.a;p.layout.N=8;p.layout.stop=7;p.layout.width=p.S;p.layout.frozen.resize(p.a);
    p.layout.frozen[0]={0,1,2,3,4,5,6,7};p.layout.frozen[1]={0,1,2,3};p.layout.frozen[2]={0};p.reference_bytes=p.ct_bytes();
    Options o;const Modulus mod(p.q.get_str(),p.a);Duration duration;SampleStats stats;const auto f=prepare_fixture(p,mod,o,duration,stats);
    MatrixStream matrix(p,mod,f.matrix_seed,5);std::vector<Big> oracle(p.n);
    for(std::uint64_t off=0;off<p.d();){const auto count=matrix.fill(off);for(std::size_t c=0;c<count;++c)for(unsigned r=0;r<p.n;++r)oracle[r]+=to_big(matrix.tile[c*p.n+r])*to_big(f.e[off+c]);off+=count;}
    for(unsigned r=0;r<p.n;++r){oracle[r]%=p.q;if(oracle[r]!=to_big(f.u[r]))return false;}
    for(unsigned wanted=0;wanted<2;++wanted){Metrics m;Seed seed{};unsigned message=wanted;const auto ct=encrypt(p,mod,o,f,message,seed,m);if(decrypt(p,mod,f,ct,m)!=wanted)return false;}
    return true;
}
void usage() {
    std::cout<<"R4-6 local fixed-identity Enc/Dec with dense Gaussian test keys (NOT Extract outputs)\n"
        <<" --selftest\n --mode micro --blocks 4 --profiles ours_mpk,ours_ct --repetitions 2 --warmup 0 --data data --output results/new_micro\n"
        <<" --mode encdec --profiles ours_mpk,ours_ct --repetitions 3 --warmup 0 --allow-long-run --data data --output results/new_full\n"
        <<" --mode verify --profiles ours_mpk --fixture-dir OLDOUTPUT --ciphertext OLDOUTPUT/ours_mpk_trial_0.bin --expected-message 0 --data data\n"
        <<" --plan --mode encdec --data data\nOptions: --fixture-dir OLDOUTPUT (reuse fixture), --tile-mib 32, --memory-limit-mb 1400, --core -1\n";
}
} // namespace

int main(int argc,char** argv) {
    fs::path active_output;
    try {
        const auto o=parse_options(argc,argv);
        if(argc==1||o.mode=="help"){usage();return 0;}
        install_memory_limit(o.limit);set_single_thread_affinity(o.core);flint_set_num_threads(1);
        if(o.selftest){
            if(!arithmetic_selftest()||!sampler_selftest()||!codec_selftest()||!encdec_selftest())throw std::runtime_error("Self-test returned false");
            std::cout<<"SELFTEST PASS (unchanged arithmetic/sampler, AES tile invariance, independent mpz u=M e oracle, both-message Enc/Dec)\n";return 0;
        }
        if(o.mode!="micro"&&o.mode!="encdec"&&o.mode!="verify")throw std::invalid_argument("Choose --mode micro, encdec or verify");
        auto profiles=selected_profiles(o);
        if(o.plan){for(const auto& p:profiles)preflight(p,o);std::cout<<"PLAN ONLY; no timing performed.\n";return 0;}
        if(o.mode=="verify"){
            if(profiles.size()!=1||o.fixture_dir.empty()||o.ciphertext.empty())throw std::invalid_argument("Verify requires one profile, --fixture-dir and --ciphertext");
            const auto& p=profiles[0];preflight(p,o);auto fixture=load_fixture(o.fixture_dir/(p.id+"_fixture.bin"),p);check_key(p,fixture);
            const auto ct=load_ciphertext(o.ciphertext,p);Metrics m;const Modulus mod(p.q.get_str(),p.a);
            const auto message=decrypt(p,mod,fixture,ct,m);if(message!=o.expected_message)throw std::runtime_error("Recovered artifact has unexpected message");
            std::cout<<"ARTIFACT VERIFY PASS message="<<message<<" Dec="<<m.dec.seconds<<" seconds; NOT an Extract-key validation\n";return 0;
        }
        run_encdec(o,profiles,active_output);std::cout<<"COMPLETED: "<<o.output.string()<<'\n';return 0;
    }catch(const std::exception& error){
        std::cerr<<"FAILED: "<<error.what()<<'\n';
        if(!active_output.empty()){std::ofstream f(active_output/"failure.txt");f<<error.what()<<"\nPartial rows are not a completed comparison.\n";}
        return 1;
    }
}
