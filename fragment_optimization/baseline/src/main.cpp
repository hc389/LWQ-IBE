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

namespace fs = std::filesystem;
using namespace bench;
namespace {
const std::vector<std::string> profile_ids = {"ours_mpk", "ours_mid", "ours_ct", "jkn_low", "jkn_joint", "abla_I_low", "abla_I_high", "abla_II"};
struct Options {
    std::string mode, profiles="representative";
    fs::path data, output;
    unsigned repetitions=1, warmup=0, tile_mib=32, blocks=4;
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
    Duration enc, dec, feed, prepare, quant, scalar, noise, serialization, matvec;
    SampleStats sampling;
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
        else if (arg=="--repetitions") o.repetitions=static_cast<unsigned>(bounded(1,100));
        else if (arg=="--warmup") o.warmup=static_cast<unsigned>(bounded(0,10));
        else if (arg=="--blocks") o.blocks=static_cast<unsigned>(bounded(1,32));
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
    if (o.mode=="blocks" && o.profiles=="representative") o.profiles="ours";
    return o;
}
std::vector<Profile> selected_profiles(const Options& o) {
    auto ids=o.profiles=="ours" ? std::vector<std::string>{"ours_mpk","ours_mid","ours_ct"} : o.profiles=="all" ? profile_ids : o.profiles=="representative" ?
        std::vector<std::string>{"ours_ct","jkn_low","abla_II"} : split(o.profiles);
    if (ids.empty() || ids.size()>8) throw std::invalid_argument("Empty or excessive profile selection");
    std::set<std::string> seen; std::vector<Profile> result;
    for (const auto& id:ids) {
        if (std::find(profile_ids.begin(),profile_ids.end(),id)==profile_ids.end() || !seen.insert(id).second)
            throw std::invalid_argument("Unknown or repeated profile: "+id);
        const auto file=o.data/(id+".cfg");
        const auto hash=expected_profile_sha256.find(id);
        if (hash==expected_profile_sha256.end() || file_sha256(file)!=hash->second)
            throw std::runtime_error("Profile hash differs from the previously verified parameter set: "+id);
        auto p=read_profile(file);
        if (o.mode=="blocks" && (!p.polar || p.scheme!="Ours")) throw std::invalid_argument("Blocks mode measures only Ours profiles");
        if (p.id!=id) throw std::runtime_error("Profile ID mismatch"); result.push_back(std::move(p));
    }
    return result;
}
std::size_t tile_columns(const Profile& p,const Options& o) {
    return std::max<std::size_t>(1,std::min<std::size_t>(256,(std::uint64_t(o.tile_mib)<<20)/(p.n*sizeof(Word))));
}
std::uint64_t planned_memory(const Profile& p,const Options& o) {
    // One private key, one packed ciphertext, one matrix tile, small vectors,
    // and 256 MB reserved for libraries, allocator, Arb and runtime overhead.
    return p.d()*sizeof(Word)+p.ct_bytes()+tile_columns(p,o)*p.n*sizeof(Word)+
        4ULL*p.n*sizeof(Word)+256000000ULL;
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
    const Profile& p_; const Modulus& mod_; Seed seed_; std::size_t capacity_;
public:
    std::vector<Word> tile;
    MatrixStream(const Profile& p,const Modulus& mod,const Seed& seed,std::size_t cols):
        p_(p),mod_(mod),seed_(seed),capacity_(cols),tile(cols*p.n) {}
    std::size_t fill(std::uint64_t offset,std::uint64_t remaining=std::numeric_limits<std::uint64_t>::max()) {
        if (offset>=p_.d()) throw std::invalid_argument("Matrix stream offset outside profile");
        const auto count=static_cast<std::size_t>(std::min<std::uint64_t>(capacity_,std::min(p_.d()-offset,remaining)));
        for (std::size_t c=0;c<count;++c) {
            Rng rng(seed_,"fixed-identity-matrix/"+p_.id+"/"+std::to_string(offset+c));
            for (unsigned row=0;row<p_.n;++row) tile[c*p_.n+row]=mod_.uniform(rng);
        }
        return count;
    }
};
struct Fixture {std::vector<Word> e,u;Seed matrix_seed;};
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
    f.matrix_seed=entropy_seed(); f.e.resize(static_cast<std::size_t>(p.d())); f.u.resize(p.n);
    Rng key_rng(entropy_seed(),"offline-algebraic-key/"+p.id); double progress=start.seconds;
    for (std::uint64_t i=0;i<p.d();++i) {
        f.e[i]=mod.encode(discrete_gaussian(p.sigma,key_rng,stats));
        if (!(i%4096)) {platform_check(planned_memory(p,o));heartbeat("offline key",i,p.d(),progress);}
    }
    MatrixStream matrix(p,mod,f.matrix_seed,tile_columns(p,o));
    for (std::uint64_t offset=0;offset<p.d();) {
        const auto count=matrix.fill(offset);
        for (std::size_t c=0;c<count;++c)
            for (unsigned row=0;row<p.n;++row) mod.addmul(f.u[row],matrix.tile[c*p.n+row],f.e[offset+c]);
        offset+=count; platform_check(planned_memory(p,o)); heartbeat("offline u=M e",offset,p.d(),progress);
    }
    duration.add(start,clock_stamp()); return f;
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
        Rng rng(entropy_seed(),"fresh-secret-scalar/"+p.id);
        if (p.scheme=="JKN21") message=rng.bit(); // Original single-bit KEM payload.
        for (auto& z:s) z=mod.uniform(rng);
        scalar=mod.add(mod.dot(f.u.data(),s.data(),p.n),mod.encode(discrete_gaussian(p.r,rng,metrics.sampling)));
        if (message) scalar=mod.add(scalar,mod.encode(p.q/2));
        if (p.polar) public_seed=entropy_seed();
    });
    Rng private_rng(entropy_seed(),"fresh-vector-randomness/"+p.id);
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
        Reader reader(ciphertext,p.ct_bits()); const Word scalar=reader.word(p.a);
        if (to_big(scalar)>=p.q) throw std::runtime_error("Noncanonical scalar");
        const Seed seed=p.polar ? reader.seed() : Seed{}; Word inner;
        for (std::uint64_t offset=0;offset<p.d();offset+=p.layout.N) {
            std::vector<Word> b;
            if (p.polar) b=unpack_polar(reader,p,mod,seed,offset/p.layout.N);
            else {
                b.resize(p.layout.N);
                for (auto& z:b) {z=reader.word(p.a);if (to_big(z)>=p.q) throw std::runtime_error("Noncanonical vector coordinate");}
            }
            inner=mod.add(inner,mod.dot(b.data(),f.e.data()+offset,p.layout.N));
        }
        reader.finish(); const Big v=to_big(mod.sub(scalar,inner)), half=p.q/2;
        Big distance0=std::min(v,Big(p.q-v)); Big distance1=abs(v-half);
        distance1=std::min(distance1,Big(p.q-distance1)); message=distance1<distance0 ? 1U : 0U;
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
// Real n/q/noise/layout, but only a prefix of complete polar blocks. This is
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
    Metrics metrics; Duration validation,other;
    Seed private_seed{},public_seed{};
    std::size_t fragment_bytes=0;
};
BlockResult encrypt_blocks(const Profile& p,const Modulus& mod,const Options& o,const Fixture& f) {
    BlockResult result; auto& m=result.metrics;
    const auto dimension=std::uint64_t(o.blocks)*p.layout.N;
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
    Rng private_rng(result.private_seed,"block-vector-randomness/"+p.id);
    timed(m.serialization,[&]{writer.word(scalar,p.a);writer.seed(result.public_seed);});
    std::vector<Word> pending;pending.reserve(p.layout.N);std::array<Word,256> projected{};
    std::uint64_t block=0;double progress=start.seconds;
    for(std::uint64_t offset=0;offset<dimension;){
        std::size_t count=0;
        timed(m.feed,[&]{count=matrix.fill(offset,dimension-offset);});
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
                    b=polar_sample_block(source,p.layout,result.public_seed,block,private_rng,m.sampling);
                });
                timed(m.serialization,[&]{pack_polar(writer,b,p,result.public_seed,block);});
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
    result.fragment_bytes=writer.bytes.size();
    timed(result.validation,[&]{
        Reader reader(writer.bytes,p.bits_for(dimension));
        if(to_big(reader.word(p.a))!=to_big(scalar)||reader.seed()!=result.public_seed)
            throw std::runtime_error("Fragment scalar/seed roundtrip failed");
        for(std::uint64_t b=0;b<o.blocks;++b){
            const auto recovered=unpack_polar(reader,p,mod,result.public_seed,b);
            for(unsigned j=0;j<p.layout.N;++j)
                if(to_big(recovered[j])!=to_big(expected[b*p.layout.N+j]))
                    throw std::runtime_error("Fragment codec roundtrip failed");
        }
        reader.finish();
    });
    return result;
}
void block_header(std::ostream& f) {
    f<<"trial,order,mode,profile,n,m,a,full_dimension,blocks,block_length,processed_dimension,fragment_bytes,matrix_cycles,quant_cycles,other_cycles,total_cycles,matrix_seconds,quant_seconds,other_seconds,total_seconds,feed_seconds,validation_seconds,matrix_pct,quant_pct,other_pct,peak_memory_bytes,codec_ok,full_parameter_dimensions,complete_ciphertext,status\n";
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
        <<','<<peak_memory_bytes()<<",1,1,0,PASS\n";out.flush();
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
        <<",\n  \"memory_private_commit_limit_bytes\": "<<o.limit<<",\n  \"tile_mib\": "<<o.tile_mib<<",\n  \"logical_cpu\": "<<o.core
        <<",\n  \"fixture_kind\": \"uniform_fixed_identity_encryption_fixture\""
        <<",\n  \"order_seed\": "<<json(hex_seed(order_seed))
        <<",\n  \"profile_order_policy\": \"randomized once; repetitions grouped per profile\""
        <<",\n  \"block_selection\": \"first B consecutive 256-coordinate blocks of the fixed-identity matrix\""
        <<",\n  \"full_parameter_dimensions\": true,\n  \"complete_ciphertext\": false,\n  \"full_ibe_implementation\": false,\n  \"constant_time\": false"
        <<",\n  \"scope\": \"Real n/q/r/S/frozen layout; prefix encryption only. Feed, validation and progress excluded. No private-key setup or decryption.\""
        <<",\n  \"other_operations\": \"fresh randomness, scalar, serialization, allocation and online bookkeeping; total minus matrix minus quantization\""
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
            const auto b=encrypt_blocks(p,mod,o,f);
            if(!public_seeds.insert(hex_seed(b.public_seed)).second||!private_seeds.insert(hex_seed(b.private_seed)).second)
                throw std::runtime_error("Repeated block encryption seed");
            block_row(trial<0?warm:raw,trial,order,o,p,b);
            details<<p.id<<" trial="<<trial<<" test_private_seed="<<hex_seed(b.private_seed)<<" public_seed="<<hex_seed(b.public_seed)
                <<" decisions="<<b.metrics.sampling.decisions<<" precision_retries="<<b.metrics.sampling.retries
                <<" max_precision="<<b.metrics.sampling.max_precision<<'\n';details.flush();
            std::cout<<"  PASS trial="<<trial<<" matrix="<<100*b.metrics.matvec.seconds/b.metrics.enc.seconds
                <<"%, quant="<<100*b.metrics.quant.seconds/b.metrics.enc.seconds<<"%, other="<<100*b.other.seconds/b.metrics.enc.seconds
                <<"%; measured fragment="<<b.metrics.enc.seconds<<" s; feed="<<b.metrics.feed.seconds<<" s\n";
        }
    }
    std::ofstream done(o.output/"COMPLETED.txt");done<<"All requested real-parameter BLOCK measurements completed; not complete ciphertext timing.\n";
    done.flush();if(!done)throw std::runtime_error("Cannot write block completion marker");
    std::cout<<"BLOCKS COMPLETED: "<<o.output.string()<<'\n';
}
void usage() {
    std::cout<<"LWQ-IBE / JKN21 / Abla24 local fixed-identity research benchmark\n"
        <<"  --selftest\n  --plan --profiles all\n"
        <<"  --mode blocks --profiles ours --blocks 4 --repetitions 5 --warmup 1 --output results/new_blocks\n"
        <<"  --mode smoke --profiles representative --output results/new_smoke\n"
        <<"  --mode full --profiles all --repetitions 10 --warmup 1 --allow-long-run --output results/new_full\n"
        <<"Options: --data DIR --memory-limit-mb 1400 (decimal, maximum1500) --tile-mib 32 --core -1\n"
        <<"No full MPK allocation. Not Setup/Extract/PubEval timing or a deployable IBE implementation.\n";
}
} // namespace

int main(int argc,char** argv) {
    fs::path active_output;
    try {
        const auto o=parse_options(argc,argv);
        if(argc==1||o.mode=="help"){usage();return 0;}
        install_memory_limit(o.limit);set_single_thread_affinity(o.core);flint_set_num_threads(1);
        if(o.selftest){
            if(!arithmetic_selftest()||!sampler_selftest()||!codec_selftest())throw std::runtime_error("Self-test returned false");
            std::cout<<"SELFTEST PASS (arithmetic, RNG, posterior/SC, Gaussian, codec, matrix streaming)\n";return 0;
        }
        auto profiles=selected_profiles(o);
        if(o.plan){for(const auto& p:profiles){if(o.mode=="blocks")block_preflight(p,o);else preflight(p,o);}std::cout<<"PLAN ONLY: no matrix/key/ciphertext allocation, no timing result.\n";return 0;}
        if(o.mode=="blocks"){run_block_benchmark(o,std::move(profiles),active_output);return 0;}
        if(o.mode!="smoke"&&o.mode!="full")throw std::invalid_argument("Choose --mode smoke or full");
        if(o.mode=="full"&&!o.allow_long)throw std::invalid_argument("Full mode requires explicit --allow-long-run");
#ifndef _WIN32
        if(o.mode=="full")throw std::runtime_error("Full timing is restricted to native Windows; this build is correctness-only");
#endif
        if(o.output.empty()||fs::exists(o.output))throw std::invalid_argument("Output must name a new, nonexistent directory");
        if(o.mode=="smoke")for(auto& p:profiles){p.n=16;p.m=256;}
        for(const auto& p:profiles)preflight(p,o);
        const Seed order_seed=entropy_seed();Rng order_rng(order_seed,"profile-order");
        for(std::size_t i=profiles.size();i>1;--i)std::swap(profiles[i-1],profiles[order_rng.below(Big(static_cast<unsigned long>(i))).get_ui()]);
        fs::create_directories(o.output);active_output=o.output;write_metadata(o,profiles,order_seed);
        std::ofstream raw(o.output/"raw.csv"),warm(o.output/"warmup.csv"),details(o.output/"diagnostics.txt");
        if(!raw||!warm||!details)throw std::runtime_error("Cannot open output files");csv_header(raw);csv_header(warm);
        for(std::size_t order=0;order<profiles.size();++order){
            const auto& p=profiles[order];std::cout<<"PROFILE "<<p.id<<" ("<<o.mode<<")\n";
            const Modulus mod(p.q.get_str(),p.a);Duration preparation;SampleStats preparation_stats;
            const auto fixture=prepare_fixture(p,mod,o,preparation,preparation_stats);
            details<<p.id<<" matrix_seed="<<hex_seed(fixture.matrix_seed)<<" prepare_seconds="<<preparation.seconds
                <<" prepare_gaussian_proposals="<<preparation_stats.gaussian_proposals<<'\n';details.flush();
            std::set<std::string> public_seeds;
            for(int trial=-static_cast<int>(o.warmup);trial<static_cast<int>(o.repetitions);++trial){
                Metrics metrics;metrics.prepare=preparation;Seed seed{};Rng message_rng(entropy_seed(),"benchmark-message");unsigned message=message_rng.bit();
                auto ciphertext=encrypt(p,mod,o,fixture,message,seed,metrics);
                if(p.polar&&!public_seeds.insert(hex_seed(seed)).second)throw std::runtime_error("Repeated public seed");
                metrics.decoded=decrypt(p,mod,fixture,ciphertext,metrics)==message;
                if(!metrics.decoded)throw std::runtime_error("Decryption failure: "+p.id);
                if(ciphertext.size()!=p.ct_bytes())throw std::runtime_error("Incorrect serialized size");
                platform_check(planned_memory(p,o));csv_row(trial<0?warm:raw,trial,order,o,p,metrics,ciphertext.size());
                details<<p.id<<" trial="<<trial<<" decisions="<<metrics.sampling.decisions<<" gaussian_proposals="<<metrics.sampling.gaussian_proposals
                    <<" precision_retries="<<metrics.sampling.retries<<" max_precision="<<metrics.sampling.max_precision<<'\n';details.flush();
                std::cout<<"  PASS trial="<<trial<<" ciphertext="<<ciphertext.size()<<" B; Enc="<<metrics.enc.seconds<<" s; Dec="<<metrics.dec.seconds
                    <<" s; feed="<<metrics.feed.seconds<<" s; process peak="<<peak_memory_bytes()/1000000.0<<" MB\n";
            }
        }
        std::ofstream complete(o.output/"COMPLETED.txt");complete<<"All requested profiles/repetitions completed. Mode="<<o.mode<<". Read metadata.json for scope.\n";
        complete.flush();if(!complete)throw std::runtime_error("Cannot write completion marker");
        std::cout<<"COMPLETED: "<<o.output.string()<<'\n';return 0;
    }catch(const std::exception& error){
        std::cerr<<"FAILED: "<<error.what()<<'\n';
        if(!active_output.empty()){std::ofstream f(active_output/"failure.txt");f<<error.what()<<"\nPartial rows are not a completed comparison.\n";}
        return 1;
    }
}
