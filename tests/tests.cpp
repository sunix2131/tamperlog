// Тесты без фреймворка: каждый CHECK печатает место падения, в конце — счётчики.
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include "nlohmann/json.hpp"
#include "tamperlog/sth.hpp"
#include "tamperlog/tree.hpp"
#include "tamperlog/verify.hpp"

using namespace tamperlog;
namespace fs = std::filesystem;

static int g_pass = 0, g_fail = 0;
#define CHECK(cond)                                                                   \
    do {                                                                              \
        if (cond) {                                                                   \
            ++g_pass;                                                                 \
        } else {                                                                      \
            ++g_fail;                                                                 \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ << "  " #cond "\n"; \
        }                                                                             \
    } while (0)

static Bytes unhex(const std::string& s) {
    Bytes b;
    for (std::size_t i = 0; i + 1 < s.size(); i += 2) b.push_back(std::stoi(s.substr(i, 2), nullptr, 16));
    return b;
}

static Bytes b64(const std::string& s) {
    static const std::string a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    Bytes out;
    unsigned buf = 0;
    int bits = 0;
    for (char c : s) {
        if (c == '=') break;
        auto p = a.find(c);
        if (p == std::string::npos) continue;
        buf = (buf << 6) | unsigned(p);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(std::uint8_t(buf >> bits));
        }
    }
    return out;
}

// В векторах встречаются «хеши» не по 32 байта, в том числе заглушки вроде "don't care 2",
// которые Go сравнивает побайтно. Такие байты отображаем в BLAKE2b("badlen" || b):
// равные входы дают равные хеши, а совпасть с настоящим хешем практически не могут.
static Hash to_hash(const Bytes& b, bool& ok) {
    ok = true;
    Hash h{};
    if (b.size() == 32) {
        std::copy(b.begin(), b.end(), h.begin());
        return h;
    }
    Bytes tagged = {'b', 'a', 'd', 'l', 'e', 'n'};
    tagged.insert(tagged.end(), b.begin(), b.end());
    return blake2b256(tagged);
}

static void test_sha256() {
    CHECK(to_hex(sha256(as_bytes(""))) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(to_hex(sha256(as_bytes("abc"))) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(to_hex(sha256(as_bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))) ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    std::string million(1'000'000, 'a');
    CHECK(to_hex(sha256(as_bytes(million))) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

// Корни из transparency-dev/merkle testonly/constants.go для деревьев 0..8 листьев.
static void test_upstream_roots() {
    const char* leaves[] = {"", "00", "10", "2021", "3031", "40414243", "5051525354555657",
                            "606162636465666768696a6b6c6d6e6f"};
    const char* roots[] = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"};
    HistoryTree t{Hasher(HashAlg::Sha256)};
    CHECK(to_hex(t.hasher().empty()) == roots[0]);
    for (int i = 0; i < 8; ++i) {
        auto d = unhex(leaves[i]);
        t.append(d);
        CHECK(to_hex(t.root()) == roots[i + 1]);
    }
    for (int i = 1; i <= 8; ++i) CHECK(to_hex(t.root_at(i)) == roots[i]);
}

struct VecStats {
    int files = 0, agree = 0;
};

static void test_upstream_vectors(VecStats& st) {
    Hasher h(HashAlg::Sha256);
    for (const auto& e : fs::recursive_directory_iterator(VECTORS_DIR)) {
        if (!e.is_regular_file() || e.path().extension() != ".json") continue;
        std::ifstream f(e.path());
        auto j = nlohmann::json::parse(f);
        bool want_err = j.value("wantErr", false);
        bool ok = true, got;
        Proof proof;
        if (j.contains("proof") && !j["proof"].is_null())
            for (auto& p : j["proof"]) {
                bool okp;
                proof.push_back(to_hash(b64(p.get<std::string>()), okp));
                ok = ok && okp;
            }
        std::string kind = e.path().string().find("/inclusion/") != std::string::npos ? "inclusion" : "consistency";
        if (kind == "inclusion") {
            // Хеш записи у клиента — 32 байта по типу Hash; Go проверяет это явно, мы — здесь.
            bool ok1;
            Hash root = to_hash(b64(j.value("root", "")), ok1);
            Bytes leaf_b = b64(j.value("leafHash", ""));
            bool ok2 = leaf_b.size() == 32;
            Hash leaf = to_hash(leaf_b, ok1);
            got = ok && ok1 && ok2 &&
                  verify_inclusion(h, j["leafIdx"].get<std::uint64_t>(), j["treeSize"].get<std::uint64_t>(), leaf,
                                   proof, root);
        } else {
            bool ok1, ok2;
            Hash r1 = to_hash(b64(j.value("root1", "")), ok1);
            Hash r2 = to_hash(b64(j.value("root2", "")), ok2);
            got = ok && ok1 && ok2 &&
                  verify_consistency(h, j["size1"].get<std::uint64_t>(), j["size2"].get<std::uint64_t>(), r1, r2,
                                     proof);
        }
        ++st.files;
        bool agree = (got == !want_err);
        if (agree) ++st.agree;
        else std::cerr << "vector disagrees: " << e.path().string() << " want_err=" << want_err << "\n";
        CHECK(agree);
    }
}

static HistoryTree build(HashAlg alg, std::uint64_t n) {
    HistoryTree t{Hasher(alg)};
    for (std::uint64_t i = 0; i < n; ++i) t.append(as_bytes("leaf-" + std::to_string(i)));
    return t;
}

static void test_exhaustive(HashAlg alg, std::uint64_t N) {
    HistoryTree t = build(alg, N);
    const Hasher& h = t.hasher();
    for (std::uint64_t n = 1; n <= N; ++n) {
        HistoryTree fresh = build(alg, n);
        CHECK(fresh.root() == t.root_at(n));
        Hash root = t.root_at(n);
        for (std::uint64_t i = 0; i < n; ++i) {
            Proof p = t.inclusion_proof(i, n);
            CHECK(p.size() == inclusion_proof_len(i, n));
            CHECK(verify_inclusion(h, i, n, t.leaf_hash(i), p, root));
            if (n > 1) CHECK(!verify_inclusion(h, (i + 1) % n, n, t.leaf_hash(i), p, root));
            for (std::size_t k = 0; k < p.size(); ++k) {
                Proof q = p;
                q[k][k % 32] ^= 0x01;
                CHECK(!verify_inclusion(h, i, n, t.leaf_hash(i), q, root));
            }
        }
        CHECK(!verify_consistency(h, 0, n, t.hasher().empty(), root, {}));
        for (std::uint64_t m = 1; m <= n; ++m) {
            Proof p = t.consistency_proof(m, n);
            CHECK(p.size() == consistency_proof_len(m, n));
            CHECK(verify_consistency(h, m, n, t.root_at(m), root, p));
            for (std::size_t k = 0; k < p.size(); ++k) {
                Proof q = p;
                q[k][(k * 7) % 32] ^= 0x80;
                CHECK(!verify_consistency(h, m, n, t.root_at(m), root, q));
            }
            if (m > 0 && m < n) CHECK(!verify_consistency(h, n, m, root, t.root_at(m), p));  // откат назад
        }
    }
}

static void test_sth() {
    // RFC 8032, раздел 7.1, TEST 1 (пустое сообщение)
    auto seed_b = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    std::array<std::uint8_t, 32> seed;
    std::copy(seed_b.begin(), seed_b.end(), seed.begin());
    KeyPair kp = keypair_from_seed(seed);
    Hash pub;
    std::copy(kp.pub.begin(), kp.pub.end(), pub.begin());
    CHECK(to_hex(pub) == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

    HistoryTree t = build(HashAlg::Blake2b256, 100);
    SignedTreeHead sth{100, 1761523200000, t.root(), {}};
    sign_sth(sth, kp);
    CHECK(verify_sth(sth, kp.pub));
    SignedTreeHead bad = sth;
    bad.tree_size = 99;
    CHECK(!verify_sth(bad, kp.pub));
    bad = sth;
    bad.root[0] ^= 1;
    CHECK(!verify_sth(bad, kp.pub));
}

int main() {
    test_sha256();
    test_upstream_roots();
    VecStats vs;
    test_upstream_vectors(vs);
    test_exhaustive(HashAlg::Sha256, 70);
    test_exhaustive(HashAlg::Blake2b256, 70);
    test_sth();
    std::cout << "upstream vectors: " << vs.agree << "/" << vs.files << " agree\n";
    std::cout << "checks passed: " << g_pass << ", failed: " << g_fail << "\n";
    return g_fail ? 1 : 0;
}
