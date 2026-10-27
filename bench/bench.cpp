// E1–E3. Два режима:
//   ./build/bench sizes  > results/proof_sizes.csv   длины доказательств для n до 10^12 (счёт, без дерева)
//   ./build/bench timing > results/timing.csv        построенные деревья n = 10^3..10^7, время и память
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#include "tamperlog/sth.hpp"
#include "tamperlog/tree.hpp"
#include "tamperlog/verify.hpp"

using namespace tamperlog;
using clk = std::chrono::steady_clock;

static double pct(std::vector<double> v, double p) {
    std::sort(v.begin(), v.end());
    return v[std::size_t(p * (v.size() - 1))];
}

static void sizes() {
    std::mt19937_64 rng(1);
    std::cout << "n,log2n,incl_mean,incl_max,cons_mean,cons_max,tree_incl_bytes_mean,"
                 "chain_incl_bytes_mean,chain_cons_bytes_mean\n";
    for (int e = 3; e <= 12; ++e) {
        for (double mant : {1.0, 3.0}) {
            std::uint64_t n = std::uint64_t(mant * std::pow(10.0, e));
            const int S = 2000;
            double is = 0, cs = 0;
            std::uint64_t imax = 0, cmax = 0;
            for (int s = 0; s < S; ++s) {
                std::uint64_t i = std::uniform_int_distribution<std::uint64_t>(0, n - 1)(rng);
                std::uint64_t m = std::uniform_int_distribution<std::uint64_t>(1, n - 1)(rng);
                std::uint64_t li = inclusion_proof_len(i, n), lc = consistency_proof_len(m, n);
                is += li;
                cs += lc;
                imax = std::max(imax, li);
                cmax = std::max(cmax, lc);
            }
            // Цепочка хешей: чтобы связать запись i с головой, нужны все n-1-i следующих звеньев;
            // для согласованности m -> n — все n-m новых звеньев. В среднем n/2.
            std::printf("%llu,%.2f,%.2f,%llu,%.2f,%llu,%.0f,%.0f,%.0f\n", (unsigned long long)n, std::log2(double(n)),
                        is / S, (unsigned long long)imax, cs / S, (unsigned long long)cmax, 32 * is / S,
                        32.0 * (n - 1) / 2, 32.0 * n / 2);
        }
    }
}

static void timing() {
    std::cout << "alg,n,append_ns_per_entry,stored_hashes,stored_bytes,"
                 "incl_len_mean,incl_gen_us_p50,incl_gen_us_p90,incl_ver_us_p50,incl_ver_us_p90,"
                 "cons_len_mean,cons_gen_us_p50,cons_gen_us_p90,cons_ver_us_p50,cons_ver_us_p90\n";
    for (HashAlg alg : {HashAlg::Blake2b256, HashAlg::Sha256}) {
        for (std::uint64_t n : {1'000ull, 10'000ull, 100'000ull, 1'000'000ull, 10'000'000ull}) {
            std::mt19937_64 rng(n);
            HistoryTree t{Hasher(alg)};
            // запись ~ 100 байт, как строка банковской операции
            std::string rec(100, 'x');
            auto t0 = clk::now();
            for (std::uint64_t i = 0; i < n; ++i) {
                std::snprintf(rec.data(), 24, "tx%020llu", (unsigned long long)i);
                t.append(as_bytes(rec));
            }
            double append_ns = std::chrono::duration<double, std::nano>(clk::now() - t0).count() / double(n);

            const int S = 2000;
            std::vector<double> ig, iv, cg, cv;
            double il = 0, cl = 0;
            Hash root = t.root();
            for (int s = 0; s < S; ++s) {
                std::uint64_t i = std::uniform_int_distribution<std::uint64_t>(0, n - 1)(rng);
                auto a = clk::now();
                Proof p = t.inclusion_proof(i, n);
                auto b = clk::now();
                bool ok = verify_inclusion(t.hasher(), i, n, t.leaf_hash(i), p, root);
                auto c = clk::now();
                if (!ok || p.size() != inclusion_proof_len(i, n)) { std::cerr << "inclusion broke\n"; return; }
                ig.push_back(std::chrono::duration<double, std::micro>(b - a).count());
                iv.push_back(std::chrono::duration<double, std::micro>(c - b).count());
                il += p.size();

                std::uint64_t m = std::uniform_int_distribution<std::uint64_t>(1, n - 1)(rng);
                Hash rm = t.root_at(m);  // корень старой головы клиент уже знает, его время не считаем
                a = clk::now();
                Proof q = t.consistency_proof(m, n);
                b = clk::now();
                ok = verify_consistency(t.hasher(), m, n, rm, root, q);
                c = clk::now();
                if (!ok || q.size() != consistency_proof_len(m, n)) { std::cerr << "consistency broke\n"; return; }
                cg.push_back(std::chrono::duration<double, std::micro>(b - a).count());
                cv.push_back(std::chrono::duration<double, std::micro>(c - b).count());
                cl += q.size();
            }
            std::printf("%s,%llu,%.1f,%llu,%llu,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f\n",
                        alg == HashAlg::Sha256 ? "sha256" : "blake2b", (unsigned long long)n, append_ns,
                        (unsigned long long)t.stored_hashes(), (unsigned long long)(32 * t.stored_hashes()), il / S,
                        pct(ig, .5), pct(ig, .9), pct(iv, .5), pct(iv, .9), cl / S, pct(cg, .5), pct(cg, .9),
                        pct(cv, .5), pct(cv, .9));
            std::fflush(stdout);
        }
    }
}

// Проверка догадки про кэш: одно и то же дерево, генерация доказательства для случайного
// индекса (холодные строки кэша) и для одного индекса подряд (тёплые).
static void cache() {
    std::cout << "n,mode,incl_gen_us_p50,incl_gen_us_p90\n";
    for (std::uint64_t n : {1'000'000ull, 10'000'000ull}) {
        HistoryTree t;
        std::string rec(100, 'x');
        for (std::uint64_t i = 0; i < n; ++i) {
            std::snprintf(rec.data(), 24, "tx%020llu", (unsigned long long)i);
            t.append(as_bytes(rec));
        }
        std::mt19937_64 rng(7);
        for (int warm = 0; warm < 2; ++warm) {
            std::vector<double> g;
            std::uint64_t fixed = n / 3;
            for (int s = 0; s < 5000; ++s) {
                std::uint64_t i = warm ? fixed : std::uniform_int_distribution<std::uint64_t>(0, n - 1)(rng);
                auto a = clk::now();
                Proof p = t.inclusion_proof(i, n);
                auto b = clk::now();
                if (p.empty()) return;
                g.push_back(std::chrono::duration<double, std::micro>(b - a).count());
            }
            std::printf("%llu,%s,%.2f,%.2f\n", (unsigned long long)n, warm ? "same_index" : "random_index",
                        pct(g, .5), pct(g, .9));
        }
    }
}

// Цена подписанной головы: подпись оператором и проверка клиентом (Ed25519, Monocypher).
static void sig() {
    std::array<std::uint8_t, 32> seed{};
    seed[0] = 42;
    KeyPair kp = keypair_from_seed(seed);
    SignedTreeHead sth{1'000'000'000, 1761523200000, Hash{}, {}};
    std::vector<double> s, v;
    for (int i = 0; i < 3000; ++i) {
        sth.root[i % 32] ^= 1;
        auto a = clk::now();
        sign_sth(sth, kp);
        auto b = clk::now();
        bool ok = verify_sth(sth, kp.pub);
        auto c = clk::now();
        if (!ok) return;
        s.push_back(std::chrono::duration<double, std::micro>(b - a).count());
        v.push_back(std::chrono::duration<double, std::micro>(c - b).count());
    }
    std::printf("op,us_p50,us_p90\nsign,%.1f,%.1f\nverify,%.1f,%.1f\n", pct(s, .5), pct(s, .9), pct(v, .5), pct(v, .9));
}

int main(int argc, char** argv) {
    std::string mode = argc > 1 ? argv[1] : "sizes";
    if (mode == "sizes") sizes();
    else if (mode == "cache") cache();
    else if (mode == "sig") sig();
    else timing();
}
