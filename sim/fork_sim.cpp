// E5–E6: сколько стоит поймать раздвоение (split view).
//
// Оператор ведёт две истории: A показывает всем, B — жертве. Общий префикс 200 записей,
// дальше они расходятся; каждый раунд обе растут на 8 записей, B всегда на 3 длиннее.
// Свидетели держат подписанную голову A. Раз в раунд жертва (если онлайн) выбирает k
// разных свидетелей из M и сверяет головы. Сверка бесполезна, если свидетель в сговоре
// (держит голову B) или если оператор перехватил ответ и подставил голову B.
// Полезная сверка запускает настоящую проверку: равные размеры — сравнить корни,
// разные — потребовать у оператора доказательство согласованности; оператор пробует
// доказательства из обеих историй. Если обе не проходят, раздвоение поймано.
//
// Режимы перехвата:
//   independent  каждая сверка перехватывается независимо с вероятностью e
//   persistent   оператор навсегда контролирует связь с round(e*M) честными свидетелями,
//                жертва каждый раунд выбирает свидетелей заново
//   fixed_list   то же, но жертва раз и навсегда выбрала k свидетелей
//
// Запуск: ./build/fork_sim [trials] [seed] > results/fork_sim.csv
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <iostream>
#include <numeric>
#include <random>
#include <string>
#include <vector>

#include "tamperlog/tree.hpp"
#include "tamperlog/verify.hpp"

using namespace tamperlog;

constexpr int R = 10;  // раундов
constexpr std::uint64_t PREFIX = 200, BASE = 256, GROW = 8, B_EXTRA = 3;

struct Histories {
    HistoryTree a, b;
    std::vector<bool> caught;  // caught[r]: полезная сверка в раунде r ловит раздвоение
};

static Histories build() {
    Histories h;
    std::uint64_t maxn = BASE + GROW * R + B_EXTRA + 1;
    for (std::uint64_t i = 0; i < maxn; ++i) {
        std::string ea = "tx-" + std::to_string(i);
        std::string eb = i < PREFIX ? ea : "fork-" + std::to_string(i);
        h.a.append(as_bytes(ea));
        h.b.append(as_bytes(eb));
    }
    const Hasher& hs = h.a.hasher();
    for (int r = 0; r < R; ++r) {
        std::uint64_t na = BASE + GROW * r, nb = na + B_EXTRA;
        Hash ra = h.a.root_at(na), rb = h.b.root_at(nb);
        // жертва видит (nb, rb), свидетель — (na, ra); na < nb, нужна согласованность na -> nb
        bool pass = verify_consistency(hs, na, nb, ra, rb, h.b.consistency_proof(na, nb)) ||
                    verify_consistency(hs, na, nb, ra, rb, h.a.consistency_proof(na, nb));
        // и вариант «одинаковый размер»: две подписанные головы na с разными корнями
        bool same_size_differs = h.a.root_at(na) != h.b.root_at(na);
        h.caught.push_back(!pass && same_size_differs);
    }
    return h;
}

static double binom(int n, int k) {
    if (k < 0 || k > n) return 0;
    return std::exp(std::lgamma(n + 1.0) - std::lgamma(k + 1.0) - std::lgamma(n - k + 1.0));
}

struct Cfg {
    std::string scenario;
    std::string mode = "independent";
    int M = 1000, f = 0, k = 3;
    double e = 0.5, off = 0.0;
};

// Точная вероятность для модели (не для симуляции): P(поймано к раунду r).
static double theory(const Cfg& c, int r) {
    if (c.mode == "independent") {
        double fail = 0;
        for (int j = 0; j <= c.k; ++j)
            fail += binom(c.f, j) * binom(c.M - c.f, c.k - j) / binom(c.M, c.k) * std::pow(c.e, c.k - j);
        double q = c.off + (1 - c.off) * fail;
        return 1 - std::pow(q, r);
    }
    int useless = std::min(c.M, c.f + int(std::lround(c.e * (c.M - c.f))));
    double all_bad = binom(useless, c.k) / binom(c.M, c.k);
    if (c.mode == "persistent") return 1 - std::pow(c.off + (1 - c.off) * all_bad, r);
    return (1 - all_bad) * (1 - std::pow(c.off, r));  // fixed_list
}

static double naive(const Cfg& c, int r) { return 1 - std::pow(c.e, c.k * r); }

static void run(const Cfg& c, const Histories& h, int trials, std::mt19937_64& rng) {
    std::vector<int> detected_by(R + 1, 0);
    std::vector<int> ids(c.M);
    std::iota(ids.begin(), ids.end(), 0);
    std::uniform_real_distribution<double> U(0, 1);
    for (int t = 0; t < trials; ++t) {
        // роли свидетелей на эту попытку: первые f после перемешивания — в сговоре,
        // следующие round(e*(M-f)) — с перехваченной связью (для persistent/fixed_list)
        std::shuffle(ids.begin(), ids.end(), rng);
        std::vector<char> colluding(c.M, 0), intercepted(c.M, 0);
        for (int i = 0; i < c.f; ++i) colluding[ids[i]] = 1;
        int ni = int(std::lround(c.e * (c.M - c.f)));
        for (int i = c.f; i < c.f + ni && i < c.M; ++i) intercepted[ids[i]] = 1;

        std::vector<int> fixed;
        if (c.mode == "fixed_list") {
            std::vector<int> all(c.M);
            std::iota(all.begin(), all.end(), 0);
            std::sample(all.begin(), all.end(), std::back_inserter(fixed), c.k, rng);
        }
        int caught_at = 0;
        for (int r = 0; r < R && !caught_at; ++r) {
            if (U(rng) < c.off) continue;
            std::vector<int> pick;
            if (c.mode == "fixed_list") {
                pick = fixed;
            } else {
                std::vector<int> all(c.M);
                std::iota(all.begin(), all.end(), 0);
                std::sample(all.begin(), all.end(), std::back_inserter(pick), c.k, rng);
            }
            for (int w : pick) {
                if (colluding[w]) continue;
                bool lost = c.mode == "independent" ? U(rng) < c.e : intercepted[w];
                if (lost) continue;
                if (h.caught[r]) {
                    caught_at = r + 1;
                    break;
                }
            }
        }
        if (caught_at) ++detected_by[caught_at];
    }
    int cum = 0;
    for (int r = 1; r <= R; ++r) {
        cum += detected_by[r];
        double p = double(cum) / trials;
        double se = std::sqrt(std::max(p * (1 - p), 1e-12) / trials);
        std::printf("%s,%s,%d,%d,%d,%.2f,%.2f,%d,%.5f,%.5f,%.5f,%.5f\n", c.scenario.c_str(), c.mode.c_str(), c.M,
                    c.f, c.k, c.e, c.off, r, p, se, theory(c, r), naive(c, r));
    }
}

int main(int argc, char** argv) {
    int trials = argc > 1 ? std::stoi(argv[1]) : 20000;
    Histories h = build();
    int holes = 0;
    for (bool b : h.caught) holes += !b;
    std::fprintf(stderr, "real proof checks per round: %d/%d catch the fork\n", R - holes, R);

    std::mt19937_64 rng(argc > 2 ? std::stoull(argv[2]) : 20261027);
    std::printf("scenario,mode,M,f,k,e,off,r,p_sim,se,p_theory,p_naive\n");

    // E5: базовая модель H3 на сетке k x e. M = 1000, сговора и офлайна нет.
    for (int k = 1; k <= 10; ++k)
        for (int ei = 0; ei <= 9; ++ei) {
            Cfg c;
            c.scenario = "E5_grid";
            c.k = k;
            c.e = ei / 10.0;
            run(c, h, trials, rng);
        }

    // E6: где простая формула ломается. M = 20, k = 3, e = 0.5.
    auto base = [] {
        Cfg c;
        c.M = 20;
        c.k = 3;
        c.e = 0.5;
        return c;
    };
    for (int f : {0, 2, 5, 10}) {
        Cfg c = base();
        c.scenario = "E6_collusion";
        c.f = f;
        run(c, h, trials, rng);
    }
    for (double off : {0.0, 0.2, 0.5}) {
        Cfg c = base();
        c.scenario = "E6_offline";
        c.off = off;
        run(c, h, trials, rng);
    }
    for (const char* mode : {"independent", "persistent", "fixed_list"}) {
        for (double e : {0.5, 0.8}) {
            Cfg c = base();
            c.scenario = "E6_interception";
            c.mode = mode;
            c.e = e;
            run(c, h, trials, rng);
        }
    }
    return 0;
}
