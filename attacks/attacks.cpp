// E4: набор атак злого оператора. Клиент помнит подписанную голову (m, root_m) честного
// журнала и индекс своей записи. Оператор подменяет историю и показывает новую голову
// (n', root'). Клиент требует доказательство согласованности m -> n' и доказательство
// включения своей записи. Оператор пробует две очевидные стратегии: доказательства,
// честно посчитанные по подделанному журналу, и доказательства из настоящего журнала.
// Атака поймана, если ни одна стратегия не прошла проверку клиента.
//
// Запуск: ./build/attacks [trials] > results/attacks.csv
#include <iostream>
#include <random>
#include <string>
#include <vector>

#include "tamperlog/tree.hpp"
#include "tamperlog/verify.hpp"

using namespace tamperlog;

static HistoryTree make(const std::vector<std::string>& entries, Hasher h = Hasher{}) {
    HistoryTree t{h};
    for (auto& e : entries) t.append(as_bytes(e));
    return t;
}

struct Outcome {
    bool consistency_passed;  // хоть одна стратегия прошла проверку согласованности
    bool inclusion_passed;    // хоть одна стратегия доказала включение записи клиента
};

static Outcome attack_once(const HistoryTree& honest, std::uint64_t m, std::uint64_t own,
                           const std::vector<std::string>& forged_entries) {
    const Hasher& h = honest.hasher();
    Hash root_m = honest.root_at(m);
    Hash own_leaf = honest.leaf_hash(own);
    HistoryTree forged = make(forged_entries);
    std::uint64_t n2 = forged.size();
    Hash root2 = forged.root();

    Outcome o{false, false};
    if (m <= n2) {
        if (verify_consistency(h, m, n2, root_m, root2, forged.consistency_proof(m, n2))) o.consistency_passed = true;
        if (n2 <= honest.size() &&
            verify_consistency(h, m, n2, root_m, root2, honest.consistency_proof(m, n2)))
            o.consistency_passed = true;
    } else {
        // откат: новая голова меньше старой; проверка обязана отказать при любом доказательстве
        if (verify_consistency(h, m, n2, root_m, root2, {})) o.consistency_passed = true;
        if (verify_consistency(h, m, n2, root_m, root2, honest.consistency_proof(n2 == 0 ? 1 : n2, m)))
            o.consistency_passed = true;
    }
    // запись клиента: ищем её в подделанном журнале на любом месте
    for (std::uint64_t i = 0; i < n2; ++i) {
        if (forged.leaf_hash(i) == own_leaf &&
            verify_inclusion(h, i, n2, own_leaf, forged.inclusion_proof(i, n2), root2))
            o.inclusion_passed = true;
    }
    return o;
}

int main(int argc, char** argv) {
    int trials = argc > 1 ? std::stoi(argv[1]) : 1000;
    std::mt19937_64 rng(20261027);
    auto uni = [&](std::uint64_t lo, std::uint64_t hi) {  // [lo, hi]
        return std::uniform_int_distribution<std::uint64_t>(lo, hi)(rng);
    };

    const char* kinds[] = {"none(control)", "rewrite", "delete", "reorder", "backdate_insert", "rollback",
                           "fork"};
    std::cout << "attack,trials,consistency_rejected,own_record_lost_or_moved,false_accept\n";
    for (const char* kind : kinds) {
        std::string k = kind;
        int cons_rejected = 0, own_lost = 0, false_accept = 0;
        for (int t = 0; t < trials; ++t) {
            std::uint64_t n = uni(4, 600);
            std::uint64_t m = uni(2, n - 1);  // клиент видел версию m
            std::uint64_t own = uni(0, m - 1);
            std::vector<std::string> entries;
            for (std::uint64_t i = 0; i < n; ++i) entries.push_back("tx-" + std::to_string(t) + "-" + std::to_string(i));
            HistoryTree honest = make(entries);
            std::vector<std::string> forged = entries;
            std::uint64_t j = uni(0, m - 1);  // подделка всегда в той части, которую клиент уже видел

            if (k == "rewrite") {
                forged[j] += "-rewritten";
            } else if (k == "delete") {
                forged.erase(forged.begin() + j);
            } else if (k == "reorder") {
                std::uint64_t j2 = uni(0, n - 1);
                if (j2 == j) j2 = (j + 1) % n;
                std::swap(forged[j], forged[j2]);
            } else if (k == "backdate_insert") {
                forged.insert(forged.begin() + j, "tx-backdated");
            } else if (k == "rollback") {
                forged.resize(uni(1, m - 1));
            } else if (k == "fork") {
                // общий префикс j записей, дальше другая история той же или большей длины
                forged.resize(j);
                for (std::uint64_t i = j; i < n + uni(0, 50); ++i) forged.push_back("fork-" + std::to_string(i));
            }

            Outcome o = attack_once(honest, m, own, forged);
            bool attack = k != "none(control)";
            if (!o.consistency_passed) ++cons_rejected;
            if (!o.inclusion_passed) ++own_lost;
            // ложный приём: атака прошла проверку согласованности (для контроля — отказ честному)
            if (attack ? o.consistency_passed : !o.consistency_passed) ++false_accept;
        }
        std::cout << kind << "," << trials << "," << cons_rejected << "," << own_lost << "," << false_accept << "\n";
    }

    // Атака на дерево без разделения доменов (лист = H(d), узел = H(l||r)).
    // Журнал из 4 записей и журнал из 2 «записей» x0 = H(d0)||H(d1), x1 = H(d2)||H(d3)
    // дают один и тот же корень. С префиксами 0x00/0x01 корни разные.
    for (bool domain : {false, true}) {
        Hasher h(HashAlg::Sha256, domain);
        HistoryTree four{h}, two{h};
        std::string d[4] = {"pay alice 10", "pay bob 20", "pay carol 30", "pay dave 40"};
        for (auto& s : d) four.append(as_bytes(s));
        auto raw = [&](const std::string& s) { return Hasher(HashAlg::Sha256, false).leaf(as_bytes(s)); };
        for (int p = 0; p < 2; ++p) {
            Bytes x;
            Hash a = raw(d[2 * p]), b = raw(d[2 * p + 1]);
            x.insert(x.end(), a.begin(), a.end());
            x.insert(x.end(), b.begin(), b.end());
            two.append(x);
        }
        std::cerr << (domain ? "with 0x00/0x01 prefixes: " : "without prefixes:        ")
                  << "root(4 entries)=" << to_hex(four.root()).substr(0, 16)
                  << "  root(2 forged)=" << to_hex(two.root()).substr(0, 16)
                  << (four.root() == two.root() ? "  SAME ROOT" : "  different") << "\n";
    }
    return 0;
}
