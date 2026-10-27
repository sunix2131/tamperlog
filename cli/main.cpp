// tamperlog — утилита для журнала, где каждая строка файла = одна запись.
//   tamperlog root   <file> [size]          корень версии size (по умолчанию — вся)
//   tamperlog incl   <file> <index> [size]  доказательство включения, хеши по строке
//   tamperlog cons   <file> <old> [new]     доказательство согласованности
//   tamperlog dump   <n>                    всё про дерево из записей "leaf-i" (для crosscheck)
//   tamperlog hash   <hex>                  SHA-256 от байт (для crosscheck)
// Флаг --sha256 перед командой переключает хеш с BLAKE2b-256 на SHA-256.
#include <fstream>
#include <iostream>
#include <string>

#include "tamperlog/tree.hpp"

using namespace tamperlog;

static HistoryTree load(const std::string& path, HashAlg alg) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open " + path);
    HistoryTree t{Hasher(alg)};
    std::string line;
    while (std::getline(f, line)) t.append(as_bytes(line));
    return t;
}

static void print(const Proof& p) {
    for (const auto& h : p) std::cout << to_hex(h) << "\n";
}

int main(int argc, char** argv) {
    try {
        int a = 1;
        HashAlg alg = HashAlg::Blake2b256;
        if (a < argc && std::string(argv[a]) == "--sha256") {
            alg = HashAlg::Sha256;
            ++a;
        }
        if (a >= argc) {
            std::cerr << "usage: tamperlog [--sha256] root|incl|cons|dump|hash ...\n";
            return 2;
        }
        std::string cmd = argv[a++];
        auto arg = [&](int i) { return std::stoull(argv[a + i]); };

        if (cmd == "hash") {
            std::string hex = a < argc ? argv[a] : "";
            Bytes b;
            for (std::size_t i = 0; i + 1 < hex.size(); i += 2) b.push_back(std::stoi(hex.substr(i, 2), nullptr, 16));
            std::cout << to_hex(sha256(b)) << "\n";
            return 0;
        }
        if (cmd == "dump") {
            std::uint64_t n = arg(0);
            HistoryTree t{Hasher(alg)};
            for (std::uint64_t i = 0; i < n; ++i) t.append(as_bytes("leaf-" + std::to_string(i)));
            for (std::uint64_t s = 1; s <= n; ++s) {
                std::cout << "R " << s << " " << to_hex(t.root_at(s)) << "\n";
                for (std::uint64_t i = 0; i < s; ++i) {
                    std::cout << "I " << i << " " << s;
                    for (auto& h : t.inclusion_proof(i, s)) std::cout << " " << to_hex(h);
                    std::cout << "\n";
                }
                for (std::uint64_t m = 1; m < s; ++m) {
                    std::cout << "C " << m << " " << s;
                    for (auto& h : t.consistency_proof(m, s)) std::cout << " " << to_hex(h);
                    std::cout << "\n";
                }
            }
            return 0;
        }

        HistoryTree t = load(argv[a++], alg);
        if (cmd == "root") {
            std::uint64_t s = a < argc ? arg(0) : t.size();
            std::cout << s << " " << to_hex(t.root_at(s)) << "\n";
        } else if (cmd == "incl") {
            std::uint64_t i = arg(0), s = a + 1 < argc ? arg(1) : t.size();
            std::cout << "leaf " << to_hex(t.leaf_hash(i)) << "\nroot " << to_hex(t.root_at(s)) << "\n";
            print(t.inclusion_proof(i, s));
        } else if (cmd == "cons") {
            std::uint64_t m = arg(0), s = a + 1 < argc ? arg(1) : t.size();
            std::cout << "old " << to_hex(t.root_at(m)) << "\nnew " << to_hex(t.root_at(s)) << "\n";
            print(t.consistency_proof(m, s));
        } else {
            std::cerr << "unknown command " << cmd << "\n";
            return 2;
        }
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
