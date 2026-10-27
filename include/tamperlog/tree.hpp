#pragma once
#include <cstdint>
#include <vector>

#include "tamperlog/hash.hpp"

namespace tamperlog {

using Proof = std::vector<Hash>;

// Дерево истории (Crosby & Wallach 2009) в раскладке RFC 6962: растёт только вправо,
// хранит хеши всех полных поддеревьев. levels_[h][i] — корень поддерева из 2^h листьев,
// начиная с листа i * 2^h. Всего около 2n хешей.
class HistoryTree {
public:
    explicit HistoryTree(Hasher hasher = Hasher{}) : hasher_(hasher) {}

    std::uint64_t append(std::span<const std::uint8_t> data);  // возвращает индекс записи
    std::uint64_t append_leaf_hash(const Hash& leaf_hash);

    std::uint64_t size() const { return levels_.empty() ? 0 : levels_[0].size(); }
    Hash root() const { return root_at(size()); }
    Hash root_at(std::uint64_t tree_size) const;  // корень любой прошлой версии
    const Hash& leaf_hash(std::uint64_t index) const { return levels_.at(0).at(index); }

    // RFC 6962, 2.1.1: путь от листа index к корню версии tree_size.
    Proof inclusion_proof(std::uint64_t index, std::uint64_t tree_size) const;
    // RFC 6962, 2.1.2: доказательство, что версия old_size — префикс версии new_size.
    Proof consistency_proof(std::uint64_t old_size, std::uint64_t new_size) const;

    std::uint64_t stored_hashes() const;
    const Hasher& hasher() const { return hasher_; }

private:
    Hash range_hash(std::uint64_t a, std::uint64_t b) const;  // MTH(D[a:b])
    void path(std::uint64_t idx, std::uint64_t a, std::uint64_t b, Proof& out) const;
    void subproof(std::uint64_t m, std::uint64_t a, std::uint64_t b, bool whole, Proof& out) const;

    Hasher hasher_;
    std::vector<std::vector<Hash>> levels_;
};

// Длины доказательств без построения дерева: та же рекурсия, только счёт.
// Нужны, чтобы честно посчитать размеры для n, которые не влезают в память.
std::uint64_t inclusion_proof_len(std::uint64_t index, std::uint64_t tree_size);
std::uint64_t consistency_proof_len(std::uint64_t old_size, std::uint64_t new_size);

// Наибольшая степень двойки, строго меньшая n (n >= 2).
std::uint64_t split_point(std::uint64_t n);

}  // namespace tamperlog
