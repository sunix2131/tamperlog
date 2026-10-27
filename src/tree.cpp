#include "tamperlog/tree.hpp"

#include <bit>
#include <stdexcept>

namespace tamperlog {

std::uint64_t split_point(std::uint64_t n) {
    return std::bit_floor(n - 1);
}

std::uint64_t HistoryTree::append(std::span<const std::uint8_t> data) {
    return append_leaf_hash(hasher_.leaf(data));
}

std::uint64_t HistoryTree::append_leaf_hash(const Hash& leaf_hash) {
    if (levels_.empty()) levels_.emplace_back();
    levels_[0].push_back(leaf_hash);
    // Поднимаем новые полные поддеревья. В среднем один узел на запись.
    for (std::size_t h = 0; levels_[h].size() % 2 == 0; ++h) {
        if (levels_.size() == h + 1) levels_.emplace_back();
        const auto& lv = levels_[h];
        levels_[h + 1].push_back(hasher_.node(lv[lv.size() - 2], lv[lv.size() - 1]));
    }
    return levels_[0].size() - 1;
}

Hash HistoryTree::range_hash(std::uint64_t a, std::uint64_t b) const {
    std::uint64_t n = b - a;
    if (n == 0) return hasher_.empty();
    if (std::has_single_bit(n)) {
        // В рекурсии RFC 6962 поддерево размера 2^h всегда начинается с кратного 2^h индекса.
        int h = std::countr_zero(n);
        return levels_[h][a >> h];
    }
    std::uint64_t k = split_point(n);
    return hasher_.node(range_hash(a, a + k), range_hash(a + k, b));
}

Hash HistoryTree::root_at(std::uint64_t tree_size) const {
    if (tree_size > size()) throw std::out_of_range("root_at: tree_size > size");
    return range_hash(0, tree_size);
}

void HistoryTree::path(std::uint64_t idx, std::uint64_t a, std::uint64_t b, Proof& out) const {
    std::uint64_t n = b - a;
    if (n == 1) return;
    std::uint64_t k = split_point(n);
    if (idx < a + k) {
        path(idx, a, a + k, out);
        out.push_back(range_hash(a + k, b));
    } else {
        path(idx, a + k, b, out);
        out.push_back(range_hash(a, a + k));
    }
}

Proof HistoryTree::inclusion_proof(std::uint64_t index, std::uint64_t tree_size) const {
    if (tree_size > size() || index >= tree_size) throw std::out_of_range("inclusion_proof");
    Proof out;
    path(index, 0, tree_size, out);
    return out;
}

void HistoryTree::subproof(std::uint64_t m, std::uint64_t a, std::uint64_t b, bool whole,
                           Proof& out) const {
    std::uint64_t n = b - a;
    if (m == n) {
        if (!whole) out.push_back(range_hash(a, b));
        return;
    }
    std::uint64_t k = split_point(n);
    if (m <= k) {
        subproof(m, a, a + k, whole, out);
        out.push_back(range_hash(a + k, b));
    } else {
        subproof(m - k, a + k, b, false, out);
        out.push_back(range_hash(a, a + k));
    }
}

Proof HistoryTree::consistency_proof(std::uint64_t old_size, std::uint64_t new_size) const {
    if (new_size > size() || old_size == 0 || old_size > new_size) throw std::out_of_range("consistency_proof");
    Proof out;
    if (old_size == new_size) return out;
    subproof(old_size, 0, new_size, true, out);
    return out;
}

std::uint64_t HistoryTree::stored_hashes() const {
    std::uint64_t s = 0;
    for (const auto& lv : levels_) s += lv.size();
    return s;
}

std::uint64_t inclusion_proof_len(std::uint64_t index, std::uint64_t n) {
    std::uint64_t len = 0;
    while (n > 1) {
        std::uint64_t k = split_point(n);
        if (index < k) {
            n = k;
        } else {
            index -= k;
            n -= k;
        }
        ++len;
    }
    return len;
}

std::uint64_t consistency_proof_len(std::uint64_t m, std::uint64_t n) {
    if (m == 0 || m == n) return 0;
    std::uint64_t len = 0;
    bool whole = true;
    while (m != n) {
        std::uint64_t k = split_point(n);
        if (m <= k) {
            n = k;
        } else {
            m -= k;
            n -= k;
            whole = false;
        }
        ++len;
    }
    return len + (whole ? 0 : 1);
}

}  // namespace tamperlog
