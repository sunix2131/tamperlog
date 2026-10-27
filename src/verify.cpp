#include "tamperlog/verify.hpp"

#include <bit>

namespace tamperlog {

bool verify_inclusion(const Hasher& h, std::uint64_t index, std::uint64_t tree_size,
                      const Hash& leaf_hash, const Proof& proof, const Hash& root) {
    if (index >= tree_size) return false;
    std::uint64_t fn = index, sn = tree_size - 1;
    Hash r = leaf_hash;
    for (const Hash& p : proof) {
        if (sn == 0) return false;  // лишние элементы в доказательстве
        if ((fn & 1) || fn == sn) {
            r = h.node(p, r);
            if (!(fn & 1)) {
                while (!(fn & 1) && fn != 0) {
                    fn >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = h.node(r, p);
        }
        fn >>= 1;
        sn >>= 1;
    }
    return sn == 0 && r == root;
}

bool verify_consistency(const Hasher& h, std::uint64_t old_size, std::uint64_t new_size,
                        const Hash& old_root, const Hash& new_root, const Proof& proof) {
    // RFC 9162, 2.1.4.2 определяет проверку только для 0 < old < new. Размер 0 отклоняем,
    // как и transparency-dev/merkle; равные размеры — пустое доказательство и равные корни.
    if (old_size == 0 || old_size > new_size) return false;
    if (old_size == new_size) return proof.empty() && old_root == new_root;
    if (proof.empty()) return false;

    Proof path;
    if (std::has_single_bit(old_size)) path.push_back(old_root);
    path.insert(path.end(), proof.begin(), proof.end());

    std::uint64_t fn = old_size - 1, sn = new_size - 1;
    while (fn & 1) {
        fn >>= 1;
        sn >>= 1;
    }
    Hash fr = path[0], sr = path[0];
    for (std::size_t i = 1; i < path.size(); ++i) {
        const Hash& c = path[i];
        if (sn == 0) return false;
        if ((fn & 1) || fn == sn) {
            fr = h.node(c, fr);
            sr = h.node(c, sr);
            if (!(fn & 1)) {
                while (!(fn & 1) && fn != 0) {
                    fn >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = h.node(sr, c);
        }
        fn >>= 1;
        sn >>= 1;
    }
    return fr == old_root && sr == new_root && sn == 0;
}

}  // namespace tamperlog
