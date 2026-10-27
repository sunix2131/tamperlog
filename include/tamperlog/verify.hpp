#pragma once
#include <cstdint>

#include "tamperlog/tree.hpp"

namespace tamperlog {

// Проверки клиента по RFC 9162, 2.1.3.2 и 2.1.4.2. Клиенту не нужно дерево:
// только размер, корень, хеш записи и само доказательство.
bool verify_inclusion(const Hasher& h, std::uint64_t index, std::uint64_t tree_size,
                      const Hash& leaf_hash, const Proof& proof, const Hash& root);

bool verify_consistency(const Hasher& h, std::uint64_t old_size, std::uint64_t new_size,
                        const Hash& old_root, const Hash& new_root, const Proof& proof);

}  // namespace tamperlog
