#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace tamperlog {

using Hash = std::array<std::uint8_t, 32>;
using Bytes = std::vector<std::uint8_t>;

enum class HashAlg { Sha256, Blake2b256 };

// Хеши листьев и узлов по RFC 6962, 2.1: лист = H(0x00 || data), узел = H(0x01 || l || r).
// domain_separation = false оставлен только для демонстрации атаки в attacks/:
// без префиксов внутренний узел можно выдать за лист.
class Hasher {
public:
    explicit Hasher(HashAlg alg = HashAlg::Blake2b256, bool domain_separation = true)
        : alg_(alg), domain_(domain_separation) {}

    Hash empty() const;
    Hash leaf(std::span<const std::uint8_t> data) const;
    Hash node(const Hash& left, const Hash& right) const;

    HashAlg alg() const { return alg_; }

private:
    HashAlg alg_;
    bool domain_;
};

Hash sha256(std::span<const std::uint8_t> data);
Hash blake2b256(std::span<const std::uint8_t> data);

std::string to_hex(const Hash& h);
Hash from_hex(const std::string& hex);

inline std::span<const std::uint8_t> as_bytes(const std::string& s) {
    return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

}  // namespace tamperlog
