#pragma once
#include <array>
#include <cstdint>

#include "tamperlog/hash.hpp"

namespace tamperlog {

using PublicKey = std::array<std::uint8_t, 32>;
using SecretKey = std::array<std::uint8_t, 64>;
using Signature = std::array<std::uint8_t, 64>;

// Подписанный корень (signed tree head): оператор подписывает «у журнала tree_size
// записей и вот его корень». Две разные подписанные головы одного размера — готовое
// доказательство раздвоения, которое можно показать кому угодно.
struct SignedTreeHead {
    std::uint64_t tree_size = 0;
    std::uint64_t timestamp_ms = 0;
    Hash root{};
    Signature signature{};

    // "tamperlog-sth-v1" || size (8 байт, big-endian) || timestamp (8 байт, BE) || root
    std::array<std::uint8_t, 16 + 8 + 8 + 32> message() const;
};

struct KeyPair {
    SecretKey secret;
    PublicKey pub;
};

KeyPair keypair_from_seed(const std::array<std::uint8_t, 32>& seed);  // Ed25519, RFC 8032
void sign_sth(SignedTreeHead& sth, const KeyPair& kp);
bool verify_sth(const SignedTreeHead& sth, const PublicKey& pub);

}  // namespace tamperlog
