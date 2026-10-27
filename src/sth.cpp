#include "tamperlog/sth.hpp"

#include <cstring>

extern "C" {
#include "monocypher-ed25519.h"
}

namespace tamperlog {

std::array<std::uint8_t, 64> SignedTreeHead::message() const {
    std::array<std::uint8_t, 64> m{};
    std::memcpy(m.data(), "tamperlog-sth-v1", 16);
    for (int i = 0; i < 8; ++i) {
        m[16 + i] = std::uint8_t(tree_size >> (56 - 8 * i));
        m[24 + i] = std::uint8_t(timestamp_ms >> (56 - 8 * i));
    }
    std::memcpy(m.data() + 32, root.data(), 32);
    return m;
}

KeyPair keypair_from_seed(const std::array<std::uint8_t, 32>& seed) {
    KeyPair kp;
    std::uint8_t s[32];
    std::memcpy(s, seed.data(), 32);  // Monocypher затирает seed
    crypto_ed25519_key_pair(kp.secret.data(), kp.pub.data(), s);
    return kp;
}

void sign_sth(SignedTreeHead& sth, const KeyPair& kp) {
    auto m = sth.message();
    crypto_ed25519_sign(sth.signature.data(), kp.secret.data(), m.data(), m.size());
}

bool verify_sth(const SignedTreeHead& sth, const PublicKey& pub) {
    auto m = sth.message();
    return crypto_ed25519_check(sth.signature.data(), pub.data(), m.data(), m.size()) == 0;
}

}  // namespace tamperlog
