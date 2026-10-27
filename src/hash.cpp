#include "tamperlog/hash.hpp"

#include <stdexcept>

extern "C" {
#include "monocypher.h"
}

namespace tamperlog {

Hash blake2b256(std::span<const std::uint8_t> data) {
    Hash out;
    crypto_blake2b(out.data(), out.size(), data.data(), data.size());
    return out;
}

static Hash digest(HashAlg alg, std::span<const std::uint8_t> data) {
    return alg == HashAlg::Sha256 ? sha256(data) : blake2b256(data);
}

Hash Hasher::empty() const { return digest(alg_, {}); }

Hash Hasher::leaf(std::span<const std::uint8_t> data) const {
    if (!domain_) return digest(alg_, data);
    Bytes buf;
    buf.reserve(data.size() + 1);
    buf.push_back(0x00);
    buf.insert(buf.end(), data.begin(), data.end());
    return digest(alg_, buf);
}

Hash Hasher::node(const Hash& left, const Hash& right) const {
    std::uint8_t buf[65];
    std::size_t off = 0;
    if (domain_) buf[off++] = 0x01;
    std::copy(left.begin(), left.end(), buf + off);
    std::copy(right.begin(), right.end(), buf + off + 32);
    return digest(alg_, {buf, off + 64});
}

std::string to_hex(const Hash& h) {
    static const char* d = "0123456789abcdef";
    std::string s(64, '0');
    for (std::size_t i = 0; i < 32; ++i) {
        s[2 * i] = d[h[i] >> 4];
        s[2 * i + 1] = d[h[i] & 15];
    }
    return s;
}

Hash from_hex(const std::string& hex) {
    if (hex.size() != 64) throw std::invalid_argument("hash hex must be 64 chars");
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw std::invalid_argument("bad hex");
    };
    Hash h;
    for (std::size_t i = 0; i < 32; ++i) h[i] = std::uint8_t(nib(hex[2 * i]) << 4 | nib(hex[2 * i + 1]));
    return h;
}

}  // namespace tamperlog
