// Portable research implementation. Original uses Botan; see the oracle tests.
#include "identity.hpp"
#include <algorithm>
#include <stdexcept>

namespace prism {
Bytes bytes(std::string_view s) {
    return Bytes(s.begin(), s.end());
}
std::string hex(const Bytes &b) {
    constexpr char h[] = "0123456789ABCDEF";
    std::string r;
    r.reserve(b.size() * 2);
    for (auto v : b) {
        r += h[v >> 4];
        r += h[v & 15];
    }
    return r;
}
Bytes unhex(std::string_view s) {
    if (s.size() % 2)
        throw std::invalid_argument("odd hex length");
    auto digit = [](char c) -> unsigned {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        throw std::invalid_argument("invalid hex");
    };
    Bytes r;
    for (std::size_t i = 0; i < s.size(); i += 2)
        r.push_back(static_cast<std::uint8_t>((digit(s[i]) << 4) | digit(s[i + 1])));
    return r;
}
namespace {
std::uint32_t rotr(std::uint32_t a, unsigned n) {
    return (a >> n) | (a << (32 - n));
}
constexpr std::uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
std::uint8_t mul8(std::uint8_t a, std::uint8_t b) {
    std::uint8_t r = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1)
            r ^= a;
        a = static_cast<std::uint8_t>((a << 1) ^ ((a & 128) ? 0x1b : 0));
        b >>= 1;
    }
    return r;
}
std::uint8_t sbox(std::uint8_t x) {
    std::uint8_t y = 1, b = x;
    unsigned exponent = 254;
    while (exponent) {
        if (exponent & 1)
            y = mul8(y, b);
        b = mul8(b, b);
        exponent >>= 1;
    }
    if (!x)
        y = 0;
    unsigned r = y ^ 0x63;
    for (unsigned n = 1; n <= 4; ++n)
        r ^= static_cast<std::uint8_t>((y << n) | (y >> (8 - n)));
    return static_cast<std::uint8_t>(r);
}
using Block = std::array<std::uint8_t, 16>;
class AES256 {
    std::array<std::uint8_t, 240> keys{};

  public:
    explicit AES256(const Bytes &key) {
        if (key.size() != 32)
            throw std::invalid_argument("AES-256 requires 32 bytes");
        std::copy(key.begin(), key.end(), keys.begin());
        std::uint8_t rc = 1;
        std::size_t i = 32;
        while (i < keys.size()) {
            std::array<std::uint8_t, 4> t{};
            std::copy_n(keys.begin() + i - 4, 4, t.begin());
            if (i % 32 == 0) {
                std::rotate(t.begin(), t.begin() + 1, t.end());
                for (auto &v : t)
                    v = sbox(v);
                t[0] ^= rc;
                rc = mul8(rc, 2);
            } else if (i % 32 == 16)
                for (auto &v : t)
                    v = sbox(v);
            for (auto v : t) {
                keys[i] = keys[i - 32] ^ v;
                ++i;
            }
        }
    }
    Block encrypt(Block a) const {
        auto add = [&](unsigned round) {
            for (unsigned i = 0; i < 16; ++i)
                a[i] ^= keys[round * 16 + i];
        };
        add(0);
        for (unsigned round = 1; round <= 14; ++round) {
            for (auto &v : a)
                v = sbox(v);
            Block b = a;
            for (unsigned row = 0; row < 4; ++row)
                for (unsigned c = 0; c < 4; ++c)
                    a[row + 4 * c] = b[row + 4 * ((c + row) % 4)];
            if (round != 14)
                for (unsigned c = 0; c < 4; ++c) {
                    const unsigned p = 4 * c;
                    const auto x = a[p], y = a[p + 1], z = a[p + 2], w = a[p + 3];
                    a[p] = mul8(x, 2) ^ mul8(y, 3) ^ z ^ w;
                    a[p + 1] = x ^ mul8(y, 2) ^ mul8(z, 3) ^ w;
                    a[p + 2] = x ^ y ^ mul8(z, 2) ^ mul8(w, 3);
                    a[p + 3] = mul8(x, 3) ^ y ^ z ^ mul8(w, 2);
                }
            add(round);
        }
        return a;
    }
};
Block gmul(Block x, Block v) {
    Block z{};
    for (unsigned i = 0; i < 128; ++i) {
        if (x[i / 8] & (0x80 >> (i % 8)))
            for (unsigned j = 0; j < 16; ++j)
                z[j] ^= v[j];
        bool low = (v[15] & 1) != 0;
        for (int j = 15; j >= 0; --j)
            v[j] = static_cast<std::uint8_t>((v[j] >> 1) | (j ? ((v[j - 1] & 1) << 7) : 0));
        if (low)
            v[0] ^= 0xe1;
    }
    return z;
}
} // namespace
Digest sha256(const Bytes &input) {
    Bytes msg = input;
    const std::uint64_t bits = static_cast<std::uint64_t>(msg.size()) * 8;
    msg.push_back(0x80);
    while (msg.size() % 64 != 56)
        msg.push_back(0);
    for (int i = 7; i >= 0; --i)
        msg.push_back(static_cast<std::uint8_t>(bits >> (i * 8)));
    std::array<std::uint32_t, 8> h = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    for (std::size_t p = 0; p < msg.size(); p += 64) {
        std::uint32_t w[64]{};
        for (unsigned i = 0; i < 16; ++i)
            for (unsigned j = 0; j < 4; ++j)
                w[i] = (w[i] << 8) | msg[p + i * 4 + j];
        for (unsigned i = 16; i < 64; ++i)
            w[i] = w[i - 16] + (rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)) +
                   w[i - 7] + (rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10));
        auto a = h;
        for (unsigned i = 0; i < 64; ++i) {
            auto t1 = a[7] + (rotr(a[4], 6) ^ rotr(a[4], 11) ^ rotr(a[4], 25)) +
                      ((a[4] & a[5]) ^ (~a[4] & a[6])) + k[i] + w[i];
            auto t2 = (rotr(a[0], 2) ^ rotr(a[0], 13) ^ rotr(a[0], 22)) +
                      ((a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]));
            for (unsigned j = 7; j > 0; --j)
                a[j] = a[j - 1];
            a[4] += t1;
            a[0] = t1 + t2;
        }
        for (unsigned i = 0; i < 8; ++i)
            h[i] += a[i];
    }
    Digest d{};
    for (unsigned i = 0; i < 32; ++i)
        d[i] = static_cast<std::uint8_t>(h[i / 4] >> (24 - (i % 4) * 8));
    return d;
}
Digest hmac_sha256(const Bytes &key, const Bytes &msg) {
    Bytes k0 = key;
    if (k0.size() > 64) {
        auto d = sha256(k0);
        k0.assign(d.begin(), d.end());
    }
    k0.resize(64);
    Bytes inner = k0, outer = k0;
    for (auto &v : inner)
        v ^= 0x36;
    for (auto &v : outer)
        v ^= 0x5c;
    inner.insert(inner.end(), msg.begin(), msg.end());
    auto d = sha256(inner);
    outer.insert(outer.end(), d.begin(), d.end());
    return sha256(outer);
}
Bytes aes256_gcm(const Bytes &key, const std::array<std::uint8_t, 12> &nonce,
                 const Bytes &plaintext) {
    AES256 aes(key);
    Block j0{};
    std::copy(nonce.begin(), nonce.end(), j0.begin());
    j0[15] = 1;
    auto counter = j0;
    Bytes cipher(plaintext.size());
    for (std::size_t p = 0; p < plaintext.size(); p += 16) {
        for (int i = 15; i >= 12; --i)
            if (++counter[i])
                break;
        auto stream = aes.encrypt(counter);
        for (std::size_t j = 0; j < std::min<std::size_t>(16, plaintext.size() - p); ++j)
            cipher[p + j] = plaintext[p + j] ^ stream[j];
    }
    const Block h = aes.encrypt(Block{});
    Block tag{};
    for (std::size_t p = 0; p < cipher.size(); p += 16) {
        for (std::size_t j = 0; j < std::min<std::size_t>(16, cipher.size() - p); ++j)
            tag[j] ^= cipher[p + j];
        tag = gmul(tag, h);
    }
    std::uint64_t bits = static_cast<std::uint64_t>(cipher.size()) * 8;
    for (unsigned i = 0; i < 8; ++i)
        tag[15 - i] ^= static_cast<std::uint8_t>(bits >> (i * 8));
    tag = gmul(tag, h);
    auto mask = aes.encrypt(j0);
    for (unsigned i = 0; i < 16; ++i)
        tag[i] ^= mask[i];
    cipher.insert(cipher.end(), tag.begin(), tag.end());
    return cipher;
}
} // namespace prism
