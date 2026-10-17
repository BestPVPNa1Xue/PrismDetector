#include "identity.hpp"
#include <algorithm>
#include <limits>
#include <stdexcept>

namespace prism {
namespace {
std::string dhex(const Digest &d) {
    return hex(Bytes(d.begin(), d.end()));
}
std::string_view cstr(std::string_view s) {
    return s.substr(0, s.find('\0'));
}
std::uint64_t le(const std::uint8_t *p, unsigned n) {
    std::uint64_t r = 0;
    for (unsigned i = 0; i < n; ++i)
        r |= std::uint64_t(p[i]) << (8 * i);
    return r;
}
void putle(std::uint8_t *p, std::uint64_t v, unsigned n) {
    for (unsigned i = 0; i < n; ++i)
        p[i] = static_cast<std::uint8_t>(v >> (8 * i));
}
void be(Bytes &b, std::uint64_t v, unsigned n) {
    for (unsigned i = n; i > 0; --i)
        b.push_back(static_cast<std::uint8_t>(v >> ((i - 1) * 8)));
}
} // namespace
std::string salted_id(std::string_view text) {
    if (text.empty())
        return {};
    auto b = bytes(text);
    b.insert(b.end(), std::begin(salt), std::end(salt));
    return dhex(sha256(b));
}
std::string drm_id(const Bytes &raw) {
    return salted_id(hex(raw));
}
std::string normalize_boot_id(std::string_view read_result) {
    auto s = cstr(read_result.substr(0, 47));
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n'))
        s.remove_suffix(1);
    return std::string(s);
}
std::string boot_id(std::string_view read_result) {
    return salted_id(normalize_boot_id(read_result));
}
Identity choose_identity(const Bytes &drm, std::string_view boot) {
    auto d = drm_id(drm);
    if (!d.empty())
        return {d, true};
    return {boot_id(boot), false};
}
ActivityInfo activity_info(const std::vector<std::string> &names) {
    ActivityInfo r;
    constexpr std::string_view suffix = ".wxapi.WXEntryActivity";
    for (const auto &raw : names) {
        auto n = cstr(raw);
        auto pos = n.find(suffix);
        if (n.size() >= suffix.size() && n.substr(n.size() - suffix.size()) == suffix)
            r.wx_prefix = std::string(n.substr(0, pos));
        if (n == "com.netease.mpay.MpayLoginActionBarActivity")
            r.has_mpay = true;
    }
    return r;
}
std::string json_string(std::string_view s) {
    std::string r = "\"";
    constexpr char h[] = "0123456789abcdef";
    for (unsigned char c : cstr(s)) {
        switch (c) {
        case '"':
            r += "\\\"";
            break;
        case '\\':
            r += "\\\\";
            break;
        case '\b':
            r += "\\b";
            break;
        case '\f':
            r += "\\f";
            break;
        case '\n':
            r += "\\n";
            break;
        case '\r':
            r += "\\r";
            break;
        case '\t':
            r += "\\t";
            break;
        default:
            if (c < 32) {
                r += "\\u00";
                r += h[c >> 4];
                r += h[c & 15];
            } else
                r += static_cast<char>(c);
        }
    }
    return r + '"';
}
void Session::install(Bytes aes_key, Bytes mac_key, std::uint16_t new_generation) {
    if (aes_key.size() != 32 || !new_generation)
        throw std::invalid_argument("invalid session key/generation");
    encryption_key = std::move(aes_key);
    hmac_key = std::move(mac_key);
    generation = new_generation;
    next_sequence = 0;
}
Result client_properties(const std::vector<std::optional<std::string>> &args, const Identity &id,
                         const AppInfo &app, const Session &s, bool jni_available) {
    if (args.size() != 1 || !args[0] || cstr(*args[0]).size() < 8)
        return {};
    if (!s.generation)
        return {Result::Kind::Error, 6005, {}};
    auto challenge = std::string(cstr(*args[0]));
    auto mac = dhex(hmac_sha256(s.hmac_key, bytes(id.value + challenge + version)));
    if (!jni_available)
        return {Result::Kind::Error, 3002, {}};
    std::string p = "[[" + json_string(version) + ",1],[" + json_string(id.value) + "," +
                    (id.from_drm ? "true" : "false") + "],[" + json_string(challenge) + "," +
                    json_string(mac) + "],[" + json_string(app.package_name) + "," +
                    json_string(app.certificate_digest) + "," +
                    json_string(app.activities.wx_prefix) + "," +
                    (app.activities.has_mpay ? "true" : "false") + "]]";
    return {Result::Kind::Event, 0, std::move(p)};
}
Bytes encrypt_packet(const Bytes &plaintext, const Bytes &key, std::uint16_t generation,
                     std::uint64_t sequence, std::uint8_t random_nibble) {
    if (random_nibble > 15)
        throw std::invalid_argument("nibble must be 0..15");
    Bytes n = {0, 0};
    be(n, generation, 2);
    be(n, sequence, 8);
    std::array<std::uint8_t, 12> nonce{};
    std::copy(n.begin(), n.end(), nonce.begin());
    Bytes out = {static_cast<std::uint8_t>((random_nibble << 4) | 2)};
    be(out, generation, 2);
    out.insert(out.end(), n.begin(), n.end());
    auto encrypted = aes256_gcm(key, nonce, plaintext);
    out.insert(out.end(), encrypted.begin(), encrypted.end());
    return out;
}
std::optional<Record> encode_result(const Result &result, Session &s, std::uint8_t random_nibble) {
    if (result.kind == Result::Kind::None)
        return std::nullopt;
    if (result.kind == Result::Kind::Error) {
        Bytes b(4);
        putle(b.data(), result.error, 4);
        return Record{6, b};
    }
    if (!s.generation)
        return Record{5, {}};
    // Engineering guard: original uses an unsigned increment. Do not reuse a GCM nonce.
    if (s.next_sequence == std::numeric_limits<std::uint64_t>::max())
        throw std::overflow_error("sequence exhausted");
    auto seq = s.next_sequence++;
    return Record{5, encrypt_packet(bytes("[19," + result.payload_json + "]"), s.encryption_key,
                                    s.generation, seq, random_nibble)};
}
bool Ring::write(const Record &r) {
    if (r.payload.size() > 0xff80)
        return false;
    auto head = static_cast<std::uint32_t>(le(memory.data(), 4));
    auto tail = static_cast<std::uint32_t>(le(memory.data() + 4, 4));
    auto count =
        static_cast<std::uint32_t>(std::max<std::size_t>(1, (r.payload.size() + 4087) / 4088));
    if (static_cast<std::uint32_t>(head - tail) > 16 - count)
        return false;
    std::size_t p = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        auto slot = memory.data() + 8 + ((head + i) & 15) * 4096;
        auto n = std::min<std::size_t>(4088, r.payload.size() - p);
        putle(slot, i == 0 ? r.payload.size() : 0, 4);
        slot[4] = i == 0 ? r.type : 0;
        slot[5] = i == 0 ? static_cast<std::uint8_t>(count) : 0;
        putle(slot + 6, n, 2);
        std::copy_n(r.payload.begin() + p, n, slot + 8);
        p += n;
    }
    putle(memory.data(), head + count, 4);
    return true;
}
Bytes first_v2_certificate(const Bytes &apk) {
    // Strict bounds replace the sample's unchecked seek/read behavior.
    auto read = [&](std::size_t p, unsigned n) -> std::uint64_t {
        if (p > apk.size() || n > apk.size() - p)
            throw std::runtime_error("truncated APK");
        return le(apk.data() + p, n);
    };
    std::size_t eocd = std::string::npos;
    for (std::size_t c = 0; c <= 65535 && c + 22 <= apk.size(); ++c) {
        auto p = apk.size() - 22 - c;
        if (read(p, 4) == 0x06054b50 && read(p + 20, 2) == c) {
            eocd = p;
            break;
        }
    }
    if (eocd == std::string::npos)
        throw std::runtime_error("EOCD missing");
    std::size_t cd = static_cast<std::size_t>(read(eocd + 16, 4));
    if (cd < 24 || cd > eocd)
        throw std::runtime_error("invalid central directory");
    if (!std::equal(apk.begin() + cd - 16, apk.begin() + cd, bytes("APK Sig Block 42").begin()))
        throw std::runtime_error("signing block missing");
    auto size = read(cd - 24, 8);
    if (size < 24 || size > cd - 8)
        throw std::runtime_error("invalid signing block size");
    std::size_t p = cd - static_cast<std::size_t>(size) - 8;
    if (read(p, 8) != size)
        throw std::runtime_error("signing sizes differ");
    p += 8;
    while (p < cd - 24) {
        if (cd - 24 - p < 8)
            throw std::runtime_error("truncated pair length");
        auto len = read(p, 8);
        p += 8;
        if (len < 4 || len > cd - 24 - p)
            throw std::runtime_error("invalid pair size");
        std::size_t end = p + static_cast<std::size_t>(len);
        if (read(p, 4) == 0x7109871a) {
            p += 4;
            auto field = [&](std::size_t &at, std::size_t limit) {
                if (at > limit || limit - at < 4)
                    throw std::runtime_error("nested field truncated");
                auto n = read(at, 4);
                at += 4;
                if (n > limit - at)
                    throw std::runtime_error("nested field overflow");
                return at + static_cast<std::size_t>(n);
            };
            auto signers_end = field(p, end);
            auto signer_end = field(p, signers_end);
            auto signed_end = field(p, signer_end);
            p = field(p, signed_end);
            auto certs_end = field(p, signed_end);
            auto cert_end = field(p, certs_end);
            return Bytes(apk.begin() + p, apk.begin() + cert_end);
        }
        p = end;
    }
    throw std::runtime_error("APK v2 pair missing");
}
} // namespace prism
