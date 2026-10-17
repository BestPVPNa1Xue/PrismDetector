#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace prism {
using Bytes = std::vector<std::uint8_t>;
using Digest = std::array<std::uint8_t, 32>;
inline constexpr char version[] = "PSR_20260211.5223e3a";
inline constexpr std::uint8_t salt[16] = {0x67, 0xd6, 0xd3, 0x1d, 0xce, 0xa9, 0xee, 0xc7,
                                          0xba, 0x1b, 0x1c, 0xe2, 0xc8, 0x7b, 0xab, 0x7b};
Bytes bytes(std::string_view s);
std::string hex(const Bytes &b);
Bytes unhex(std::string_view s);
Digest sha256(const Bytes &b);
Digest hmac_sha256(const Bytes &key, const Bytes &msg);
Bytes aes256_gcm(const Bytes &key, const std::array<std::uint8_t, 12> &nonce,
                 const Bytes &plaintext);
std::string salted_id(std::string_view text);
std::string drm_id(const Bytes &raw); // hex(raw) before hashing; empty stays empty
std::string normalize_boot_id(std::string_view read_result);
std::string boot_id(std::string_view read_result);
struct Identity {
    std::string value;
    bool from_drm = false;
};
Identity choose_identity(const Bytes &drm, std::string_view boot);
struct ActivityInfo {
    std::string wx_prefix;
    bool has_mpay = false;
};
ActivityInfo activity_info(const std::vector<std::string> &names);
// Bounded parser of the first certificate in the first v2 signer. No signature verification.
Bytes first_v2_certificate(const Bytes &apk);
struct AppInfo {
    std::string package_name, certificate_digest;
    ActivityInfo activities;
};
struct Session {
    Bytes encryption_key, hmac_key;
    std::uint16_t generation = 0;
    std::uint64_t next_sequence = 0;
    void install(Bytes aes_key, Bytes mac_key, std::uint16_t new_generation);
};
struct Result {
    enum class Kind { Event = 0, None = 1, Error = 2 } kind = Kind::None;
    std::uint32_t error = 0;
    std::string payload_json;
};
// nullopt is a non-string JSON item; caller retains array cardinality.
Result client_properties(const std::vector<std::optional<std::string>> &args, const Identity &id,
                         const AppInfo &app, const Session &s, bool jni_available = true);
std::string json_string(std::string_view s);
Bytes encrypt_packet(const Bytes &plaintext, const Bytes &key, std::uint16_t generation,
                     std::uint64_t sequence, std::uint8_t random_nibble);
struct Record {
    std::uint8_t type;
    Bytes payload;
};
std::optional<Record> encode_result(const Result &result, Session &s, std::uint8_t random_nibble);
// In-memory single-thread model; NOT a cross-process atomic queue implementation.
class Ring {
  public:
    std::array<std::uint8_t, 0x10008> memory{};
    bool write(const Record &record);
};
} // namespace prism
