#include "verified_helpers.h"

// 0x2bc7b0: body only; original entry checks and stack canary are not reproduced.
void prism_xor_cycle64(std::uint8_t* data, std::size_t size,
                       std::uint64_t key) noexcept {
    for (std::size_t i = 0; i < size; ++i) {
        data[i] ^= static_cast<std::uint8_t>(key >> (8 * (i & 7)));
    }
}

// 0x11da20: writes exactly 2 * size bytes, with no trailing NUL.
void prism_hex_encode(char* output, const std::uint8_t* input,
                      std::size_t size, bool uppercase) noexcept {
    const char* digits = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
    for (std::size_t i = 0; i < size; ++i) {
        output[2 * i] = digits[input[i] >> 4];
        output[2 * i + 1] = digits[input[i] & 15];
    }
}

// Repeated AArch64 B / BRK / BR predicates; this is a classifier, not a hook test.
bool prism_entry_pattern(std::uint32_t word0, std::uint32_t word1,
                         std::uint32_t word2) noexcept {
    return (word0 & 0xfc000000u) == 0x14000000u ||
           (word0 & 0xffe00000u) == 0xd4200000u ||
           (word1 & 0xfffffc00u) == 0xd61f0000u ||
           (word2 & 0xfffffc00u) == 0xd61f0000u;
}
