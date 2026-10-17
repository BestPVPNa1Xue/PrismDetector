#pragma once

#include <cstddef>
#include <cstdint>

#if defined(_WIN32)
#define PRISM_API __declspec(dllexport)
#else
#define PRISM_API __attribute__((visibility("default")))
#endif

extern "C" {
PRISM_API void prism_xor_cycle64(std::uint8_t* data, std::size_t size,
                                std::uint64_t key) noexcept;
PRISM_API void prism_hex_encode(char* output, const std::uint8_t* input,
                               std::size_t size, bool uppercase) noexcept;
PRISM_API bool prism_entry_pattern(std::uint32_t word0, std::uint32_t word1,
                                  std::uint32_t word2) noexcept;
}
