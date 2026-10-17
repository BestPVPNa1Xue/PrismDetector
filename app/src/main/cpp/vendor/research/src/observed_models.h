#pragma once

#include <cstdint>

#if defined(_WIN32)
#define PRISM_MODEL_API __declspec(dllexport)
#else
#define PRISM_MODEL_API __attribute__((visibility("default")))
#endif

// Compact semantic view; original strings and byte +32 are not ABI-compatible.
struct PrismFilterFlags {
    std::uint8_t acceptable;
    std::uint8_t excessive_count;
    std::uint8_t suspicious_handler;
    std::uint8_t status_failed;
    std::int32_t observed;
    std::uint8_t reason;
};

extern "C" {
PRISM_MODEL_API bool prism_tracer_positive(std::int32_t tracer_pid) noexcept;
PRISM_MODEL_API bool prism_filter_exceeds(std::int32_t observed,
                                        std::uint32_t layer) noexcept;
PRISM_MODEL_API bool prism_reason_accepted(std::uint8_t reason) noexcept;
PRISM_MODEL_API void prism_filter_policy(bool status_failed,
                                       std::int32_t observed,
                                       std::uint32_t layer,
                                       bool handler_failed,
                                       std::uint8_t reason,
                                       PrismFilterFlags* output) noexcept;
}
