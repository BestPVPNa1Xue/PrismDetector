#pragma once
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace prism::accessibility {
// Semantic reconstruction, not a replacement for the sample's C++ ABI.
enum class ResultKind : std::uint32_t { Event = 0, Unchanged = 1, Error = 2 };
struct State {
    std::atomic<std::uint32_t> previous_hash{0}; // original singleton +552
    std::atomic<bool> initialized{false};        // original singleton +556
};
struct Result {
    ResultKind kind = ResultKind::Unchanged;
    std::uint8_t event_type = 0;
    std::uint32_t error_code = 0;
    std::vector<std::string> payload;
};

// Sorts a copy by unsigned-byte lexicographic order, preserves duplicates,
// hashes each full std::string followed by NUL, then reads the BE digest as LE.
std::uint32_t snapshot_hash(std::vector<std::string> ids);

// Pass the initialized flag sampled BEFORE obtaining the JNI snapshot, as
// in 0x6cf200. No mutex or compare-exchange is invented for the original.
Result evaluate_snapshot(State& state, bool initialized_before_collection,
                         const std::vector<std::string>& ids, bool env_available = true);
Result evaluate(State& state, const std::vector<std::string>& ids,
                bool env_available = true);

// Readable compact representation of the cJSON array. Not a recovered wire
// protocol. Raw non-ASCII/MUTF-8 bytes are preserved, as in cJSON strings.
std::string payload_json(const Result& result);
} // namespace prism::accessibility

#ifdef _WIN32
#define A11Y_EXPORT extern "C" __declspec(dllexport)
#else
#define A11Y_EXPORT extern "C" __attribute__((visibility("default")))
#endif

// Explicit test ABI; input bytes need not be NUL-terminated.
struct A11yBytes { const unsigned char* data; std::size_t size; };
struct A11yModelResult {
    std::uint32_t kind, event_type, error_code, previous_hash, initialized;
};
A11Y_EXPORT std::uint32_t a11y_snapshot_hash(const A11yBytes* ids, std::size_t count);
A11Y_EXPORT int a11y_evaluate(std::uint32_t previous_hash, std::uint32_t initialized,
                             const A11yBytes* ids, std::size_t count, int env_available,
                             A11yModelResult* result, char* payload, std::size_t capacity);
