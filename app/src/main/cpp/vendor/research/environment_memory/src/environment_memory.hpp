#pragma once

// Evidence-backed semantic models for the environment/integrity paths in
// libprism-sun.so.  These types deliberately do not reproduce the original
// C++/JNI ABI; they expose the values that were observed at the native
// boundaries so that the model can be tested on a host.

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace prism::environment {

// The sample's 0x44c740 path is Botan CRC32.  Its four digest bytes are read
// as a little-endian u32, therefore the native return value is bswap32 of the
// conventional CRC32 value.
std::uint32_t crc32_bswap(const std::uint8_t* data, std::size_t size) noexcept;
inline std::uint32_t crc32_bswap(const std::vector<std::uint8_t>& bytes) noexcept {
    return crc32_bswap(bytes.data(), bytes.size());
}

struct ByteView {
    const std::uint8_t* data = nullptr;
    std::size_t size = 0;
};

struct ElfExecSection {
    std::uint16_t index = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t size = 0;
    std::uint64_t flags = 0;
    std::uint32_t digest_xor_mask = 0;
};

struct ElfBaseline {
    // 0x449dd0 stores at most the first two executable section records.
    std::vector<ElfExecSection> sections;
    // The original uses a per-baseline 32-bit value and XORs it with each
    // section digest.  The source of this value is intentionally injectable.
    std::uint32_t mask = 0;
    bool initialized = false;
    // Native baseline +56 persists across calls and is consumed on fallback.
    std::uint64_t fallback_base = 0;
};

// Parse ELF64 little-endian section headers (e_shoff/e_shnum/e_shentsize).
// This intentionally uses section headers, not PT_LOAD/program headers.
std::optional<ElfBaseline> make_elf_baseline(ByteView image,
                                               std::uint32_t mask = 0,
                                               std::size_t max_sections = 2);
std::optional<ElfBaseline> make_elf_baseline(const std::vector<std::uint8_t>& image,
                                               std::uint32_t mask = 0,
                                               std::size_t max_sections = 2);

// The parser behind 0x5cc630 records r/w/x as bits 1/2/4.  Other details of
// Android's maps line (device/inode/private-vs-shared) are retained only when
// useful to a caller and are not used as an integrity verdict here.
struct MapEntry {
    std::uint64_t start = 0;
    std::uint64_t end = 0;
    std::uint64_t file_offset = 0;
    std::uint8_t permissions = 0; // read=1, write=2, execute=4
    bool private_mapping = false;
    std::string path;

    bool readable() const noexcept { return (permissions & 1u) != 0; }
    bool writable() const noexcept { return (permissions & 2u) != 0; }
    bool executable() const noexcept { return (permissions & 4u) != 0; }
};

std::optional<MapEntry> parse_maps_line(const std::string& line);
std::vector<MapEntry> parse_maps_text(const std::string& text);

enum class IntegrityCode : std::uint32_t {
    Uninitialized = 23,
    Mismatch = 12,
    Normal = 46,
    MapsUnavailable = 57,
};

struct IntegrityObservation {
    std::optional<IntegrityCode> code; // absent on host-only read/input failure
    std::size_t mappings_seen = 0;
    std::size_t executable_mappings_seen = 0;
    std::size_t sections_compared = 0;
    std::size_t sections_missing = 0;
    bool stopped_on_mismatch = false;
    bool local_termination = false;
    bool complete = true; // false: host read/input failure; code is not a native verdict
    std::uint64_t selected_base = 0;
    std::string detail;
};

using MemoryReader = std::function<std::optional<std::vector<std::uint8_t>>(
    std::uint64_t address, std::size_t size)>;

// Input must be the already-filtered, ordered records from 0x5cc630.
// Path consistency is checked before permissions. Select one base for ALL
// sections, consume +56 if any range exceeds map.end, and return after the
// FIRST readable executable mapping. Arithmetic wraps as AArch64 unsigned
// addition; file_offset is not subtracted. Reader failure is host-only.
IntegrityObservation compare_mappings(ElfBaseline& baseline,
                                       const std::vector<MapEntry>& maps,
                                       const MemoryReader& reader);

// ---- Four-library environment loop (0x40fd54) ---------------------------
enum class Library : std::uint8_t { MediaNdk = 0, Libc = 1, LibAndroid = 2, LibArt = 3 };
const char* library_name(Library library) noexcept;

struct EnvironmentState {
    // The original initializes this counter to 100.  It performs a complete
    // library pass when >=100, then increments once per ordinary cycle.
    std::uint32_t integrity_counter = 100;
    std::uint32_t precheck_failures = 0;
    // Index 0 records the media abnormal result before the local-termination
    // call; indices 1..3 are libc/libandroid/libart mismatch latches.
    std::array<bool, 4> latched{};
    bool terminated = false;
};

struct EnvironmentCycleInput {
    // These are the four return values from the already-recovered checks;
    // null means that the corresponding check was skipped this cycle.
    std::array<std::optional<std::uint32_t>, 4> library_codes{};
    // The outer loop has a separate early-failure counter (threshold 3).
    bool precheck_failed = false;
    // 0x4106f8 uses signed CMP/B.LE, so only a positive signed value is a
    // tracer hit.  null represents an acquisition/parsing failure.
    std::optional<std::int32_t> tracer_pid;
};

struct EnvironmentCycleResult {
    bool complete = true; // false when an expected checker result was not supplied
    bool ran_integrity = false;
    bool local_termination = false;
    bool tracer_positive = false;
    std::uint32_t precheck_failures = 0;
    std::array<bool, 4> latched{};
    std::string reason;
};

EnvironmentCycleResult run_environment_cycle(EnvironmentState& state,
                                             const EnvironmentCycleInput& input);

// Payload order of 0x66e838 (event 21) and numeric value of 0x68cbe0
// (event 24). Serialization and transport are outside these helpers.
std::array<bool, 3> event21_flags(const EnvironmentState& state) noexcept;
unsigned event24_value(const EnvironmentState& state) noexcept;

// ---- Input-method list consumer (0x6f4218 + 0x6f8da4) -------------------
struct InputMethodResult {
    enum class Kind : std::uint32_t { Event = 0, Unchanged = 1, Error = 2 };
    Kind kind = Kind::Unchanged;
    std::uint8_t event_type = 0; // 34 first, 35 changed
    std::uint32_t error_code = 0;
    std::uint32_t previous_hash = 0;
    bool initialized = false;
    std::vector<std::string> payload; // original list order
};

struct InputMethodState {
    std::uint32_t previous_hash = 0;
    bool initialized = false;
};

std::uint32_t input_method_hash(std::vector<std::string> service_names);
InputMethodResult evaluate_input_methods(InputMethodState& state,
                                         const std::vector<std::string>& service_names,
                                         bool jni_environment_available = true);

} // namespace prism::environment

