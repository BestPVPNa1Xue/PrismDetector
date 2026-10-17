#include "environment_memory.hpp"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <limits>
#include <sstream>
#include <string_view>

namespace prism::environment {
namespace {

constexpr std::uint32_t kCrcPolynomial = 0xedb88320U;
constexpr std::uint64_t kElf64ShdrSize = 64;
constexpr std::uint64_t kElf64EhdrSize = 64;
constexpr std::uint64_t kElfClass64 = 2;
constexpr std::uint64_t kElfDataLsb = 1;
constexpr std::uint64_t kElfMachineAarch64 = 183;
constexpr std::uint64_t kShfExecInstr = 0x4;

template <typename T>
bool read_le(ByteView view, std::uint64_t offset, T& out) noexcept {
    if (offset > view.size || sizeof(T) > view.size - static_cast<std::size_t>(offset)) {
        return false;
    }
    out = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i)
        out = static_cast<T>(out | (static_cast<std::uint64_t>(view.data[offset + i]) << (8 * i)));
    return true;
}

bool range_inside(ByteView view, std::uint64_t offset, std::uint64_t size) noexcept {
    return offset <= view.size && size <= view.size - offset;
}

std::uint32_t bswap32(std::uint32_t value) noexcept {
    return ((value & 0x000000ffU) << 24) |
           ((value & 0x0000ff00U) << 8) |
           ((value & 0x00ff0000U) >> 8) |
           ((value & 0xff000000U) >> 24);
}

bool byte_less(const std::string& left, const std::string& right) noexcept {
    return std::lexicographical_compare(
        left.begin(), left.end(), right.begin(), right.end(),
        [](char a, char b) {
            return static_cast<unsigned char>(a) < static_cast<unsigned char>(b);
        });
}

std::optional<std::uint64_t> parse_hex(std::string_view text) noexcept {
    if (text.empty()) return std::nullopt;
    std::uint64_t value = 0;
    const auto* first = text.data();
    const auto* last = first + text.size();
    const auto result = std::from_chars(first, last, value, 16);
    if (result.ec != std::errc() || result.ptr != last) return std::nullopt;
    return value;
}

} // namespace

std::uint32_t crc32_bswap(const std::uint8_t* data, std::size_t size) noexcept {
    // Botan's CRC32 and the sample's update/final path use the reflected
    // IEEE polynomial with the usual init/final xor.  A null pointer is only
    // accepted for a zero-length input, matching the host model's boundary.
    if (size != 0 && data == nullptr) return 0;
    std::uint32_t crc = 0xffffffffU;
    for (std::size_t index = 0; index < size; ++index) {
        crc ^= data[index];
        for (unsigned bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1U) ^ ((0U - (crc & 1U)) & kCrcPolynomial);
        }
    }
    return bswap32(crc ^ 0xffffffffU);
}

std::optional<ElfBaseline> make_elf_baseline(ByteView image,
                                               std::uint32_t mask,
                                               std::size_t max_sections) {
    if (image.data == nullptr || image.size < kElf64EhdrSize || max_sections == 0) {
        return std::nullopt;
    }
    if (image.data[0] != 0x7f || image.data[1] != 'E' || image.data[2] != 'L' ||
        image.data[3] != 'F' || image.data[4] != kElfClass64 || image.data[5] != kElfDataLsb) {
        return std::nullopt;
    }
    std::uint16_t machine = 0;
    std::uint64_t section_offset = 0;
    std::uint16_t section_entry_size = 0;
    std::uint16_t section_count = 0;
    if (!read_le(image, 18, machine) || !read_le(image, 40, section_offset) ||
        !read_le(image, 58, section_entry_size) || !read_le(image, 60, section_count)) {
        return std::nullopt;
    }
    // This sample is Android AArch64.  Rejecting another machine here avoids
    // silently treating a caller's unrelated file as a PrismSUN baseline.
    if (machine != kElfMachineAarch64 || section_entry_size != kElf64ShdrSize ||
        section_count == 0 || !range_inside(image, section_offset,
                                             static_cast<std::uint64_t>(section_entry_size) * section_count)) {
        return std::nullopt;
    }
    ElfBaseline baseline;
    baseline.mask = mask;
    max_sections = std::min<std::size_t>(max_sections, 2);
    baseline.sections.reserve(std::min<std::size_t>(max_sections, section_count));
    for (std::uint16_t index = 0; index < section_count && baseline.sections.size() < max_sections; ++index) {
        const auto offset = section_offset + static_cast<std::uint64_t>(index) * section_entry_size;
        std::uint64_t flags = 0;
        std::uint64_t data_offset = 0;
        std::uint64_t data_size = 0;
        if (!read_le(image, offset + 8, flags) || !read_le(image, offset + 24, data_offset) ||
            !read_le(image, offset + 32, data_size)) {
            return std::nullopt;
        }
        if ((flags & kShfExecInstr) == 0) continue;
        // The native selection tests only SHF_EXECINSTR. This host parser
        // additionally validates the file range before reading it.
        if (!range_inside(image, data_offset, data_size)) return std::nullopt;
        const auto digest = crc32_bswap(image.data + static_cast<std::size_t>(data_offset),
                                        static_cast<std::size_t>(data_size));
        baseline.sections.push_back({index, data_offset, data_size, flags, digest ^ mask});
    }
    baseline.initialized = !baseline.sections.empty();
    return baseline;
}

std::optional<ElfBaseline> make_elf_baseline(const std::vector<std::uint8_t>& image,
                                               std::uint32_t mask,
                                               std::size_t max_sections) {
    return make_elf_baseline({image.data(), image.size()}, mask, max_sections);
}

std::optional<MapEntry> parse_maps_line(const std::string& line) {
    // /proc/<pid>/maps: start-end perms offset dev inode [pathname].  The
    // parser accepts a missing pathname and ignores device/inode after the
    // fields needed by the observed checker.
    std::istringstream stream(line);
    std::string range;
    std::string permissions;
    std::string offset;
    std::string device;
    std::string inode;
    if (!(stream >> range >> permissions >> offset >> device >> inode)) return std::nullopt;
    const auto dash = range.find('-');
    if (dash == std::string::npos || permissions.size() != 4) return std::nullopt;
    const auto start = parse_hex(std::string_view(range).substr(0, dash));
    const auto end = parse_hex(std::string_view(range).substr(dash + 1));
    const auto file_offset = parse_hex(offset);
    if (!start || !end || !file_offset || *start >= *end) return std::nullopt;
    if (permissions[0] != 'r' && permissions[0] != '-') return std::nullopt;
    if (permissions[1] != 'w' && permissions[1] != '-') return std::nullopt;
    if (permissions[2] != 'x' && permissions[2] != '-') return std::nullopt;
    if (permissions[3] != 'p' && permissions[3] != 's') return std::nullopt;
    MapEntry result;
    result.start = *start;
    result.end = *end;
    result.file_offset = *file_offset;
    result.permissions = static_cast<std::uint8_t>((permissions[0] == 'r' ? 1 : 0) |
                                                   (permissions[1] == 'w' ? 2 : 0) |
                                                   (permissions[2] == 'x' ? 4 : 0));
    result.private_mapping = permissions[3] == 'p';
    std::getline(stream, result.path);
    const auto first = result.path.find_first_not_of(" \t\r");
    result.path = first == std::string::npos ? std::string{} : result.path.substr(first);
    if (!result.path.empty() && result.path.back() == '\r') result.path.pop_back();
    return result;
}

std::vector<MapEntry> parse_maps_text(const std::string& text) {
    std::vector<MapEntry> entries;
    std::istringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        if (const auto entry = parse_maps_line(line)) entries.push_back(*entry);
    }
    return entries;
}

IntegrityObservation compare_mappings(ElfBaseline& baseline,
                                       const std::vector<MapEntry>& maps,
                                       const MemoryReader& reader) {
    IntegrityObservation observation;
    if (!baseline.initialized) {
        observation.code = IntegrityCode::Uninitialized;
        observation.detail = "baseline not initialized";
        return observation;
    }
    if (maps.empty()) {
        observation.code = IntegrityCode::MapsUnavailable;
        observation.detail = "filtered maps vector empty (native code 57)";
        return observation;
    }
    std::string previous_path;
    for (const auto& map : maps) {
        ++observation.mappings_seen;
        if (!previous_path.empty() && previous_path != map.path) {
            observation.code = IntegrityCode::Mismatch;
            observation.local_termination = true;
            observation.detail = "candidate paths differ; native termination call precedes code 12";
            return observation;
        }
        previous_path = map.path;
        if (!map.readable()) continue;
        if (!map.executable()) {
            baseline.fallback_base = map.start;
            continue;
        }
        ++observation.executable_mappings_seen;
        auto base = map.start;
        for (const auto& section : baseline.sections) {
            if (map.start + section.file_offset + section.size > map.end && baseline.fallback_base != 0) {
                base = baseline.fallback_base;
                baseline.fallback_base = 0;
                break;
            }
        }
        observation.selected_base = base;
        for (std::size_t index = 0; index < baseline.sections.size(); ++index) {
            const auto& section = baseline.sections[index];
            const auto address = base + section.file_offset;
            if (!reader || section.size > std::numeric_limits<std::size_t>::max()) {
                ++observation.sections_missing;
                observation.complete = false;
                observation.detail = "host reader unavailable or size unrepresentable; no native verdict";
                return observation;
            }
            const auto bytes = reader(address, static_cast<std::size_t>(section.size));
            if (!bytes || bytes->size() != section.size) {
                ++observation.sections_missing;
                observation.complete = false;
                observation.detail = "host memory read failed; no native verdict";
                return observation;
            }
            ++observation.sections_compared;
            const auto observed = crc32_bswap(*bytes) ^ baseline.mask;
            if (observed != section.digest_xor_mask) {
                observation.code = IntegrityCode::Mismatch;
                observation.stopped_on_mismatch = true;
                observation.detail = "section digest mismatch";
                return observation;
            }
        }
        observation.code = IntegrityCode::Normal;
        observation.detail = "first readable executable mapping matched";
        return observation;
    }
    observation.code = IntegrityCode::Normal;
    observation.detail = "nonempty candidate list exhausted without executable comparison";
    return observation;
}

const char* library_name(Library library) noexcept {
    switch (library) {
    case Library::MediaNdk: return "libmediandk.so";
    case Library::Libc: return "libc.so";
    case Library::LibAndroid: return "libandroid.so";
    case Library::LibArt: return "libart.so";
    }
    return "unknown";
}

EnvironmentCycleResult run_environment_cycle(EnvironmentState& state,
                                             const EnvironmentCycleInput& input) {
    EnvironmentCycleResult result;
    result.precheck_failures = state.precheck_failures;
    result.latched = state.latched;
    if (state.terminated) {
        result.local_termination = true;
        result.latched = state.latched;
        result.reason = "state already terminated";
        return result;
    }
    if (input.precheck_failed) {
        ++state.precheck_failures;
        result.precheck_failures = state.precheck_failures;
        if (state.precheck_failures >= 3) {
            state.terminated = true;
            result.local_termination = true;
            result.reason = "precheck failure threshold reached";
            return result;
        }
        result.latched = state.latched;
        result.reason = "precheck failed; cycle deferred";
        return result;
    }
    state.precheck_failures = 0;
    result.precheck_failures = 0;
    if (state.integrity_counter >= 100) {
      result.ran_integrity = true;
      if (!input.library_codes[0]) {
          result.complete = false;
          result.reason = "missing required MediaNdk result";
          return result;
      }
    // The observed order is the MediaNdk check followed by libc, libandroid,
    // and libart state latches.  A missing result means the branch was not
    // reached, not that it was clean.
      if (input.library_codes[static_cast<std::size_t>(Library::MediaNdk)] &&
          *input.library_codes[static_cast<std::size_t>(Library::MediaNdk)] != 46) {
          state.latched[static_cast<std::size_t>(Library::MediaNdk)] = true;
          state.terminated = true;
          result.local_termination = true;
          result.reason = "libmediandk integrity result != 46";
          result.latched = state.latched;
          return result;
      }
      for (const auto library : {Library::Libc, Library::LibAndroid, Library::LibArt}) {
          const auto index = static_cast<std::size_t>(library);
          if (!state.latched[index] && !input.library_codes[index]) {
              result.complete = false;
              result.latched = state.latched;
              result.reason = "missing required library result";
              return result;
          }
          if (!state.latched[index] && input.library_codes[index] && *input.library_codes[index] == 12) {
              state.latched[index] = true;
          }
        }
      state.integrity_counter = 0;
    }
    if (input.tracer_pid && *input.tracer_pid > 0) {
        state.terminated = true;
        result.tracer_positive = true;
        result.local_termination = true;
        result.latched = state.latched;
        result.reason = "TracerPid > 0";
        return result;
    }
    ++state.integrity_counter;
    result.latched = state.latched;
    result.reason = result.ran_integrity ? "integrity pass complete" : "integrity pass deferred by counter";
    return result;
}

std::array<bool, 3> event21_flags(const EnvironmentState& state) noexcept {
    return {state.latched[3], state.latched[2], state.latched[1]};
}

unsigned event24_value(const EnvironmentState& state) noexcept {
    return state.latched[3] ? 1U : 0U;
}

std::uint32_t input_method_hash(std::vector<std::string> service_names) {
    std::sort(service_names.begin(), service_names.end(), byte_less);
    std::vector<std::uint8_t> bytes;
    std::size_t total = 0;
    for (const auto& name : service_names) total += name.size() + 1;
    bytes.reserve(total);
    for (const auto& name : service_names) {
        bytes.insert(bytes.end(), name.begin(), name.end());
        bytes.push_back(0);
    }
    return crc32_bswap(bytes);
}

InputMethodResult evaluate_input_methods(InputMethodState& state,
                                         const std::vector<std::string>& service_names,
                                         bool jni_environment_available) {
    InputMethodResult result;
    result.previous_hash = state.previous_hash;
    result.initialized = state.initialized;
    if (!jni_environment_available) {
        result.kind = InputMethodResult::Kind::Error;
        result.error_code = 0xbba;
        return result;
    }
    const auto hash = input_method_hash(service_names);
    result.payload = service_names; // preserve getInputMethodList() order
    if (!state.initialized) {
        state.initialized = true;
        state.previous_hash = hash;
        result.kind = InputMethodResult::Kind::Event;
        result.event_type = 34;
    } else if (state.previous_hash != hash) {
        state.previous_hash = hash;
        result.kind = InputMethodResult::Kind::Event;
        result.event_type = 35;
    } else {
        result.kind = InputMethodResult::Kind::Unchanged;
        result.payload.clear();
    }
    result.previous_hash = state.previous_hash;
    result.initialized = state.initialized;
    return result;
}

} // namespace prism::environment

