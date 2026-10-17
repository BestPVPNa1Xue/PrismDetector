#pragma once

#include "../../environment_memory/src/environment_memory.hpp"
#include "../../src/observed_models.h"
#include <functional>
#include <optional>
#include <string_view>

// Semantic reconstruction, not the sample's C++ ABI. Sources: CHAIN_NOTES.zh-CN.md.
namespace prism::chains {
using environment::MapEntry;

struct ReadObservation {
    bool opened = true;
    bool read_failed = false;
    std::string bytes; // bytes returned, not the entire file when a read was short
};
std::int32_t atoi32(std::string_view text) noexcept;
std::int32_t tracer_pid(const ReadObservation& status) noexcept;
std::string cmdline_first(const ReadObservation& cmdline);

struct SeccompStatus {
    std::int32_t mode = -1;
    std::int32_t filters = -1;
    bool no_new_privs = false;
    std::uint32_t error = 0; // 0xfa1 open, 0xfa2 read/EOF
};
SeccompStatus seccomp_status(const ReadObservation& status) noexcept;

struct MapsObservation {
    bool complete = true; // host-only guard, not a native verdict
    bool opened = true;
    bool fdopen_succeeded = true;
    std::vector<MapEntry> entries;
    std::size_t discarded = 0;
};
// Format parser for representable Linux maps fields; preserves unusual permissions
// and inverted ranges accepted by sscanf. No normalization of the pathname.
std::optional<MapEntry> parse_native_maps_line(std::string_view line);
MapsObservation filter_maps(std::string_view text, std::string_view requested,
                            bool exclude_deleted = true, bool opened = true,
                            bool fdopen_succeeded = true);

struct HandlerInfo {
    bool complete = true;
    std::uint32_t error = 0; // 0x1389 if rt_sigaction query failed
    std::uint64_t address = 0;
    bool active = false;
    std::string path;
    std::uint64_t start = 0, end = 0;
};
HandlerInfo locate_sigsys_handler(bool query_succeeded, std::uint64_t address,
                                 const MapsObservation& maps);
std::string package_from_install_path(std::string_view path);
std::string select_probe_path(const MapsObservation& base_apk_maps,
                              std::string_view cmdline);

inline constexpr std::uint32_t kProbeInitial = 0x6ab22396u;
inline constexpr std::uint32_t kProbeTrapped = 0x6ab22397u;
struct SignalObservation {
    bool siginfo_present = false;
    std::int32_t code = 0;
    std::int32_t syscall_number = 0;
    bool context_present = false;
};
struct SignalEffect {
    std::uint32_t marker;
    std::optional<std::uint64_t> x0;
};
SignalEffect sigsys_handler_effect(std::uint32_t marker,
                                   const SignalObservation& signal) noexcept;

// Backend is deliberately explicit. Core tests use a synthetic backend and never
// install process signal handlers. Implementations must not throw from methods.
class ProbeBackend {
public:
    virtual ~ProbeBackend() = default;
    virtual void reset_marker(std::uint32_t) noexcept = 0;
    virtual bool install_sigsys() noexcept = 0; // save old action; SA_SIGINFO, empty mask
    virtual int open_readonly(const char*) noexcept = 0;
    virtual std::uint32_t marker() noexcept = 0;
    virtual void close_fd(int) noexcept = 0;
    virtual bool restore_sigsys() noexcept = 0;
};
struct ProbeResult {
    bool completed = false;
    bool installed = false;
    bool changed = false;
    bool restore_attempted = false;
    bool restore_succeeded = false;
    int fd = -1;
};
ProbeResult run_probe(std::string_view path, ProbeBackend& backend);

struct ReasonResult {
    std::optional<std::uint8_t> reason;
    bool probe_required = false;
};
ReasonResult handler_reason(const HandlerInfo& handler, std::int32_t filters,
                            std::uint32_t layer, std::string_view cmdline,
                            std::optional<bool> active_probe_result = {});
struct SeccompResult {
    bool complete = true;
    PrismFilterFlags flags{};
    bool probe_required = false;
    std::string handler_source;
    std::uint32_t diagnostic = 0; // 5006 in the layer=0 consumer, when unacceptable
};
SeccompResult evaluate_seccomp(const SeccompStatus& status, const HandlerInfo& handler,
                               std::uint32_t layer, std::string_view cmdline,
                               std::optional<bool> active_probe_result = {});

environment::IntegrityObservation compare_library(
    environment::ElfBaseline& baseline, std::string_view maps_text,
    environment::Library library, const environment::MemoryReader& reader,
    bool opened = true, bool fdopen_succeeded = true);

// Event20 counter consumer. Its independent raw numeric scanner is NOT replaced
// by the four-library parser. Supply its parsed entries at this boundary.
struct Event20State {
    std::uint32_t baseline16 = 0; // constructor default; later provenance unresolved
    std::uint32_t delta20 = 0;
    std::uint32_t empty24 = 0;
};
struct Event20Result {
    std::int32_t delta = 0, empty = 0;
    std::vector<std::string> diagnostics; // injected original diagnostic strings
};
Event20Result event20_counts(Event20State& state, const std::vector<MapEntry>& entries,
                             bool acquisition_succeeded,
                             std::vector<std::string> diagnostics = {});

// cJSON semantic value, with low-byte type and nullable valuestring preserved.
// Text JSON parsing, ownership ABI and session decryption remain adapters.
struct JsonValue {
    std::uint32_t type = 0; // number=8, string=16, array=32
    std::int32_t valueint = 0;
    std::optional<std::string> valuestring;
    std::vector<JsonValue> children;
};
struct RequestView {
    std::uint8_t task_id = 0;
    const JsonValue* config = nullptr;
};
std::optional<RequestView> request_view(const JsonValue& root) noexcept;
bool class_config_enabled(const JsonValue* config) noexcept;
class ClassBackend {
public:
    virtual ~ClassBackend() = default;
    virtual bool acquire() noexcept = 0;
    virtual void release() noexcept = 0;
    virtual std::uintptr_t find_class(const char*) noexcept = 0;
    virtual bool exception_pending() noexcept = 0;
    virtual void clear_exception() noexcept = 0;
    virtual void delete_local_ref(std::uintptr_t) noexcept = 0;
};
struct ClassResult {
    bool complete = true;
    std::optional<std::uint8_t> event;
    std::uint32_t diagnostic = 0;
    std::size_t queried = 0, cleared = 0, deleted = 0;
    bool stopped_at_non_string = false;
    std::vector<std::string> visible;
};
ClassResult probe_classes(const JsonValue* config, ClassBackend& backend);
} // namespace prism::chains
