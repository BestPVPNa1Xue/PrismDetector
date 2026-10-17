#include "detection_chains.hpp"
#include <algorithm>
#include <cstdio>
#include <cstring>

namespace prism::chains {
namespace {
std::string_view ctext(std::string_view s) noexcept {
    const auto n = s.find('\0');
    return n == s.npos ? s : s.substr(0, n);
}
bool whitespace(unsigned char c) noexcept { return c == 32 || (c >= 9 && c <= 13); }
bool starts(std::string_view s, std::string_view p) noexcept {
    return s.size() >= p.size() && s.substr(0, p.size()) == p;
}
std::int32_t signed32(std::uint32_t bits) noexcept {
    std::int32_t result;
    std::memcpy(&result, &bits, sizeof result);
    return result;
}
std::string_view read_text(const ReadObservation& r, std::size_t maximum) noexcept {
    return ctext(std::string_view(r.bytes).substr(0, maximum));
}
std::int32_t field(std::string_view s, std::string_view marker) noexcept {
    const auto pos = s.find(marker);
    if (pos == s.npos) return -1;
    s.remove_prefix(pos + marker.size());
    while (!s.empty() && (s.front() == ':' || s.front() == ' ' || s.front() == '\t'))
        s.remove_prefix(1);
    return atoi32(s);
}
} // namespace

std::int32_t atoi32(std::string_view s) noexcept {
    s = ctext(s);
    while (!s.empty() && whitespace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
    bool negative = false;
    if (!s.empty() && (s.front() == '-' || s.front() == '+')) {
        negative = s.front() == '-';
        s.remove_prefix(1);
    }
    std::uint32_t accumulator = 0;
    for (const auto c : s) {
        if (c < '0' || c > '9') break;
        accumulator = accumulator * 10u - static_cast<unsigned>(c - '0');
    }
    return signed32(negative ? accumulator : 0u - accumulator);
}

std::int32_t tracer_pid(const ReadObservation& r) noexcept {
    if (!r.opened || r.read_failed || r.bytes.empty()) return -2;
    auto s = read_text(r, 2047);
    constexpr std::string_view marker = "TracerPid:";
    const auto p = s.find(marker);
    if (p == s.npos) return -1;
    s.remove_prefix(p + marker.size());
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    return atoi32(s);
}

std::string cmdline_first(const ReadObservation& r) {
    if (!r.opened || r.read_failed) return {};
    return std::string(read_text(r, 255));
}

SeccompStatus seccomp_status(const ReadObservation& r) noexcept {
    SeccompStatus out;
    if (!r.opened) { out.error = 0xfa1; return out; }
    if (r.read_failed || r.bytes.empty()) { out.error = 0xfa2; return out; }
    const auto s = read_text(r, 4095);
    out.mode = field(s, "Seccomp:");
    out.filters = field(s, "Seccomp_filters:");
    out.no_new_privs = field(s, "NoNewPrivs:") == 1;
    return out;
}

std::optional<MapEntry> parse_native_maps_line(std::string_view line) {
    const std::string input(ctext(line));
    unsigned long long begin = 0, end = 0, offset = 0, inode = 0;
    unsigned major = 0, minor = 0;
    char perms[5]{};
    int consumed = -1;
    // long is 32-bit on Windows; ll is the portable host spelling for the
    // sample's AArch64 unsigned long fields. %n and %*s don't count assignments.
    const int count = std::sscanf(input.c_str(), "%llx-%llx %4s %llx %x:%x %llu %n%*s",
                                  &begin, &end, perms, &offset, &major, &minor, &inode,
                                  &consumed);
    if (count != 7 || consumed < 0 || static_cast<std::size_t>(consumed) > input.size())
        return {};
    auto p = static_cast<std::size_t>(consumed);
    while (p < input.size() && whitespace(static_cast<unsigned char>(input[p]))) ++p;
    MapEntry out;
    out.start = begin; out.end = end; out.file_offset = offset;
    out.permissions = static_cast<std::uint8_t>((perms[0] == 'r' ? 1 : 0) |
                       (perms[1] == 'w' ? 2 : 0) | (perms[2] == 'x' ? 4 : 0));
    out.private_mapping = perms[3] == 'p';
    out.path = input.substr(p);
    return out;
}

MapsObservation filter_maps(std::string_view text, std::string_view requested,
                            bool exclude, bool opened, bool fdopen_ok) {
    MapsObservation out;
    out.opened = opened; out.fdopen_succeeded = fdopen_ok;
    if (!opened) return out;
    if (!fdopen_ok) { out.complete = false; return out; }
    requested = ctext(requested);
    while (!text.empty()) {
        const auto nl = text.find('\n');
        const auto length = nl == text.npos ? text.size() : nl + 1;
        auto line = text.substr(0, length);
        text.remove_prefix(length);
        const auto original = ctext(line);
        if (original.find(requested) == original.npos ||
            (exclude && original.find("(deleted)") != original.npos)) {
            ++out.discarded;
            continue;
        }
        // 0x5cca68 truncates the last byte regardless of whether it is a LF.
        line.remove_suffix(1);
        if (auto entry = parse_native_maps_line(line)) out.entries.push_back(std::move(*entry));
        else ++out.discarded;
    }
    return out;
}

HandlerInfo locate_sigsys_handler(bool ok, std::uint64_t address,
                                 const MapsObservation& maps) {
    HandlerInfo out;
    if (!ok) { out.error = 0x1389; return out; }
    out.address = address;
    out.active = address != 0 && address != 1;
    if (!out.active) return out;
    if (!maps.complete) { out.complete = false; return out; }
    for (const auto& m : maps.entries) {
        if (m.start <= address && address < m.end) {
            out.path = m.path; out.start = m.start; out.end = m.end;
            break;
        }
    }
    return out;
}

std::string package_from_install_path(std::string_view path) {
    path = ctext(path);
    constexpr std::string_view prefix = "/data/app/";
    if (!starts(path, prefix) || path.size() <= prefix.size()) return {};
    path.remove_prefix(prefix.size());
    if (starts(path, "~~")) {
        const auto slash = path.find('/');
        if (slash == path.npos) return {};
        path.remove_prefix(slash + 1);
    }
    const auto dash = path.find('-');
    if (dash == path.npos || dash == 0) return {};
    return std::string(path.substr(0, dash));
}

std::string select_probe_path(const MapsObservation& maps, std::string_view command) {
    command = ctext(command);
    for (const auto& m : maps.entries) {
        if (!starts(ctext(m.path), "/data/app/")) continue;
        if (!command.empty() && package_from_install_path(m.path) != command) continue;
        return std::string(ctext(m.path));
    }
    return "/dev/null";
}

SignalEffect sigsys_handler_effect(std::uint32_t marker, const SignalObservation& s) noexcept {
    if (s.siginfo_present && s.code == 1 && s.syscall_number == 56) marker = kProbeTrapped;
    return {marker, s.context_present ? std::optional<std::uint64_t>(~std::uint64_t{0}) : std::nullopt};
}

ProbeResult run_probe(std::string_view path, ProbeBackend& backend) {
    const std::string pathname(ctext(path)); // allocate before installing a handler
    ProbeResult out;
    backend.reset_marker(kProbeInitial);
    out.installed = backend.install_sigsys();
    out.completed = true; // installation failure is the original false result
    if (!out.installed) return out;
    out.fd = backend.open_readonly(pathname.c_str());
    out.changed = backend.marker() != kProbeInitial;
    if (out.fd >= 0) backend.close_fd(out.fd);
    out.restore_attempted = true;
    out.restore_succeeded = backend.restore_sigsys();
    // Original return value ignores failure of restore; retain both observations.
    return out;
}

ReasonResult handler_reason(const HandlerInfo& h, std::int32_t count,
                            std::uint32_t layer, std::string_view cmd,
                            std::optional<bool> probe) {
    if (!h.complete || h.error) return {};
    if (!h.active) return {0, false};
    const auto path = ctext(h.path);
    if (path.empty()) return {11, false};
    if (!starts(path, "/data/")) return {2, false};
    const std::string name(ctext(cmd));
    if (!starts(path, "/data/app/") && !starts(path, "/data/data/" + name + "/") &&
        !starts(path, "/data/user/0/" + name + "/")) return {12, false};
    if (count >= 0 && count <= signed32(layer + 1u)) return {3, false};
    if (!probe) return {std::nullopt, true};
    return {static_cast<std::uint8_t>(*probe ? 10 : 4), true};
}

SeccompResult evaluate_seccomp(const SeccompStatus& status, const HandlerInfo& handler,
                               std::uint32_t layer, std::string_view cmd,
                               std::optional<bool> probe) {
    SeccompResult out;
    const auto count = status.error ? -1 : status.filters;
    const auto reason = handler_reason(handler, count, layer, cmd, probe);
    out.probe_required = reason.probe_required;
    out.complete = handler.complete && (handler.error != 0 || reason.reason.has_value());
    prism_filter_policy(status.error != 0, count, layer, handler.error != 0,
                        reason.reason.value_or(0), &out.flags);
    // No probe is not equivalent to reason4, nor to a clean final result.
    if (!out.complete) out.flags.acceptable = 0;
    if (out.flags.suspicious_handler) out.handler_source = handler.path;
    if (out.complete && layer == 0 && !out.flags.acceptable) out.diagnostic = 5006;
    return out;
}

environment::IntegrityObservation compare_library(environment::ElfBaseline& baseline,
    std::string_view text, environment::Library library, const environment::MemoryReader& reader,
    bool opened, bool fdopen_ok) {
    if (!baseline.initialized) return environment::compare_mappings(baseline, {}, reader);
    const auto maps = filter_maps(text, environment::library_name(library), true, opened, fdopen_ok);
    if (!maps.complete) {
        environment::IntegrityObservation out;
        out.complete = false;
        out.detail = "fdopen failed; original lacks a null-stream guard";
        return out;
    }
    return environment::compare_mappings(baseline, maps.entries, reader);
}

Event20Result event20_counts(Event20State& state, const std::vector<MapEntry>& entries,
                             bool ok, std::vector<std::string> diagnostics) {
    state.delta20 = 0;
    if (ok) {
        std::uint32_t empty = 0, named_anon = 0;
        for (const auto& m : entries) {
            if (!m.executable() || m.end - m.start <= 0x5000u) continue;
            const auto p = ctext(m.path);
            if (p.empty()) ++empty;
            else if (p.find("/dev/zero (deleted)") != p.npos || starts(p, "[anon:")) ++named_anon;
        }
        state.delta20 = named_anon - state.baseline16;
        state.empty24 = empty;
    }
    return {signed32(state.delta20), signed32(state.empty24), std::move(diagnostics)};
}

std::optional<RequestView> request_view(const JsonValue& root) noexcept {
    if ((root.type & 255u) != 32 || root.children.size() < 2 ||
        (root.children[0].type & 255u) != 8 || (root.children[1].type & 255u) != 32) return {};
    return RequestView{static_cast<std::uint8_t>(root.children[0].valueint), &root.children[1]};
}
bool class_config_enabled(const JsonValue* config) noexcept {
    return config && (config->type & 255u) == 32 && !config->children.empty();
}
ClassResult probe_classes(const JsonValue* config, ClassBackend& backend) {
    ClassResult out;
    if (!class_config_enabled(config)) { out.event = 22; return out; }
    const bool acquired = backend.acquire();
    // release also runs on acquisition failure, like the original scope destructor.
    struct Release { ClassBackend& b; ~Release() { b.release(); } } release{backend};
    if (!acquired) { out.diagnostic = 0xbba; return out; }
    for (const auto& item : config->children) {
        if ((item.type & 255u) != 16) { out.stopped_at_non_string = true; break; }
        if (!item.valuestring) { out.complete = false; return out; }
        ++out.queried;
        const auto ref = backend.find_class(item.valuestring->c_str());
        if (backend.exception_pending()) {
            backend.clear_exception(); ++out.cleared;
            continue; // original does not delete a nonzero ref on this branch
        }
        if (ref) {
            backend.delete_local_ref(ref); ++out.deleted;
            out.visible.emplace_back(ctext(*item.valuestring));
        }
    }
    out.event = 22;
    return out;
}
} // namespace prism::chains
