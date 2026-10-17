#pragma once
#include "detection_chains.hpp"

namespace prism::chains::android {
// Android AArch64 only. No initialization side effects, worker threads or APK UI.
ReadObservation read_tracer_status();
ReadObservation read_seccomp_status();
ReadObservation read_cmdline();
MapsObservation read_maps(std::string_view requested, bool exclude_deleted = true);
HandlerInfo query_sigsys();

class NativeProbeBackend final : public ProbeBackend {
public:
    void reset_marker(std::uint32_t) noexcept override;
    bool install_sigsys() noexcept override;
    int open_readonly(const char*) noexcept override;
    std::uint32_t marker() noexcept override;
    void close_fd(int) noexcept override;
    bool restore_sigsys() noexcept override;
private:
    std::array<std::uint64_t, 4> old_action_{};
};
struct CurrentSeccomp {
    SeccompStatus status;
    HandlerInfo handler;
    std::string cmdline, probe_path;
    std::optional<ProbeResult> probe;
    SeccompResult result;
};
// Active probe changes the process-wide SIGSYS handler. The caller must ensure
// exclusive use; the sample has no observed lock. No filter is installed.
CurrentSeccomp inspect_seccomp(std::uint32_t layer = 0, bool active_probe = false);
} // namespace prism::chains::android
