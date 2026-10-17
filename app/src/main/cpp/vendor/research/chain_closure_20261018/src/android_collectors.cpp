#include "android_collectors.hpp"
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error This collector is specific to Android AArch64.
#endif
#include <cstdio>
#include <cstdlib>
#include <cstddef>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>

namespace prism::chains::android {
namespace {
static_assert(SIGSYS == 31 && SA_SIGINFO == 4);
static_assert(SYS_openat == 56 && SYS_rt_sigaction == 134);
static_assert(offsetof(siginfo_t, si_code) == 8);
static_assert(offsetof(siginfo_t, si_syscall) == 24);
static_assert(offsetof(ucontext_t, uc_mcontext) + offsetof(mcontext_t, regs) == 0xb8);
// Linux kernel ABI, not bionic's public sigaction struct with a larger sigset_t.
struct KernelAction {
    std::uint64_t handler, flags, restorer, mask;
};
static_assert(sizeof(KernelAction) == 32 && offsetof(KernelAction, mask) == 24);

long syscall4(long number, long a0 = 0, long a1 = 0, long a2 = 0, long a3 = 0) noexcept {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x8 __asm__("x8") = number;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
                     : "memory", "cc");
    return x0;
}
long ptr(const void* p) noexcept { return reinterpret_cast<long>(p); }
std::string proc(const char* leaf) {
    return "/proc/" + std::to_string(syscall4(SYS_getpid)) + "/" + leaf;
}
ReadObservation read_once(const char* leaf, std::size_t capacity) {
    ReadObservation result;
    const auto name = proc(leaf);
    const long fd = syscall4(SYS_openat, -100, ptr(name.c_str()), 0, 0);
    if (fd < 0) { result.opened = false; return result; }
    // Allocate before read; close the fd if C++ allocation fails.
    struct Close { long fd; ~Close() { syscall4(SYS_close, fd); } } close{fd};
    std::string buffer(capacity, '\0');
    const long size = syscall4(SYS_read, fd, ptr(buffer.data()), static_cast<long>(capacity - 1));
    if (size < 0) result.read_failed = true;
    else { buffer.resize(static_cast<std::size_t>(size)); result.bytes = std::move(buffer); }
    return result;
}
volatile sig_atomic_t probe_marker = 0;
void probe_handler(int, siginfo_t* info, void* context) noexcept {
    if (info && info->si_code == 1 && info->si_syscall == 56)
        probe_marker = static_cast<sig_atomic_t>(kProbeTrapped);
    if (context) static_cast<ucontext_t*>(context)->uc_mcontext.regs[0] = ~std::uint64_t{0};
}
} // namespace

ReadObservation read_tracer_status() { return read_once("status", 2048); }
ReadObservation read_seccomp_status() { return read_once("status", 4096); }
ReadObservation read_cmdline() { return read_once("cmdline", 256); }

MapsObservation read_maps(std::string_view requested, bool exclude) {
    MapsObservation out;
    const auto name = proc("maps");
    const long fd = syscall4(SYS_openat, -100, ptr(name.c_str()), 0, 0);
    if (fd < 0) { out.opened = false; return out; }
    FILE* stream = fdopen(static_cast<int>(fd), "r");
    if (!stream) {
        syscall4(SYS_close, fd);
        out.fdopen_succeeded = false; out.complete = false;
        return out; // explicit guard for the sample's unchecked null FILE*
    }
    struct LineScope {
        FILE* stream; char* data = nullptr;
        ~LineScope() { std::free(data); std::fclose(stream); }
    } scope{stream};
    std::size_t capacity = 0;
    for (;;) {
        const auto length = getline(&scope.data, &capacity, stream);
        if (length < 0) break; // original does not distinguish EOF and ferror
        auto line = filter_maps(std::string_view(scope.data, static_cast<std::size_t>(length)),
                                requested, exclude);
        out.discarded += line.discarded;
        for (auto& entry : line.entries) out.entries.push_back(std::move(entry));
    }
    return out;
}

HandlerInfo query_sigsys() {
    KernelAction action{};
    if (syscall4(SYS_rt_sigaction, SIGSYS, 0, ptr(&action), 8) < 0)
        return locate_sigsys_handler(false, 0, {});
    // Inactive handlers do not cause a maps read in the sample.
    const auto maps = action.handler > 1 ? read_maps("", true) : MapsObservation{};
    return locate_sigsys_handler(true, action.handler, maps);
}
void NativeProbeBackend::reset_marker(std::uint32_t value) noexcept {
    probe_marker = static_cast<sig_atomic_t>(value);
}
bool NativeProbeBackend::install_sigsys() noexcept {
    const KernelAction action{reinterpret_cast<std::uint64_t>(&probe_handler), 4, 0, 0};
    return syscall4(SYS_rt_sigaction, SIGSYS, ptr(&action), ptr(old_action_.data()), 8) >= 0;
}
int NativeProbeBackend::open_readonly(const char* name) noexcept {
    return static_cast<int>(syscall4(SYS_openat, -100, ptr(name), 0, 0));
}
std::uint32_t NativeProbeBackend::marker() noexcept { return static_cast<std::uint32_t>(probe_marker); }
void NativeProbeBackend::close_fd(int fd) noexcept { syscall4(SYS_close, fd); }
bool NativeProbeBackend::restore_sigsys() noexcept {
    return syscall4(SYS_rt_sigaction, SIGSYS, ptr(old_action_.data()), 0, 8) >= 0;
}
CurrentSeccomp inspect_seccomp(std::uint32_t layer, bool active_probe) {
    CurrentSeccomp out;
    out.status = seccomp_status(read_seccomp_status());
    out.handler = query_sigsys();
    out.cmdline = cmdline_first(read_cmdline());
    out.result = evaluate_seccomp(out.status, out.handler, layer, out.cmdline);
    if (out.result.probe_required && active_probe) {
        const auto maps = read_maps("/base.apk", true);
        if (!maps.complete) return out;
        out.probe_path = select_probe_path(maps, out.cmdline);
        NativeProbeBackend backend;
        out.probe = run_probe(out.probe_path, backend);
        out.result = evaluate_seccomp(out.status, out.handler, layer, out.cmdline, out.probe->changed);
    }
    return out;
}
} // namespace prism::chains::android
