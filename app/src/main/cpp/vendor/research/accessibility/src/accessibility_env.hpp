#pragma once

#include <jni.h>

namespace prism::accessibility {

// Reconstructs 0x305790 + 0x3078cc. The scope must be constructed, used and
// destroyed on the same native thread; JavaVM ownership remains with the caller.
class ScopedJniEnvironment final {
public:
    explicit ScopedJniEnvironment(JavaVM* vm) noexcept;
    ~ScopedJniEnvironment() noexcept;
    ScopedJniEnvironment(const ScopedJniEnvironment&) = delete;
    ScopedJniEnvironment& operator=(const ScopedJniEnvironment&) = delete;
    ScopedJniEnvironment(ScopedJniEnvironment&&) = delete;
    ScopedJniEnvironment& operator=(ScopedJniEnvironment&&) = delete;

    JNIEnv* get() const noexcept { return env_; }
    bool attached_by_this_scope() const noexcept { return attached_; }

private:
    JavaVM* vm_ = nullptr; // sample +0
    JNIEnv* env_ = nullptr; // sample +8
    bool attached_ = false; // sample +16, bit 0
};

} // namespace prism::accessibility
