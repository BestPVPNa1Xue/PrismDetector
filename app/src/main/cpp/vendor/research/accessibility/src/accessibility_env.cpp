#include "accessibility_env.hpp"

namespace prism::accessibility {

ScopedJniEnvironment::ScopedJniEnvironment(JavaVM* vm) noexcept : vm_(vm) {
    // Null-VM handling is present in the original (0x305cf4..0x305d40).
    if (!vm_) return;
    // Original call 0x305db4: JavaVM table slot 6, version 0x00010006.
    const jint status = vm_->GetEnv(reinterpret_cast<void**>(&env_), JNI_VERSION_1_6);
    if (status == JNI_OK) return;
    // Original checks exactly -2 at 0x305e78; version/error failures do not attach.
    if (status == JNI_EDETACHED && vm_->AttachCurrentThread(&env_, nullptr) == JNI_OK) {
        attached_ = true;
        return;
    }
    // Normalize the output even if a failed VM call wrote a non-null value.
    env_ = nullptr;
}

ScopedJniEnvironment::~ScopedJniEnvironment() noexcept {
    // Original 0x3078cc tests owner bit and VM only, and ignores detach status.
    if (attached_ && vm_) vm_->DetachCurrentThread();
}

} // namespace prism::accessibility
