#include "classes_jni.hpp"

namespace prism::chains {
bool JniClassBackend::acquire() noexcept {
    if (!scope_) scope_.emplace(vm_);
    return scope_->get() != nullptr;
}
void JniClassBackend::release() noexcept { scope_.reset(); }
std::uintptr_t JniClassBackend::find_class(const char* name) noexcept {
    return reinterpret_cast<std::uintptr_t>(scope_->get()->FindClass(name));
}
bool JniClassBackend::exception_pending() noexcept {
    return scope_->get()->ExceptionCheck() != JNI_FALSE;
}
void JniClassBackend::clear_exception() noexcept { scope_->get()->ExceptionClear(); }
void JniClassBackend::delete_local_ref(std::uintptr_t ref) noexcept {
    scope_->get()->DeleteLocalRef(reinterpret_cast<jobject>(ref));
}
ClassResult probe_classes_jni(const JsonValue* config, JavaVM* vm) {
    JniClassBackend backend(vm);
    return probe_classes(config, backend);
}
} // namespace prism::chains
