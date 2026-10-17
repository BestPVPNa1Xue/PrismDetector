#pragma once
#include "detection_chains.hpp"
#include "../../accessibility/src/accessibility_env.hpp"

namespace prism::chains {
// Construct/use/destroy on the same thread. Does not retain JavaVM ownership.
class JniClassBackend final : public ClassBackend {
public:
    explicit JniClassBackend(JavaVM* vm) noexcept : vm_(vm) {}
    bool acquire() noexcept override;
    void release() noexcept override;
    std::uintptr_t find_class(const char*) noexcept override;
    bool exception_pending() noexcept override;
    void clear_exception() noexcept override;
    void delete_local_ref(std::uintptr_t) noexcept override;
private:
    JavaVM* vm_;
    std::optional<accessibility::ScopedJniEnvironment> scope_;
};
ClassResult probe_classes_jni(const JsonValue* config, JavaVM* vm);
} // namespace prism::chains
