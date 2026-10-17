#include "accessibility_monitor.hpp"

namespace prism::accessibility {
namespace {
Observation finish(State& state, bool was_initialized, EnumerationResult enumeration) {
    Observation out;
    out.enumeration = std::move(enumeration);
    if (out.enumeration.complete)
        out.result = evaluate_snapshot(state, was_initialized, out.enumeration.ids);
    return out;
}
Observation no_env(State& state, bool was_initialized) {
    Observation out;
    out.enumeration.diagnostics.push_back({JniStage::Entry, -1, "JNIEnv unavailable (original result error 0xbba)"});
    out.result = evaluate_snapshot(state, was_initialized, {}, false);
    return out;
}
}

Observation observe(State& state, JNIEnv* env) {
    const bool was_initialized = state.initialized.load(std::memory_order_seq_cst);
    if (!env) return no_env(state, was_initialized);
    return finish(state, was_initialized, enumerate_enabled_services(env));
}

Observation observe_from_context(State& state, JNIEnv* env, jobject context) {
    const bool was_initialized = state.initialized.load(std::memory_order_seq_cst);
    if (!env) return no_env(state, was_initialized);
    return finish(state, was_initialized, enumerate_enabled_services_from_context(env, context));
}

Observation observe_vm(State& state, JavaVM* vm) {
    const bool was_initialized = state.initialized.load(std::memory_order_seq_cst);
    EnumerationResult enumeration;
    {
        ScopedJniEnvironment environment(vm);
        if (!environment.get()) return no_env(state, was_initialized);
        enumeration = enumerate_enabled_services(environment.get());
    } // 0x6cf354: release the JNI scope before JSON/hash/state processing.
    return finish(state, was_initialized, std::move(enumeration));
}
} // namespace prism::accessibility
