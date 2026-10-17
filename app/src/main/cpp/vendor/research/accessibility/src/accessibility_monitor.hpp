#pragma once
#include "accessibility_core.hpp"
#include "accessibility_jni.hpp"
#include "accessibility_env.hpp"
#include <optional>

namespace prism::accessibility {
struct Observation {
    EnumerationResult enumeration;
    // Absent only when the defensive adapter stopped on incomplete JNI data.
    // This separate state is an integration API, not an invented ACE event.
    std::optional<Result> result;
};

// Use on an attached Android thread. nullptr env returns original error 0xbba.
// The caller owns State and controls the invocation schedule.
Observation observe(State& state, JNIEnv* env);
Observation observe_from_context(State& state, JNIEnv* env, jobject context);
// Includes the recovered GetEnv/AttachCurrentThread/DetachCurrentThread scope.
Observation observe_vm(State& state, JavaVM* vm);
} // namespace prism::accessibility
