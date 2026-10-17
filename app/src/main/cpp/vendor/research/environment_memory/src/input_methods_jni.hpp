#pragma once
#include "environment_memory.hpp"
#include <jni.h>

namespace prism::environment {
struct InputMethodEnumeration {
    std::vector<std::string> service_names;
    bool complete = false;
    bool java_exception_pending = false;
    std::string stage;
};

// Semantic adapter for 0x34adcc. Explicit null/exception guards are host
// improvements, not claims about the original obfuscated JNI wrappers.
// Context/VM are borrowed; exceptions are preserved, never cleared here.
InputMethodEnumeration enumerate_input_methods_from_context(JNIEnv*, jobject context);
InputMethodEnumeration enumerate_input_methods(JavaVM*);
} // namespace prism::environment
