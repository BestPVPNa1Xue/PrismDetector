#pragma once

#include <jni.h>
#include <string>
#include <vector>

namespace prism::accessibility {

enum class JniStage {
    Entry, ActivityThreadClass, CurrentActivityThreadMethod, CurrentActivityThread,
    ApplicationMethod, Application, ContextClass, ServiceField, ServiceName,
    SystemServiceMethod, AccessibilityManager, ManagerClass, EnabledListMethod,
    ListClass, ListGetMethod, ListSizeMethod, ServiceInfoClass, ServiceIdMethod,
    EnabledList, ListSize, ListElement, ServiceId, UtfChars, Complete
};

struct JniDiagnostic {
    JniStage stage;
    int index = -1;
    std::string detail;
};

struct EnumerationResult {
    // API list order, duplicates and empty IDs are preserved.
    std::vector<std::string> ids;
    std::vector<JniDiagnostic> diagnostics;
    // false means ids is only a partial observation; do not feed it into a
    // change detector as a complete snapshot.
    bool complete = false;
    bool java_exception_pending = false;
};

const char* jni_stage_name(JniStage stage) noexcept;

// Caller supplies the JNIEnv for the current attached thread. This function
// neither attaches a thread nor clears pending Java exceptions. It follows
// 0x2db974: ActivityThread.currentActivityThread().getApplication().
EnumerationResult enumerate_enabled_services(JNIEnv* env);

// Same enumeration body (0x31b73c), with an explicitly supplied live Context.
// The Context is borrowed; the caller owns its reference.
EnumerationResult enumerate_enabled_services_from_context(JNIEnv* env, jobject context);

} // namespace prism::accessibility
