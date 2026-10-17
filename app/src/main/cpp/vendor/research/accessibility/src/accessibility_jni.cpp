#include "accessibility_jni.hpp"

#include <utility>

namespace prism::accessibility {
namespace {

// 0x2e1048/0x2dd338/0x2e8568 store {JNIEnv*, local_ref}; destructors
// 0x2e4dd0/0x2e4ef4/0x2e8d48 release via 0x301194 (JNI slot 23).
template <typename T> class LocalRef {
public:
    LocalRef(JNIEnv* env, T value) : env_(env), value_(value) {}
    ~LocalRef() { if (env_ && value_) env_->DeleteLocalRef(value_); }
    LocalRef(const LocalRef&) = delete;
    LocalRef& operator=(const LocalRef&) = delete;
    T get() const noexcept { return value_; }
private:
    JNIEnv* env_;
    T value_;
};

class UtfChars {
public:
    UtfChars(JNIEnv* env, jstring value, const char* chars)
        : env_(env), value_(value), chars_(chars) {}
    ~UtfChars() { if (chars_) env_->ReleaseStringUTFChars(value_, chars_); }
    UtfChars(const UtfChars&) = delete;
    UtfChars& operator=(const UtfChars&) = delete;
private:
    JNIEnv* env_;
    jstring value_;
    const char* chars_;
};

void record(EnumerationResult& out, JniStage stage, const char* detail, int index = -1) {
    out.diagnostics.push_back({stage, index, detail});
}

// Explicit ExceptionCheck is an adapter improvement. The original normal-path
// wrappers do not test/clear Java exceptions; do not attribute this to ACE.
bool java_ok(JNIEnv* env, EnumerationResult& out, JniStage stage, int index = -1) {
    if (env->ExceptionCheck()) {
        out.java_exception_pending = true;
        record(out, stage, "Java exception remains pending; enumeration stopped", index);
        return false;
    }
    return true;
}

template <typename T>
bool required(JNIEnv* env, T value, EnumerationResult& out, JniStage stage,
              const char* detail, int index = -1) {
    if (!java_ok(env, out, stage, index)) return false;
    if (!value) {
        record(out, stage, "Required JNI object or ID is null; enumeration stopped", index);
        return false;
    }
    record(out, stage, detail, index);
    return true;
}

bool entry(JNIEnv* env, EnumerationResult& out) {
    if (!env) {
        record(out, JniStage::Entry, "JNIEnv is null");
        return false;
    }
    return java_ok(env, out, JniStage::Entry);
}

void enumerate_body(JNIEnv* env, jobject context, EnumerationResult& out) {
    if (!context) {
        record(out, JniStage::Application, "Context is null");
        return;
    }
    // 0x31bac4/0x31bb3c/0x31bb68: FindClass, GetStaticFieldID,
    // GetStaticObjectField; the value is read from Android, not hardcoded.
    LocalRef<jclass> context_class(env, env->FindClass("android/content/Context"));
    if (!required(env, context_class.get(), out, JniStage::ContextClass, "Context class resolved")) return;
    const jfieldID service_field = env->GetStaticFieldID(
        context_class.get(), "ACCESSIBILITY_SERVICE", "Ljava/lang/String;");
    if (!required(env, service_field, out, JniStage::ServiceField, "ACCESSIBILITY_SERVICE field resolved")) return;
    LocalRef<jobject> service_name(env, env->GetStaticObjectField(context_class.get(), service_field));
    if (!required(env, service_name.get(), out, JniStage::ServiceName, "Service name read")) return;
    const jmethodID get_system_service = env->GetMethodID(
        context_class.get(), "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;");
    if (!required(env, get_system_service, out, JniStage::SystemServiceMethod, "getSystemService resolved")) return;
    LocalRef<jobject> manager(env, env->CallObjectMethod(context, get_system_service, service_name.get()));
    if (!required(env, manager.get(), out, JniStage::AccessibilityManager, "AccessibilityManager obtained")) return;

    LocalRef<jclass> manager_class(env, env->FindClass("android/view/accessibility/AccessibilityManager"));
    if (!required(env, manager_class.get(), out, JniStage::ManagerClass, "AccessibilityManager class resolved")) return;
    const jmethodID get_enabled = env->GetMethodID(
        manager_class.get(), "getEnabledAccessibilityServiceList", "(I)Ljava/util/List;");
    if (!required(env, get_enabled, out, JniStage::EnabledListMethod, "Enabled-service list method resolved")) return;
    LocalRef<jclass> list_class(env, env->FindClass("java/util/List"));
    if (!required(env, list_class.get(), out, JniStage::ListClass, "List class resolved")) return;
    const jmethodID list_get = env->GetMethodID(list_class.get(), "get", "(I)Ljava/lang/Object;");
    if (!required(env, list_get, out, JniStage::ListGetMethod, "List.get resolved")) return;
    const jmethodID list_size = env->GetMethodID(list_class.get(), "size", "()I");
    if (!required(env, list_size, out, JniStage::ListSizeMethod, "List.size resolved")) return;
    LocalRef<jclass> info_class(env, env->FindClass("android/accessibilityservice/AccessibilityServiceInfo"));
    if (!required(env, info_class.get(), out, JniStage::ServiceInfoClass, "AccessibilityServiceInfo class resolved")) return;
    const jmethodID get_id = env->GetMethodID(info_class.get(), "getId", "()Ljava/lang/String;");
    if (!required(env, get_id, out, JniStage::ServiceIdMethod, "getId resolved")) return;

    // 0x31c008, W3=0xffffffff: FEEDBACK_ALL_MASK, not a specific feedback type.
    LocalRef<jobject> list(env, env->CallObjectMethod(manager.get(), get_enabled, static_cast<jint>(-1)));
    if (!java_ok(env, out, JniStage::EnabledList)) return;
    if (!list.get()) {
        record(out, JniStage::EnabledList, "Null list maps to an empty observation (original behavior)");
        out.complete = true;
        return;
    }
    record(out, JniStage::EnabledList, "Enabled-service list obtained");
    const jint count = env->CallIntMethod(list.get(), list_size);
    if (!java_ok(env, out, JniStage::ListSize)) return;
    out.diagnostics.push_back({JniStage::ListSize, -1, "List.size=" + std::to_string(count)});
    // Signed comparison at 0x31c35c/0x31c360; size is evaluated once.
    for (jint index = 0; index < count; ++index) {
        LocalRef<jobject> info(env, env->CallObjectMethod(list.get(), list_get, index));
        if (!required(env, info.get(), out, JniStage::ListElement, "List element obtained", index)) return;
        LocalRef<jstring> id(env, static_cast<jstring>(env->CallObjectMethod(info.get(), get_id)));
        if (!java_ok(env, out, JniStage::ServiceId, index)) return;
        // 0x2e5024 produces an empty std::string for a null jstring or a null
        // GetStringUTFChars result. This adapter preserves that non-exception case.
        if (!id.get()) {
            out.ids.emplace_back();
            record(out, JniStage::ServiceId, "Null ID preserved as an empty string", index);
            continue;
        }
        const char* chars = env->GetStringUTFChars(id.get(), nullptr);
        UtfChars release(env, id.get(), chars);
        if (!java_ok(env, out, JniStage::UtfChars, index)) return;
        out.ids.emplace_back(chars ? chars : "");
        record(out, JniStage::UtfChars, chars ? "Copied modified UTF-8 ID" : "Null UTF chars preserved as an empty string", index);
    }
    out.complete = true;
    record(out, JniStage::Complete, "Enumeration complete");
}

} // namespace

const char* jni_stage_name(JniStage stage) noexcept {
    switch (stage) {
#define STAGE_NAME(name) case JniStage::name: return #name
        STAGE_NAME(Entry); STAGE_NAME(ActivityThreadClass); STAGE_NAME(CurrentActivityThreadMethod);
        STAGE_NAME(CurrentActivityThread); STAGE_NAME(ApplicationMethod); STAGE_NAME(Application);
        STAGE_NAME(ContextClass); STAGE_NAME(ServiceField); STAGE_NAME(ServiceName);
        STAGE_NAME(SystemServiceMethod); STAGE_NAME(AccessibilityManager); STAGE_NAME(ManagerClass);
        STAGE_NAME(EnabledListMethod); STAGE_NAME(ListClass); STAGE_NAME(ListGetMethod);
        STAGE_NAME(ListSizeMethod); STAGE_NAME(ServiceInfoClass); STAGE_NAME(ServiceIdMethod);
        STAGE_NAME(EnabledList); STAGE_NAME(ListSize); STAGE_NAME(ListElement);
        STAGE_NAME(ServiceId); STAGE_NAME(UtfChars); STAGE_NAME(Complete);
#undef STAGE_NAME
    }
    return "Unknown";
}

EnumerationResult enumerate_enabled_services(JNIEnv* env) {
    EnumerationResult out;
    if (!entry(env, out)) return out;
    // 0x2db974. Android hidden-API restrictions may reject this original route;
    // no bypass or silent fallback is implemented.
    LocalRef<jclass> thread_class(env, env->FindClass("android/app/ActivityThread"));
    if (!required(env, thread_class.get(), out, JniStage::ActivityThreadClass, "ActivityThread class resolved")) return out;
    const jmethodID current_method = env->GetStaticMethodID(
        thread_class.get(), "currentActivityThread", "()Landroid/app/ActivityThread;");
    if (!required(env, current_method, out, JniStage::CurrentActivityThreadMethod, "currentActivityThread resolved")) return out;
    LocalRef<jobject> thread(env, env->CallStaticObjectMethod(thread_class.get(), current_method));
    if (!required(env, thread.get(), out, JniStage::CurrentActivityThread, "ActivityThread obtained")) return out;
    const jmethodID application_method = env->GetMethodID(
        thread_class.get(), "getApplication", "()Landroid/app/Application;");
    if (!required(env, application_method, out, JniStage::ApplicationMethod, "getApplication resolved")) return out;
    LocalRef<jobject> application(env, env->CallObjectMethod(thread.get(), application_method));
    if (!required(env, application.get(), out, JniStage::Application, "Application obtained")) return out;
    enumerate_body(env, application.get(), out);
    return out;
}

EnumerationResult enumerate_enabled_services_from_context(JNIEnv* env, jobject context) {
    EnumerationResult out;
    if (!entry(env, out)) return out;
    enumerate_body(env, context, out);
    return out;
}

} // namespace prism::accessibility
