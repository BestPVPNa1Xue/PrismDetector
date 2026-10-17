#include "input_methods_jni.hpp"
#include "../../accessibility/src/accessibility_env.hpp"

namespace prism::environment {
namespace {
template <typename T> class LocalRef {
public:
    LocalRef(JNIEnv* env, T value) : env_(env), value_(value) {}
    ~LocalRef() { if (value_) env_->DeleteLocalRef(value_); }
    LocalRef(const LocalRef&) = delete;
    LocalRef& operator=(const LocalRef&) = delete;
    T get() const noexcept { return value_; }
private:
    JNIEnv* env_;
    T value_;
};
class UtfChars {
public:
    UtfChars(JNIEnv* env, jstring s) : env_(env), s_(s), p_(env->GetStringUTFChars(s, nullptr)) {}
    ~UtfChars() { if (p_) env_->ReleaseStringUTFChars(s_, p_); }
    UtfChars(const UtfChars&) = delete;
    UtfChars& operator=(const UtfChars&) = delete;
    const char* get() const noexcept { return p_; }
private:
    JNIEnv* env_;
    jstring s_;
    const char* p_;
};
bool ok(JNIEnv* env, InputMethodEnumeration& out, const char* stage) {
    out.stage = stage;
    out.java_exception_pending = env->ExceptionCheck();
    return !out.java_exception_pending;
}
template <typename T> bool required(JNIEnv* env, T p, InputMethodEnumeration& out, const char* stage) {
    return ok(env, out, stage) && p != nullptr;
}
} // namespace

InputMethodEnumeration enumerate_input_methods_from_context(JNIEnv* env, jobject context) {
    InputMethodEnumeration out;
    out.stage = "entry";
    if (!env || !ok(env, out, "entry") || !context) return out;
    LocalRef<jclass> context_class(env, env->FindClass("android/content/Context"));
    if (!required(env, context_class.get(), out, "Context")) return out;
    const auto field = env->GetStaticFieldID(context_class.get(), "INPUT_METHOD_SERVICE", "Ljava/lang/String;");
    if (!required(env, field, out, "INPUT_METHOD_SERVICE field")) return out;
    LocalRef<jobject> name(env, env->GetStaticObjectField(context_class.get(), field));
    if (!required(env, name.get(), out, "INPUT_METHOD_SERVICE value")) return out;
    const auto service = env->GetMethodID(context_class.get(), "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;");
    if (!required(env, service, out, "getSystemService method")) return out;
    LocalRef<jobject> manager(env, env->CallObjectMethod(context, service, name.get()));
    if (!required(env, manager.get(), out, "InputMethodManager object")) return out;
    LocalRef<jclass> manager_class(env, env->FindClass("android/view/inputmethod/InputMethodManager"));
    if (!required(env, manager_class.get(), out, "InputMethodManager class")) return out;
    const auto get_list = env->GetMethodID(manager_class.get(), "getInputMethodList", "()Ljava/util/List;");
    if (!required(env, get_list, out, "getInputMethodList method")) return out;
    LocalRef<jclass> list_class(env, env->FindClass("java/util/List"));
    if (!required(env, list_class.get(), out, "List class")) return out;
    const auto get = env->GetMethodID(list_class.get(), "get", "(I)Ljava/lang/Object;");
    if (!required(env, get, out, "List.get method")) return out;
    const auto size = env->GetMethodID(list_class.get(), "size", "()I");
    if (!required(env, size, out, "List.size method")) return out;
    LocalRef<jclass> info_class(env, env->FindClass("android/view/inputmethod/InputMethodInfo"));
    if (!required(env, info_class.get(), out, "InputMethodInfo class")) return out;
    const auto get_name = env->GetMethodID(info_class.get(), "getServiceName", "()Ljava/lang/String;");
    if (!required(env, get_name, out, "getServiceName method")) return out;
    LocalRef<jobject> list(env, env->CallObjectMethod(manager.get(), get_list));
    if (!ok(env, out, "getInputMethodList result")) return out;
    if (!list.get()) { out.complete = true; return out; }
    const jint count = env->CallIntMethod(list.get(), size);
    if (!ok(env, out, "List.size result")) return out;
    for (jint i = 0; i < count; ++i) {
        LocalRef<jobject> info(env, env->CallObjectMethod(list.get(), get, i));
        if (!required(env, info.get(), out, "List.get result")) return out;
        LocalRef<jstring> value(env, static_cast<jstring>(env->CallObjectMethod(info.get(), get_name)));
        if (!ok(env, out, "getServiceName result")) return out;
        if (!value.get()) { out.service_names.emplace_back(); continue; }
        UtfChars chars(env, value.get());
        if (!ok(env, out, "GetStringUTFChars")) return out;
        out.service_names.emplace_back(chars.get() ? chars.get() : "");
    }
    out.complete = true;
    out.stage = "complete";
    return out;
}

InputMethodEnumeration enumerate_input_methods(JavaVM* vm) {
    prism::accessibility::ScopedJniEnvironment scope(vm);
    auto* env = scope.get();
    InputMethodEnumeration out;
    out.stage = "JNI environment";
    if (!env || !ok(env, out, "entry")) return out;
    LocalRef<jclass> cls(env, env->FindClass("android/app/ActivityThread"));
    if (!required(env, cls.get(), out, "ActivityThread class")) return out;
    const auto current = env->GetStaticMethodID(cls.get(), "currentActivityThread", "()Landroid/app/ActivityThread;");
    if (!required(env, current, out, "currentActivityThread method")) return out;
    LocalRef<jobject> thread(env, env->CallStaticObjectMethod(cls.get(), current));
    if (!required(env, thread.get(), out, "currentActivityThread result")) return out;
    const auto app = env->GetMethodID(cls.get(), "getApplication", "()Landroid/app/Application;");
    if (!required(env, app, out, "getApplication method")) return out;
    LocalRef<jobject> context(env, env->CallObjectMethod(thread.get(), app));
    if (!required(env, context.get(), out, "getApplication result")) return out;
    return enumerate_input_methods_from_context(env, context.get());
}
} // namespace prism::environment
