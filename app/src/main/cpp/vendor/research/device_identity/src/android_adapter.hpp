#pragma once
#include "identity.hpp"
#ifdef __ANDROID__
#include <jni.h>
namespace prism {
Identity collect_android_identity(bool drm_disabled = false);
AppInfo collect_android_app(JNIEnv *env, jobject application_context);
// Caller supplies its existing attached JNIEnv. No thread is spawned or attached.
Result collect_android_properties(JNIEnv *env, jobject context,
                                  const std::vector<std::optional<std::string>> &args,
                                  const Session &session, bool drm_disabled = false);
} // namespace prism
#endif
