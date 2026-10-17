#include "android_adapter.hpp"
#ifdef __ANDROID__
#include <algorithm>
#include <dlfcn.h>
#include <fcntl.h>
#include <fstream>
#include <media/NdkMediaDrm.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace prism {
namespace {
struct Library {
    void *h = dlopen("libmediandk.so", RTLD_NOW | RTLD_LOCAL);
    ~Library() {
        if (h)
            dlclose(h);
    }
};
struct Fd {
    int n = -1;
    ~Fd() {
        if (n >= 0)
            close(n);
    }
};
struct LocalFrame {
    JNIEnv *e;
    bool active;
    explicit LocalFrame(JNIEnv *env) : e(env), active(e && e->PushLocalFrame(48) == JNI_OK) {
        if (!active)
            throw std::runtime_error("JNI frame unavailable");
    }
    ~LocalFrame() {
        if (active)
            e->PopLocalFrame(nullptr);
    }
};
void check(JNIEnv *e) {
    if (e->ExceptionCheck()) {
        e->ExceptionClear();
        throw std::runtime_error("JNI operation failed");
    }
}
jclass klass(JNIEnv *e, jobject o) {
    if (!o)
        throw std::runtime_error("null Java object");
    auto c = e->GetObjectClass(o);
    check(e);
    if (!c)
        throw std::runtime_error("class unavailable");
    return c;
}
jmethodID method(JNIEnv *e, jclass c, const char *n, const char *sig) {
    auto id = e->GetMethodID(c, n, sig);
    check(e);
    if (!id)
        throw std::runtime_error("method unavailable");
    return id;
}
jfieldID field(JNIEnv *e, jclass c, const char *n, const char *sig) {
    auto id = e->GetFieldID(c, n, sig);
    check(e);
    if (!id)
        throw std::runtime_error("field unavailable");
    return id;
}
std::string text(JNIEnv *e, jstring s) {
    if (!s)
        return {};
    const char *p = e->GetStringUTFChars(s, nullptr);
    check(e);
    if (!p)
        throw std::runtime_error("UTF chars unavailable");
    try {
        std::string r(p);
        e->ReleaseStringUTFChars(s, p);
        return r;
    } catch (...) {
        e->ReleaseStringUTFChars(s, p);
        throw;
    }
}
std::uint64_t le_at(const Bytes &b, std::size_t p, unsigned n) {
    if (p > b.size() || n > b.size() - p)
        throw std::runtime_error("truncated field");
    std::uint64_t v = 0;
    for (unsigned i = 0; i < n; ++i)
        v |= std::uint64_t(b[p + i]) << (8 * i);
    return v;
}
void put32(Bytes &b, std::size_t p, std::uint32_t x) {
    for (unsigned i = 0; i < 4; ++i)
        b[p + i] = static_cast<std::uint8_t>(x >> (i * 8));
}
std::string file_fingerprint(const std::string &path) {
    if (path.empty())
        return "FAIL_1";
    if (path.compare(0, 10, "/data/app/") != 0)
        return "FAIL_2";
    Fd fd;
    fd.n = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd.n < 0)
        return "FAIL_3";
    struct stat st {};
    if (stat(path.c_str(), &st))
        return "FAIL_4";
    // This unusual MINIMUM size gate is present in the sample; not a typo.
    if (st.st_size < 0x40000000LL)
        return "FAIL_5";
    try {
        auto read = [&](std::uint64_t at, std::size_t n) {
            Bytes b(n);
            std::size_t done = 0;
            while (done < n) {
                auto k = pread(fd.n, b.data() + done, n - done, static_cast<off_t>(at + done));
                if (k <= 0)
                    throw std::runtime_error("short APK read");
                done += static_cast<std::size_t>(k);
            }
            return b;
        };
        auto size = static_cast<std::uint64_t>(st.st_size);
        std::size_t tail_size = static_cast<std::size_t>(std::min<std::uint64_t>(size, 65557));
        auto tail = read(size - tail_size, tail_size);
        std::size_t eocd = std::string::npos;
        for (std::size_t c = 0; c + 22 <= tail.size(); ++c) {
            auto p = tail.size() - 22 - c;
            if (le_at(tail, p, 4) == 0x06054b50 && le_at(tail, p + 20, 2) == c) {
                eocd = p;
                break;
            }
        }
        if (eocd == std::string::npos)
            return "FAIL_6";
        auto cd = le_at(tail, eocd + 16, 4);
        if (cd < 24 || cd > size)
            return "FAIL_6";
        auto footer = read(cd - 24, 24);
        auto len = le_at(footer, 0, 8);
        // Engineering allocation bound, absent from the original unchecked parser.
        if (len < 24 || len > cd - 8 || len > 64 * 1024 * 1024)
            return "FAIL_6";
        auto block = read(cd - len - 8, static_cast<std::size_t>(len + 8));
        auto compact_cd = block.size();
        block.resize(block.size() + 22);
        put32(block, compact_cd, 0x06054b50);
        put32(block, compact_cd + 16, static_cast<std::uint32_t>(compact_cd));
        auto cert = first_v2_certificate(block);
        if (cert.empty())
            return "FAIL_6";
        auto d = sha256(cert);
        return hex(Bytes(d.begin(), d.end()));
    } catch (const std::exception &) {
        return "FAIL_6";
    }
}
} // namespace
Identity collect_android_identity(bool drm_disabled) {
    Bytes raw;
    if (!drm_disabled) {
        Library lib;
        if (lib.h) {
            auto create = reinterpret_cast<decltype(&AMediaDrm_createByUUID)>(
                dlsym(lib.h, "AMediaDrm_createByUUID"));
            auto property = reinterpret_cast<decltype(&AMediaDrm_getPropertyByteArray)>(
                dlsym(lib.h, "AMediaDrm_getPropertyByteArray"));
            auto release =
                reinterpret_cast<decltype(&AMediaDrm_release)>(dlsym(lib.h, "AMediaDrm_release"));
            if (create && property && release) {
                const std::uint8_t uuid[16] = {0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce,
                                               0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed};
                auto drm = create(uuid);
                if (drm) {
                    AMediaDrmByteArray out{};
                    try {
                        if (property(drm, "deviceUniqueId", &out) == AMEDIA_OK && out.ptr &&
                            out.length)
                            raw.assign(out.ptr, out.ptr + out.length);
                    } catch (...) {
                        release(drm);
                        throw;
                    }
                    release(drm); // Engineering fix: release on property failure as well.
                }
            }
        }
    }
    if (!raw.empty())
        return {drm_id(raw), true};
    Fd fd;
    fd.n = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
    if (fd.n < 0)
        return {};
    char buffer[48]{};
    auto n = read(fd.n, buffer, 47);
    if (n <= 0)
        return {};
    return {boot_id(std::string_view(buffer, static_cast<std::size_t>(n))), false};
}
AppInfo collect_android_app(JNIEnv *e, jobject context) {
    if (!e || !context)
        throw std::runtime_error("JNI context unavailable");
    LocalFrame frame(e);
    auto c = klass(e, context);
    auto get_name = method(e, c, "getPackageName", "()Ljava/lang/String;");
    auto name = static_cast<jstring>(e->CallObjectMethod(context, get_name));
    check(e);
    AppInfo out;
    out.package_name = text(e, name);
    auto get_info = method(e, c, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
    auto info = e->CallObjectMethod(context, get_info);
    check(e);
    auto ic = klass(e, info);
    auto source = static_cast<jstring>(
        e->GetObjectField(info, field(e, ic, "sourceDir", "Ljava/lang/String;")));
    check(e);
    out.certificate_digest = file_fingerprint(text(e, source));
    auto get_pm = method(e, c, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    auto pm = e->CallObjectMethod(context, get_pm);
    check(e);
    auto pc = klass(e, pm);
    auto get_pkg =
        method(e, pc, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    auto pkg = e->CallObjectMethod(pm, get_pkg, name, 1);
    check(e);
    auto pkgc = klass(e, pkg);
    auto arr = static_cast<jobjectArray>(
        e->GetObjectField(pkg, field(e, pkgc, "activities", "[Landroid/content/pm/ActivityInfo;")));
    check(e);
    std::vector<std::string> names;
    if (arr) {
        auto count = e->GetArrayLength(arr);
        check(e);
        for (jsize i = 0; i < count; ++i) {
            LocalFrame item(e);
            auto a = e->GetObjectArrayElement(arr, i);
            check(e);
            if (!a)
                continue;
            auto ac = klass(e, a);
            auto v = static_cast<jstring>(
                e->GetObjectField(a, field(e, ac, "name", "Ljava/lang/String;")));
            check(e);
            names.push_back(text(e, v));
        }
    }
    out.activities = activity_info(names);
    return out;
}
Result collect_android_properties(JNIEnv *e, jobject context,
                                  const std::vector<std::optional<std::string>> &args,
                                  const Session &session, bool drm_disabled) {
    // Preserve original validation/ready ordering before JNI metadata collection.
    if (args.size() != 1 || !args[0] || args[0]->substr(0, args[0]->find('\0')).size() < 8)
        return {};
    auto id = collect_android_identity(drm_disabled);
    if (!session.generation)
        return {Result::Kind::Error, 6005, {}};
    if (!e || !context)
        return {Result::Kind::Error, 3002, {}};
    try {
        return client_properties(args, id, collect_android_app(e, context), session, true);
    } catch (const std::exception &) {
        return {Result::Kind::Error, 3002, {}};
    }
}
} // namespace prism
#endif
