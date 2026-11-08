#include "thunks_android.h"
#include "thunk_manager.h"
#include "thunk_types.h"
#include "dynarmic_host.h"
#include "jni_fake_env.h"

#include <EGL/egl.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <android/native_window.h>
#include <android/native_window_jni.h>
#include <android/log.h>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <vector>

#define LOG_TAG "Arm32Bridge_Android"
#if ARM32_BRIDGE_ENABLE_LOGGING
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#endif

namespace {
template <typename T>
class HandleTable {
public:
    uint32_t Add(T value) {
        if (!value) return 0;
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [handle, existing] : values_) if (existing == value) return handle;
        const uint32_t handle = next_++;
        values_[handle] = value;
        return handle;
    }
    T Get(uint32_t handle) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = values_.find(handle);
        return it == values_.end() ? T{} : it->second;
    }
    void Remove(uint32_t handle) {
        std::lock_guard<std::mutex> lock(mutex_);
        values_.erase(handle);
    }
private:
    mutable std::mutex mutex_;
    uint32_t next_ = 0x60000000;
    std::unordered_map<uint32_t, T> values_;
};

HandleTable<EGLDisplay> displays;
HandleTable<EGLConfig> configs;
HandleTable<EGLContext> contexts;
HandleTable<EGLSurface> surfaces;
HandleTable<ANativeWindow*> windows;
HandleTable<AAssetManager*> asset_managers;
HandleTable<AAsset*> assets;
HandleTable<AAssetDir*> asset_dirs;

const char* GuestString(DynarmicHost& host, uint32_t address) {
    if (!GuestRangeValid(host.GetGuestMemorySize(), address, 1)) return nullptr;
    const char* value = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + address);
    return memchr(value, 0, host.GetGuestMemorySize() - address) ? value : nullptr;
}

const EGLint* GuestEglInts(DynarmicHost& host, uint32_t address) {
    if (!address || address % alignof(EGLint)) return nullptr;
    const size_t size = host.GetGuestMemorySize();
    for (uint64_t cursor = address; cursor + sizeof(EGLint) <= size; cursor += 2 * sizeof(EGLint)) {
        if (host.MemoryRead32(static_cast<uint32_t>(cursor)) == EGL_NONE)
            return reinterpret_cast<const EGLint*>(host.GetGuestMemoryBase() + address);
        if (cursor + 2 * sizeof(EGLint) > size) break;
    }
    LOGE("EGL rejected unterminated guest attributes at 0x%08X", address);
    return nullptr;
}

uint32_t CopyHostString(DynarmicHost& host, const char* value) {
    if (!value) return 0;
    const size_t size = strlen(value) + 1;
    const uint32_t guest = host.GuestAlloc(size, 4);
    if (guest) memcpy(host.GetGuestMemoryBase() + guest, value, size);
    return guest;
}
}

void RegisterAndroidThunks(ThunkManager& manager, DynarmicHost& host) {
    manager.RegisterThunk("ANativeWindow_fromSurface", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        JNIEnv* env = FakeJniEnv::Instance().GetEnv();
        jobject surface = FakeJniEnv::Instance().ResolveObject(jit.Regs()[1]);
        jit.Regs()[0] = (env && surface) ? windows.Add(ANativeWindow_fromSurface(env, surface)) : 0;
    });
    manager.RegisterThunk("ANativeWindow_release", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        ANativeWindow* window = windows.Get(jit.Regs()[0]);
        if (window) ANativeWindow_release(window);
        windows.Remove(jit.Regs()[0]);
    });

    manager.RegisterThunk("AAssetManager_fromJava", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        JNIEnv* env = FakeJniEnv::Instance().GetEnv();
        jobject object = FakeJniEnv::Instance().ResolveObject(jit.Regs()[1]);
        jit.Regs()[0] = (env && object) ? asset_managers.Add(AAssetManager_fromJava(env, object)) : 0;
    });
    manager.RegisterThunk("AAssetManager_open", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        AAssetManager* manager_ptr = asset_managers.Get(jit.Regs()[0]);
        const char* name = GuestString(host, jit.Regs()[1]);
        AAsset* asset = (manager_ptr && name) ? AAssetManager_open(manager_ptr, name, jit.Regs()[2]) : nullptr;
        jit.Regs()[0] = assets.Add(asset);
        LOGI("AAssetManager_open '%s' -> 0x%08X", name ? name : "(null)", jit.Regs()[0]);
    });
    manager.RegisterThunk("AAssetManager_openDir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        AAssetManager* manager_ptr = asset_managers.Get(jit.Regs()[0]);
        const char* name = GuestString(host, jit.Regs()[1]);
        AAssetDir* dir = (manager_ptr && name) ? AAssetManager_openDir(manager_ptr, name) : nullptr;
        jit.Regs()[0] = asset_dirs.Add(dir);
        LOGI("AAssetManager_openDir '%s' -> 0x%08X", name ? name : "(null)", jit.Regs()[0]);
    });
    manager.RegisterThunk("AAsset_read", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        AAsset* asset = assets.Get(jit.Regs()[0]);
        void* buffer = GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1], jit.Regs()[2]);
        jit.Regs()[0] = (asset && buffer) ? static_cast<uint32_t>(AAsset_read(asset, buffer, jit.Regs()[2])) : static_cast<uint32_t>(-1);
    });
    manager.RegisterThunk("AAsset_seek", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        AAsset* asset = assets.Get(jit.Regs()[0]);
        jit.Regs()[0] = asset ? static_cast<uint32_t>(AAsset_seek(asset, static_cast<off_t>(static_cast<int32_t>(jit.Regs()[1])), jit.Regs()[2])) : static_cast<uint32_t>(-1);
    });
    manager.RegisterThunk("AAsset_close", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        AAsset* asset = assets.Get(jit.Regs()[0]);
        if (asset) AAsset_close(asset);
        assets.Remove(jit.Regs()[0]);
    });
    manager.RegisterThunk("AAsset_getLength", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        AAsset* asset = assets.Get(jit.Regs()[0]);
        jit.Regs()[0] = asset ? static_cast<uint32_t>(AAsset_getLength(asset)) : 0;
    });
    manager.RegisterThunk("AAsset_openFileDescriptor", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        AAsset* asset = assets.Get(jit.Regs()[0]);
        if ((jit.Regs()[1] && !GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[1], sizeof(uint32_t))) ||
            (jit.Regs()[2] && !GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[2], sizeof(uint32_t)))) {
            jit.Regs()[0] = static_cast<uint32_t>(-1);
            return;
        }
        off_t start = 0, length = 0;
        int fd = asset ? AAsset_openFileDescriptor(asset, &start, &length) : -1;
        if (jit.Regs()[1]) host.MemoryWrite32(jit.Regs()[1], static_cast<uint32_t>(start));
        if (jit.Regs()[2]) host.MemoryWrite32(jit.Regs()[2], static_cast<uint32_t>(length));
        jit.Regs()[0] = static_cast<uint32_t>(fd);
    });
    manager.RegisterThunk("AAssetDir_getNextFileName", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        AAssetDir* dir = asset_dirs.Get(jit.Regs()[0]);
        jit.Regs()[0] = dir ? CopyHostString(host, AAssetDir_getNextFileName(dir)) : 0;
    });
    manager.RegisterThunk("AAssetDir_rewind", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        AAssetDir* dir = asset_dirs.Get(jit.Regs()[0]);
        if (dir) AAssetDir_rewind(dir);
    });
    manager.RegisterThunk("AAssetDir_close", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        AAssetDir* dir = asset_dirs.Get(jit.Regs()[0]);
        if (dir) AAssetDir_close(dir);
        asset_dirs.Remove(jit.Regs()[0]);
    });

    manager.RegisterThunk("eglBindAPI", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = eglBindAPI(jit.Regs()[0]); });
    manager.RegisterThunk("eglQueryAPI", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = eglQueryAPI(); });
    manager.RegisterThunk("eglGetDisplay", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = displays.Add(eglGetDisplay(EGL_DEFAULT_DISPLAY));
    });
    manager.RegisterThunk("eglInitialize", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        EGLDisplay display = displays.Get(jit.Regs()[0]);
        EGLint* major = jit.Regs()[1] ? static_cast<EGLint*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1], sizeof(EGLint))) : nullptr;
        EGLint* minor = jit.Regs()[2] ? static_cast<EGLint*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[2], sizeof(EGLint))) : nullptr;
        if ((jit.Regs()[1] && !major) || (jit.Regs()[2] && !minor)) { jit.Regs()[0] = EGL_FALSE; return; }
        jit.Regs()[0] = eglInitialize(display, major, minor);
    });
    manager.RegisterThunk("eglChooseConfig", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        EGLDisplay display = displays.Get(jit.Regs()[0]);
        const EGLint* attributes = GuestEglInts(host, jit.Regs()[1]);
        const uint32_t out = jit.Regs()[2];
        const EGLint capacity = static_cast<EGLint>(jit.Regs()[3]);
        const uint32_t count_out = host.MemoryRead32(jit.Regs()[13]);
        if ((jit.Regs()[1] && !attributes) || capacity < 0 ||
            !GuestRangeValid(host.GetGuestMemorySize(), count_out, sizeof(EGLint)) ||
            (out && !GuestRangeValid(host.GetGuestMemorySize(), out, static_cast<size_t>(capacity) * sizeof(uint32_t)))) {
            jit.Regs()[0] = EGL_FALSE;
            return;
        }
        EGLint count = 0;
        EGLBoolean ok = eglChooseConfig(display, attributes, nullptr, 0, &count);
        if (ok && out && capacity > 0 && count > 0) {
            const EGLint limit = std::min(count, capacity);
            std::vector<EGLConfig> found(limit);
            ok = eglChooseConfig(display, attributes, found.data(), limit, &count);
            if (ok) for (EGLint i = 0; i < std::min(count, limit); ++i) host.MemoryWrite32(out + i * 4, configs.Add(found[i]));
        } else if (out && capacity == 0) {
            count = 0;
        }
        host.MemoryWrite32(count_out, static_cast<uint32_t>(count));
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglGetConfigs", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        EGLDisplay display = displays.Get(jit.Regs()[0]);
        const uint32_t out = jit.Regs()[1];
        const EGLint capacity = static_cast<EGLint>(jit.Regs()[2]);
        const uint32_t count_out = jit.Regs()[3];
        if (capacity < 0 || !GuestRangeValid(host.GetGuestMemorySize(), count_out, sizeof(EGLint)) ||
            (out && !GuestRangeValid(host.GetGuestMemorySize(), out, static_cast<size_t>(capacity) * sizeof(uint32_t)))) {
            jit.Regs()[0] = EGL_FALSE;
            return;
        }
        EGLint count = 0;
        EGLBoolean ok = eglGetConfigs(display, nullptr, 0, &count);
        if (ok && out && capacity > 0 && count > 0) {
            const EGLint limit = std::min(count, capacity);
            std::vector<EGLConfig> found(limit);
            ok = eglGetConfigs(display, found.data(), limit, &count);
            if (ok) for (EGLint i = 0; i < std::min(count, limit); ++i) host.MemoryWrite32(out + i * 4, configs.Add(found[i]));
        } else if (out && capacity == 0) {
            count = 0;
        }
        host.MemoryWrite32(count_out, static_cast<uint32_t>(count));
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglGetConfigAttrib", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        if (!GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[3], sizeof(EGLint))) { jit.Regs()[0] = EGL_FALSE; return; }
        EGLint value = 0;
        const EGLBoolean ok = eglGetConfigAttrib(displays.Get(jit.Regs()[0]), configs.Get(jit.Regs()[1]), jit.Regs()[2], &value);
        if (ok) host.MemoryWrite32(jit.Regs()[3], static_cast<uint32_t>(value));
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglCreateWindowSurface", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const EGLint* attributes = GuestEglInts(host, jit.Regs()[3]);
        if (jit.Regs()[3] && !attributes) { jit.Regs()[0] = 0; return; }
        EGLSurface surface = eglCreateWindowSurface(displays.Get(jit.Regs()[0]), configs.Get(jit.Regs()[1]),
            windows.Get(jit.Regs()[2]), attributes);
        jit.Regs()[0] = surfaces.Add(surface);
    });
    manager.RegisterThunk("eglCreateContext", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const EGLint* attributes = GuestEglInts(host, jit.Regs()[3]);
        if (jit.Regs()[3] && !attributes) { jit.Regs()[0] = 0; return; }
        EGLContext context = eglCreateContext(displays.Get(jit.Regs()[0]), configs.Get(jit.Regs()[1]),
            contexts.Get(jit.Regs()[2]), attributes);
        jit.Regs()[0] = contexts.Add(context);
    });
    manager.RegisterThunk("eglMakeCurrent", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = eglMakeCurrent(displays.Get(jit.Regs()[0]), surfaces.Get(jit.Regs()[1]),
                                      surfaces.Get(jit.Regs()[2]), contexts.Get(jit.Regs()[3]));
    });
    manager.RegisterThunk("eglSwapBuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        static std::atomic<uint32_t> swaps{0};
        const EGLBoolean result = eglSwapBuffers(displays.Get(jit.Regs()[0]), surfaces.Get(jit.Regs()[1]));
        const uint32_t count = ++swaps;
        if (count <= 10 || count % 300 == 0) LOGI("eglSwapBuffers #%u result=%u", count, result);
        jit.Regs()[0] = result;
    });
    manager.RegisterThunk("eglSwapInterval", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = eglSwapInterval(displays.Get(jit.Regs()[0]), static_cast<EGLint>(jit.Regs()[1]));
    });
    manager.RegisterThunk("eglDestroySurface", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        const EGLBoolean ok = eglDestroySurface(displays.Get(jit.Regs()[0]), surfaces.Get(jit.Regs()[1]));
        if (ok) surfaces.Remove(jit.Regs()[1]);
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglDestroyContext", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        const EGLBoolean ok = eglDestroyContext(displays.Get(jit.Regs()[0]), contexts.Get(jit.Regs()[1]));
        if (ok) contexts.Remove(jit.Regs()[1]);
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglTerminate", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = eglTerminate(displays.Get(jit.Regs()[0]));
    });
    manager.RegisterThunk("eglWaitNative", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = eglWaitNative(jit.Regs()[0]); });
    manager.RegisterThunk("eglWaitGL", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = eglWaitGL(); });
    manager.RegisterThunk("eglReleaseThread", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = eglReleaseThread(); });
    manager.RegisterThunk("eglGetError", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = eglGetError(); });
    manager.RegisterThunk("eglQueryString", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = CopyHostString(host, eglQueryString(displays.Get(jit.Regs()[0]), jit.Regs()[1]));
    });
    manager.RegisterThunk("eglGetCurrentDisplay", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = displays.Add(eglGetCurrentDisplay()); });
    manager.RegisterThunk("eglGetCurrentContext", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = contexts.Add(eglGetCurrentContext()); });
    manager.RegisterThunk("eglGetCurrentSurface", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = surfaces.Add(eglGetCurrentSurface(jit.Regs()[0])); });
    manager.RegisterThunk("eglGetProcAddress", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = GuestString(host, jit.Regs()[0]);
        jit.Regs()[0] = name ? host.GetThunkManager().FindProvider(name, ThunkManager::ProviderKind::Function) : 0;
    });

    LOGI("Registered Android asset/window/EGL thunks");
}
