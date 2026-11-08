#include <jni.h>
#include <android/log.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstring>
#include <fcntl.h>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>
#include <zlib.h>

#include "dynarmic_host.h"
#include "elf_loader.h"
#include "jni_fake_env.h"
#include "thunk_manager.h"
#include "thunk_types.h"
#include "game_port_config.h"
#include "thunks_opensles.h"
#include "telltale_addcallback_fastpath.h"
#include "telltale_propertyset_fastpath.h"

#define LOG_TAG "Arm32Bridge_JNI"
#if ARM32_BRIDGE_ENABLE_LOGGING
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#endif

std::unique_ptr<DynarmicHost> g_host;
JavaVM* g_jvm = nullptr;
JavaVM* GetHostJavaVM() { return g_jvm; }
static std::mutex g_load_mutex;
static bool g_ready = false;
static std::string g_apk_path;
static std::vector<std::string> g_apk_paths;
static std::string g_files_dir;

extern "C" int IndexApk(const char* apk_path);
extern "C" int IndexApks(const char* const* apk_paths, size_t apk_count);
extern "C" int TelltaleWidescreenOverrideEnabled();

static bool ExtractFromApk(const std::string& apk_path, const std::string& entry_name,
                           std::vector<uint8_t>& out_data) {
    const int fd = open(apk_path.c_str(), O_RDONLY);
    if (fd < 0) return false;
    const off_t file_len = lseek(fd, 0, SEEK_END);
    if (file_len < 22) { close(fd); return false; }

    const off_t search_len = std::min<off_t>(file_len, 65536 + 22);
    const off_t search_start = file_len - search_len;
    std::vector<uint8_t> tail(static_cast<size_t>(search_len));
    if (pread(fd, tail.data(), tail.size(), search_start) != static_cast<ssize_t>(tail.size())) {
        close(fd); return false;
    }
    off_t eocd_offset = -1;
    for (ssize_t i = static_cast<ssize_t>(tail.size()) - 22; i >= 0; --i) {
        if (memcmp(tail.data() + i, "PK\x05\x06", 4) == 0) { eocd_offset = search_start + i; break; }
    }
    if (eocd_offset < 0) { close(fd); return false; }

    uint8_t eocd[22]{};
    if (pread(fd, eocd, sizeof(eocd), eocd_offset) != sizeof(eocd)) { close(fd); return false; }
    const uint16_t num_entries = *reinterpret_cast<uint16_t*>(eocd + 10);
    const uint32_t cd_size = *reinterpret_cast<uint32_t*>(eocd + 12);
    const uint32_t cd_offset = *reinterpret_cast<uint32_t*>(eocd + 16);
    if (num_entries == 0xFFFF || cd_size == 0xFFFFFFFFu || cd_offset == 0xFFFFFFFFu ||
        static_cast<uint64_t>(cd_offset) + cd_size > static_cast<uint64_t>(file_len)) {
        close(fd); return false;
    }

    std::vector<uint8_t> cd(cd_size);
    if (pread(fd, cd.data(), cd.size(), cd_offset) != static_cast<ssize_t>(cd.size())) {
        close(fd); return false;
    }
    size_t pos = 0;
    for (uint16_t i = 0; i < num_entries && pos + 46 <= cd.size(); ++i) {
        if (*reinterpret_cast<uint32_t*>(cd.data() + pos) != 0x02014b50) break;
        const uint16_t method = *reinterpret_cast<uint16_t*>(cd.data() + pos + 10);
        const uint32_t csize = *reinterpret_cast<uint32_t*>(cd.data() + pos + 20);
        const uint32_t usize = *reinterpret_cast<uint32_t*>(cd.data() + pos + 24);
        const uint16_t fn_len = *reinterpret_cast<uint16_t*>(cd.data() + pos + 28);
        const uint16_t extra_len = *reinterpret_cast<uint16_t*>(cd.data() + pos + 30);
        const uint16_t comment_len = *reinterpret_cast<uint16_t*>(cd.data() + pos + 32);
        const uint32_t local_offset = *reinterpret_cast<uint32_t*>(cd.data() + pos + 42);
        if (pos + 46ull + fn_len + extra_len + comment_len > cd.size()) break;
        const std::string name(reinterpret_cast<char*>(cd.data() + pos + 46), fn_len);
        if (name == entry_name) {
            uint8_t local[30]{};
            if (pread(fd, local, sizeof(local), local_offset) != sizeof(local) ||
                *reinterpret_cast<uint32_t*>(local) != 0x04034b50) { close(fd); return false; }
            const uint16_t local_name = *reinterpret_cast<uint16_t*>(local + 26);
            const uint16_t local_extra = *reinterpret_cast<uint16_t*>(local + 28);
            const off_t raw = static_cast<off_t>(local_offset) + 30 + local_name + local_extra;
            out_data.resize(usize);
            if (method == 0) {
                const bool ok = pread(fd, out_data.data(), usize, raw) == static_cast<ssize_t>(usize);
                close(fd); return ok;
            }
            if (method == 8) {
                std::vector<uint8_t> compressed(csize);
                if (pread(fd, compressed.data(), csize, raw) != static_cast<ssize_t>(csize)) {
                    close(fd); return false;
                }
                z_stream stream{};
                stream.next_in = compressed.data();
                stream.avail_in = csize;
                stream.next_out = out_data.data();
                stream.avail_out = usize;
                int result = inflateInit2(&stream, -MAX_WBITS);
                if (result == Z_OK) result = inflate(&stream, Z_FINISH);
                inflateEnd(&stream);
                close(fd);
                return result == Z_STREAM_END;
            }
            close(fd); return false;
        }
        pos += 46ull + fn_len + extra_len + comment_len;
    }
    close(fd);
    return false;
}

#if ARM32_BRIDGE_ENABLE_TELLTALE_ZLIB_ACCELERATION
static bool InstallTelltaleZlibAcceleration(DynarmicHost& host) {
    static constexpr char kSymbol[] = "_ZN11Compression14ZlibDecompressEPvPjPKvj";
    static constexpr std::array<uint32_t, 13> kFingerprint = {
        0xE92D4010, 0xE24DD008, 0xE1A04001, 0xE3A0C004, 0xE5911000,
        0xE58DC000, 0xEBFFFF4B, 0xE5943000, 0xE0630000, 0xE16F0F10,
        0xE1A002A0, 0xE28DD008, 0xE8BD8010,
    };

    ElfLoader* engine = host.FindModule("libGameEngine.so");
    const ElfSymbol* symbol = engine ? engine->GetExportedSymbol(kSymbol) : nullptr;
    if (!symbol || symbol->type != STT_FUNC || symbol->size != sizeof(kFingerprint) ||
        !symbol->value || (symbol->value & 1u)) {
        LOGE("Native raw-DEFLATE acceleration unavailable: unexpected symbol metadata");
        return false;
    }

    const uint32_t target = symbol->value;
    for (size_t i = 0; i < kFingerprint.size(); ++i) {
        if (host.MemoryRead32(target + static_cast<uint32_t>(i * sizeof(uint32_t))) != kFingerprint[i]) {
            LOGE("Native raw-DEFLATE acceleration refused: fingerprint mismatch at 0x%08X",
                 target + static_cast<uint32_t>(i * sizeof(uint32_t)));
            return false;
        }
    }

    const uint32_t thunk = host.GetThunkManager().RegisterThunk(
        "__telltale_native_raw_deflate_decompress",
        [](Dynarmic::A32::Jit& jit, DynarmicHost& runtime) {
            const uint32_t destination = jit.Regs()[0];
            const uint32_t expected_size_ptr = jit.Regs()[1];
            const uint32_t source = jit.Regs()[2];
            const uint32_t source_size = jit.Regs()[3];
            uint32_t produced = UINT32_MAX;

            if (destination && expected_size_ptr && source &&
                GuestRangeValid(runtime.GetGuestMemorySize(), expected_size_ptr, sizeof(uint32_t))) {
                const uint32_t capacity = runtime.MemoryRead32(expected_size_ptr);
                auto* output = static_cast<Bytef*>(GuestSpan(runtime.GetGuestMemoryBase(),
                                                             runtime.GetGuestMemorySize(),
                                                             destination, capacity));
                auto* input = static_cast<Bytef*>(GuestSpan(runtime.GetGuestMemoryBase(),
                                                            runtime.GetGuestMemorySize(),
                                                            source, source_size));
                if (output && input) {
                    Bytef empty_output = 0;
                    z_stream stream{};
                    stream.next_in = input;
                    stream.avail_in = source_size;
                    stream.next_out = capacity ? output : &empty_output;
                    stream.avail_out = capacity;

#if ARM32_BRIDGE_ENABLE_TELLTALE_ZLIB_DIAGNOSTICS
                    const auto start = std::chrono::steady_clock::now();
#endif
                    const int init_result = inflateInit2(&stream, -MAX_WBITS);
                    int inflate_result = init_result;
                    if (init_result == Z_OK) {
                        inflate_result = inflate(&stream, Z_FINISH);
                        if (inflate_result == Z_STREAM_END && stream.total_out <= UINT32_MAX) {
                            produced = static_cast<uint32_t>(stream.total_out);
                        }
                        inflateEnd(&stream);
                    }

#if ARM32_BRIDGE_ENABLE_TELLTALE_ZLIB_DIAGNOSTICS
                    static std::atomic<uint32_t> calls{0};
                    static std::atomic<uint64_t> total_output{0};
                    static std::atomic<uint64_t> total_microseconds{0};
                    const uint64_t elapsed_us = static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now() - start).count());
                    const uint32_t call = calls.fetch_add(1, std::memory_order_relaxed) + 1;
                    const uint64_t bytes = produced == UINT32_MAX ? 0 : produced;
                    const uint64_t aggregate_bytes =
                        total_output.fetch_add(bytes, std::memory_order_relaxed) + bytes;
                    const uint64_t aggregate_us =
                        total_microseconds.fetch_add(elapsed_us, std::memory_order_relaxed) + elapsed_us;
                    if ((call & (call - 1)) == 0) {
                        LOGI("Native raw-DEFLATE calls=%u last=%u->%u status=%d total=%" PRIu64
                             " bytes time=%" PRIu64 " us",
                             call, source_size, produced, inflate_result,
                             aggregate_bytes, aggregate_us);
                    }
#endif
                }
            }

            // The ARM32 wrapper reads the expected size again and never writes it.
            jit.Regs()[0] = produced == runtime.MemoryRead32(expected_size_ptr) ? 1u : 0u;
        });
    if (!thunk) {
        LOGE("Native raw-DEFLATE acceleration unavailable: thunk registration failed");
        return false;
    }

    // Tail-jump through the bridge trampoline. Writing the destination first keeps
    // the entry fail-closed if a debugger observes the pair between stores.
    host.MemoryWrite32(target + 4, thunk);
    host.MemoryWrite32(target, 0xE51FF004);  // ldr pc, [pc, #-4]
    host.InvalidateGuestCode(target, 8);
    LOGI("Installed native raw-DEFLATE acceleration at 0x%08X -> 0x%08X", target, thunk);
    return true;
}
#endif

static std::string JString(JNIEnv* env, jstring value) {
    if (!value) return {};
    const char* chars = env->GetStringUTFChars(value, nullptr);
    std::string result = chars ? chars : "";
    if (chars) env->ReleaseStringUTFChars(value, chars);
    return result;
}

static bool DiscoverApplicationPaths(JNIEnv* env) {
    jclass sdl = env->FindClass(portcfg::kSdlActivityClass);
    if (!sdl) return false;
    jfieldID singleton_field = env->GetStaticFieldID(sdl, "mSingleton", "Lorg/libsdl/app/SDLActivity;");
    jobject activity = singleton_field ? env->GetStaticObjectField(sdl, singleton_field) : nullptr;
    if (!activity) return false;
    jclass activity_class = env->GetObjectClass(activity);

    jmethodID get_app_info = env->GetMethodID(activity_class, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
    jobject app_info = get_app_info ? env->CallObjectMethod(activity, get_app_info) : nullptr;
    if (!app_info) return false;
    jclass app_info_class = env->GetObjectClass(app_info);
    jfieldID source_field = env->GetFieldID(app_info_class, "sourceDir", "Ljava/lang/String;");
    g_apk_path = JString(env, static_cast<jstring>(env->GetObjectField(app_info, source_field)));
    g_apk_paths.clear();
    if (!g_apk_path.empty()) g_apk_paths.push_back(g_apk_path);
    jfieldID split_source_field = env->GetFieldID(app_info_class, "splitSourceDirs", "[Ljava/lang/String;");
    if (split_source_field) {
        auto split_sources = static_cast<jobjectArray>(env->GetObjectField(app_info, split_source_field));
        const jsize split_count = split_sources ? env->GetArrayLength(split_sources) : 0;
        for (jsize i = 0; i < split_count; ++i) {
            auto split = static_cast<jstring>(env->GetObjectArrayElement(split_sources, i));
            const std::string path = JString(env, split);
            if (!path.empty()) g_apk_paths.push_back(path);
            if (split) env->DeleteLocalRef(split);
        }
        if (split_sources) env->DeleteLocalRef(split_sources);
    }
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        return false;
    }

    jmethodID get_files = env->GetMethodID(activity_class, "getExternalFilesDir", "(Ljava/lang/String;)Ljava/io/File;");
    jobject files = get_files ? env->CallObjectMethod(activity, get_files, nullptr) : nullptr;
    if (files) {
        jclass file_class = env->GetObjectClass(files);
        jmethodID absolute = env->GetMethodID(file_class, "getAbsolutePath", "()Ljava/lang/String;");
        g_files_dir = JString(env, static_cast<jstring>(env->CallObjectMethod(files, absolute)));
    }
    if (env->ExceptionCheck()) { env->ExceptionDescribe(); env->ExceptionClear(); return false; }
    LOGI("Application paths: apk='%s' splits=%zu files='%s'", g_apk_path.c_str(), g_apk_paths.size(), g_files_dir.c_str());
    return !g_apk_path.empty();
}

static uint32_t Sym(const char* module_name, const char* symbol) {
    ElfLoader* module = g_host ? g_host->FindModule(module_name) : nullptr;
    const uint32_t address = module ? module->GetSymbolAddress(symbol) : 0;
    if (!address) LOGE("Missing guest symbol %s in %s", symbol, module_name);
    return address;
}

struct GuestSymbols {
    uint32_t nativeInit = 0;
    uint32_t nativeAddJoystick = 0, nativeFlipBuffers = 0, nativeLowMemory = 0;
    uint32_t nativePause = 0, nativeQuit = 0, nativeRemoveJoystick = 0, nativeResume = 0;
    uint32_t onNativeAccel = 0, onNativeHat = 0, onNativeJoy = 0;
    uint32_t onNativeKeyDown = 0, onNativeKeyUp = 0, onNativeKeyboardFocusLost = 0;
    uint32_t onNativePadDown = 0, onNativePadUp = 0, onNativeResize = 0;
    uint32_t onNativeSurfaceChanged = 0, onNativeSurfaceDestroyed = 0, onNativeTouch = 0;
    uint32_t nativeCommitText = 0, nativeSetComposingText = 0;
    uint32_t fmodGetSize = 0, fmodReadAt = 0;
    uint32_t nativeOnPermissionComplete = 0, nativeOnPurchaseComplete = 0;
} g_symbols;

#if defined(ARM32_BRIDGE_ENABLE_MCSM_WIDESCREEN_OVERRIDE) && \
    ARM32_BRIDGE_ENABLE_MCSM_WIDESCREEN_OVERRIDE
static bool GuestRangeHasFlags(const ElfLoader& module, uint32_t address, uint32_t size,
                               uint32_t required_flags) {
    if (!size || address < module.GetBaseAddress()) return false;
    const uint64_t start = static_cast<uint64_t>(address - module.GetBaseAddress());
    const uint64_t end = start + size;
    if (end > UINT32_MAX) return false;
    for (const ElfSegment& segment : module.GetSegments()) {
        const uint64_t segment_start = segment.vaddr;
        const uint64_t segment_end = segment_start + segment.memsz;
        if (start >= segment_start && end <= segment_end &&
            (segment.flags & required_flags) == required_flags) return true;
    }
    return false;
}

static std::atomic<bool> g_mcsm_gameplay_started{false};

struct MCSMEntryHook {
    uint32_t target = 0;
    uint32_t veneer = 0;
    uint32_t svc = 0;
    uint32_t first = 0;
    uint32_t second = 0;
};

static bool PrepareMCSMEntryHook(DynarmicHost& runtime, const ElfLoader& engine,
                                const char* symbol_name, uint32_t expected_size,
                                uint32_t first, uint32_t second, const char* thunk_name,
                                ThunkHandler handler, MCSMEntryHook& out) {
    const ElfSymbol* symbol = engine.GetExportedSymbol(symbol_name);
    if (!symbol || symbol->type != STT_FUNC || symbol->size != expected_size ||
        (symbol->value & 3u) || !GuestRangeHasFlags(engine, symbol->value, symbol->size, PF_X) ||
        runtime.MemoryRead32(symbol->value) != first || runtime.MemoryRead32(symbol->value + 4) != second) {
        LOGE("MCSM aspect hook refused: function fingerprint mismatch for %s.", symbol_name);
        return false;
    }
    const uint32_t thunk = runtime.GetThunkManager().RegisterThunk(thunk_name, std::move(handler));
    const uint32_t svc = thunk ? runtime.MemoryRead32(thunk) : 0;
    if (!thunk || (svc & 0xFF000000u) != 0xEF000000u) {
        LOGE("MCSM aspect hook refused: cannot create thunk %s.", thunk_name);
        return false;
    }
    const uint32_t veneer = runtime.GuestAlloc(32, 4);
    if (!veneer) {
        LOGE("MCSM aspect hook refused: cannot allocate veneer for %s.", symbol_name);
        return false;
    }
    runtime.MemoryWrite32(veneer + 0, svc);
    runtime.MemoryWrite32(veneer + 4, first);
    runtime.MemoryWrite32(veneer + 8, second);
    runtime.MemoryWrite32(veneer + 12, 0xE51FF004u); // ldr pc, [pc, #-4]
    runtime.MemoryWrite32(veneer + 16, symbol->value + 8);
    runtime.InvalidateGuestCode(veneer, 20);
    runtime.AddExecutableRange(veneer, 20);
    out = {symbol->value, veneer, svc, first, second};
    return true;
}

static void CommitMCSMEntryHook(DynarmicHost& runtime, const MCSMEntryHook& hook) {
    runtime.MemoryWrite32(hook.target + 0, 0xE51FF004u); // ldr pc, [pc, #-4]
    runtime.MemoryWrite32(hook.target + 4, hook.veneer);
    runtime.InvalidateGuestCode(hook.target, 8);
}

// MCSM 1.37 Mali: _project.lua forces 16:9 globally. Only the optional
// widescreen split may override that behavior. Without it, leave the guest
// setters and aspect state untouched so every gameplay entry path keeps the
// authored ratio. Every patched target is validated for this exact build.
static bool InstallMCSMGameplayAspectHooks(DynarmicHost& runtime) {
    ElfLoader* engine = runtime.FindModule("libGameEngine.so");
    if (!engine) {
        LOGE("MCSM gameplay aspect hooks refused: libGameEngine.so is not loaded.");
        return false;
    }
    constexpr char kSetForceName[] = "_ZN12RenderDevice30SetForceGameContentAspectRatioEb";
    constexpr char kSetAspectName[] = "_ZN12RenderDevice25SetGameContentAspectRatioEf";
    constexpr char kForceFlagName[] = "_ZN12RenderDevice18sbForceAspectRatioE";
    constexpr char kAspectValueName[] = "_ZN12RenderDevice24sfGameContentAspectRatioE";
    constexpr char kReinitializeName[] = "_ZN12RenderDevice20mbReInitializeDeviceE";
    constexpr char kNewGameName[] = "_Z12luaResetGameP9lua_State";
    constexpr char kLoadGameName[] = "_Z11luaLoadGameP9lua_State";
    const ElfSymbol* set_force = engine->GetExportedSymbol(kSetForceName);
    const ElfSymbol* set_aspect = engine->GetExportedSymbol(kSetAspectName);
    const ElfSymbol* force_flag = engine->GetExportedSymbol(kForceFlagName);
    const ElfSymbol* aspect_value = engine->GetExportedSymbol(kAspectValueName);
    const ElfSymbol* reinitialize = engine->GetExportedSymbol(kReinitializeName);
    const ElfSymbol* new_game = engine->GetExportedSymbol(kNewGameName);
    const ElfSymbol* load_game = engine->GetExportedSymbol(kLoadGameName);
    constexpr uint32_t kSetForceSize = 52;
    constexpr uint32_t kSetAspectSize = 68;
    constexpr uint32_t kNewGameSize = 688;
    constexpr uint32_t kLoadGameSize = 176;
    constexpr uint32_t kSetForceStoreOffset = 0x1C;
    constexpr uint32_t kSetForceStore = 0xE5C30000u; // strb r0, [r3]
    constexpr std::array<uint32_t, 4> kSetForcePrologue = {
        0xE59F3024u, 0xE79F3003u, 0xE5D32000u, 0xE1520000u,
    };
    constexpr std::array<uint32_t, 4> kSetAspectPrologue = {
        0xE59F2030u, 0xEE070A90u, 0xE59F302Cu, 0xE79F2002u,
    };
    constexpr uint32_t kSetAspectForceStoreOffset = 0x30;
    constexpr uint32_t kSetAspectForceStore = 0x15C32000u; // strbne r2, [r3]
    constexpr uint32_t kNewGameFirst = 0xE92D4FF0u;
    constexpr uint32_t kNewGameSecond = 0xE1A04000u;
    constexpr uint32_t kLoadGameFirst = 0xE92D40F0u;
    constexpr uint32_t kLoadGameSecond = 0xE24DD00Cu;
    if (!set_force || set_force->type != STT_FUNC || set_force->size != kSetForceSize ||
        (set_force->value & 3u) || !GuestRangeHasFlags(*engine, set_force->value, set_force->size, PF_X) ||
        !set_aspect || set_aspect->type != STT_FUNC || set_aspect->size != kSetAspectSize ||
        (set_aspect->value & 3u) || !GuestRangeHasFlags(*engine, set_aspect->value, set_aspect->size, PF_X) ||
        !force_flag || force_flag->type != STT_OBJECT || force_flag->size != 1 ||
        !GuestRangeHasFlags(*engine, force_flag->value, force_flag->size, PF_W) ||
        !aspect_value || aspect_value->type != STT_OBJECT || aspect_value->size != 4 ||
        !GuestRangeHasFlags(*engine, aspect_value->value, aspect_value->size, PF_W) ||
        !reinitialize || reinitialize->type != STT_OBJECT || reinitialize->size != 1 ||
        !GuestRangeHasFlags(*engine, reinitialize->value, reinitialize->size, PF_W) ||
        !new_game || new_game->type != STT_FUNC || new_game->size != kNewGameSize ||
        !GuestRangeHasFlags(*engine, new_game->value, new_game->size, PF_X) ||
        !load_game || load_game->type != STT_FUNC || load_game->size != kLoadGameSize ||
        !GuestRangeHasFlags(*engine, load_game->value, load_game->size, PF_X)) {
        LOGE("MCSM gameplay aspect hooks refused: required export type/size/segment checks failed.");
        return false;
    }
    for (size_t i = 0; i < kSetForcePrologue.size(); ++i) {
        if (runtime.MemoryRead32(set_force->value + static_cast<uint32_t>(i * 4)) !=
            kSetForcePrologue[i]) {
            LOGE("MCSM gameplay aspect hooks refused: SetForce prologue mismatch at +0x%zX.", i * 4);
            return false;
        }
        if (runtime.MemoryRead32(set_aspect->value + static_cast<uint32_t>(i * 4)) !=
            kSetAspectPrologue[i]) {
            LOGE("MCSM gameplay aspect hooks refused: SetAspect prologue mismatch at +0x%zX.", i * 4);
            return false;
        }
    }
    const uint32_t set_force_store = runtime.MemoryRead32(set_force->value + kSetForceStoreOffset);
    const uint32_t set_aspect_store = runtime.MemoryRead32(set_aspect->value + kSetAspectForceStoreOffset);
    const uint32_t new_game_first = runtime.MemoryRead32(new_game->value);
    const uint32_t new_game_second = runtime.MemoryRead32(new_game->value + 4);
    const uint32_t load_game_first = runtime.MemoryRead32(load_game->value);
    const uint32_t load_game_second = runtime.MemoryRead32(load_game->value + 4);
    if (set_force_store != kSetForceStore || set_aspect_store != kSetAspectForceStore ||
        new_game_first != kNewGameFirst || new_game_second != kNewGameSecond ||
        load_game_first != kLoadGameFirst || load_game_second != kLoadGameSecond ||
        runtime.MemoryRead8(force_flag->value) > 1) {
        LOGE("MCSM gameplay aspect hooks refused: force-store=0x%08X aspect-store=0x%08X "
             "new-game=0x%08X/0x%08X load-game=0x%08X/0x%08X.",
             set_force_store, set_aspect_store, new_game_first, new_game_second,
             load_game_first, load_game_second);
        return false;
    }

    const bool widescreen_marker = TelltaleWidescreenOverrideEnabled() != 0;
    g_mcsm_gameplay_started.store(false, std::memory_order_relaxed);
    auto gameplay_start = [widescreen_marker, force_address = force_flag->value,
                           aspect_address = aspect_value->value,
                           reinitialize_address = reinitialize->value]
                          (Dynarmic::A32::Jit&, DynarmicHost& host) {
        g_mcsm_gameplay_started.store(true, std::memory_order_relaxed);
        host.MemoryWrite32(aspect_address, 0x3FE38E39u); // 16:9
        host.MemoryWrite8(force_address, widescreen_marker ? 0 : 1);
        host.MemoryWrite8(reinitialize_address, 1);
        LOGI("MCSM gameplay aspect selected: marker=%u force16by9=%u.",
             widescreen_marker ? 1u : 0u, widescreen_marker ? 0u : 1u);
    };
    auto force_gate = [widescreen_marker, force_address = force_flag->value]
                      (Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        if (jit.Regs()[3] != force_address) return;
        const bool gameplay_started = g_mcsm_gameplay_started.load(std::memory_order_relaxed);
        const uint8_t requested = (!gameplay_started || widescreen_marker)
            ? 0 : static_cast<uint8_t>(jit.Regs()[0] & 1u);
        host.MemoryWrite8(force_address, requested);
    };
    const uint32_t force_gate_thunk = runtime.GetThunkManager().RegisterThunk(
        "mcsm_aspect_force_gate", std::move(force_gate));
    const uint32_t force_gate_svc = force_gate_thunk ? runtime.MemoryRead32(force_gate_thunk) : 0;
    if (!force_gate_thunk || (force_gate_svc & 0xFF000000u) != 0xEF000000u) {
        LOGE("MCSM gameplay aspect hooks refused: cannot create SetForce gate thunk.");
        return false;
    }
    MCSMEntryHook new_game_hook;
    MCSMEntryHook load_game_hook;
    if (!PrepareMCSMEntryHook(runtime, *engine, kNewGameName, kNewGameSize,
            kNewGameFirst, kNewGameSecond, "mcsm_aspect_new_game_start",
            gameplay_start, new_game_hook) ||
        !PrepareMCSMEntryHook(runtime, *engine, kLoadGameName, kLoadGameSize,
            kLoadGameFirst, kLoadGameSecond, "mcsm_aspect_load_game_start",
            gameplay_start, load_game_hook)) {
        return false;
    }

    CommitMCSMEntryHook(runtime, new_game_hook);
    CommitMCSMEntryHook(runtime, load_game_hook);
    runtime.MemoryWrite32(set_force->value + kSetForceStoreOffset, force_gate_svc);
    runtime.MemoryWrite32(set_aspect->value + kSetAspectForceStoreOffset, 0xE1A00000u); // nop
    runtime.MemoryWrite8(force_flag->value, 0);
    runtime.MemoryWrite8(reinitialize->value, 1);
    runtime.InvalidateGuestCode(set_force->value + kSetForceStoreOffset, sizeof(uint32_t));
    runtime.InvalidateGuestCode(set_aspect->value + kSetAspectForceStoreOffset, sizeof(uint32_t));
    LOGI("MCSM gameplay aspect hooks installed: marker=%u force=0x%08X aspect=0x%08X new=0x%08X load=0x%08X.",
         widescreen_marker ? 1u : 0u, set_force->value, set_aspect->value,
         new_game_hook.target, load_game_hook.target);
    return true;
}
#endif

static bool ResolveGuestSymbols() {
#define RESOLVE(field, module, symbol) do { g_symbols.field = Sym(module, symbol); if (!g_symbols.field) return false; } while (0)
    RESOLVE(nativeInit, "libmain.so", "Java_org_libsdl_app_SDLActivity_nativeInit");
    RESOLVE(nativeAddJoystick, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_nativeAddJoystick");
    RESOLVE(nativeFlipBuffers, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_nativeFlipBuffers");
    RESOLVE(nativeLowMemory, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_nativeLowMemory");
    RESOLVE(nativePause, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_nativePause");
    RESOLVE(nativeQuit, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_nativeQuit");
    RESOLVE(nativeRemoveJoystick, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_nativeRemoveJoystick");
    RESOLVE(nativeResume, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_nativeResume");
    RESOLVE(onNativeAccel, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativeAccel");
    RESOLVE(onNativeHat, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativeHat");
    RESOLVE(onNativeJoy, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativeJoy");
    RESOLVE(onNativeKeyDown, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativeKeyDown");
    RESOLVE(onNativeKeyUp, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativeKeyUp");
    RESOLVE(onNativeKeyboardFocusLost, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativeKeyboardFocusLost");
    RESOLVE(onNativePadDown, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativePadDown");
    RESOLVE(onNativePadUp, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativePadUp");
    RESOLVE(onNativeResize, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativeResize");
    RESOLVE(onNativeSurfaceChanged, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativeSurfaceChanged");
    RESOLVE(onNativeSurfaceDestroyed, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativeSurfaceDestroyed");
    RESOLVE(onNativeTouch, "libSDL2.so", "Java_org_libsdl_app_SDLActivity_onNativeTouch");
    RESOLVE(nativeCommitText, "libSDL2.so", "Java_org_libsdl_app_SDLInputConnection_nativeCommitText");
    RESOLVE(nativeSetComposingText, "libSDL2.so", "Java_org_libsdl_app_SDLInputConnection_nativeSetComposingText");
    RESOLVE(fmodGetSize, "libfmod.so", "Java_org_fmod_MediaCodec_fmodGetSize");
    RESOLVE(fmodReadAt, "libfmod.so", "Java_org_fmod_MediaCodec_fmodReadAt");
    RESOLVE(nativeOnPermissionComplete, "libGameEngine.so", "Java_com_telltalegames_telltale_TelltaleActivity_nativeOnPermissionComplete");
    RESOLVE(nativeOnPurchaseComplete, "libGameEngine.so", "Java_com_telltalegames_telltale_TelltaleActivity_nativeOnPurchaseComplete");
#undef RESOLVE
    return true;
}

static bool EnsureGameLoaded(JNIEnv* env) {
    std::lock_guard<std::mutex> lock(g_load_mutex);
    if (g_ready && g_host) { FakeJniEnv::Instance().AttachHostEnv(env); return true; }
    if (g_host && !g_ready) g_host.reset();
    if (!DiscoverApplicationPaths(env)) return false;

    auto host = std::make_unique<DynarmicHost>();
    if (!host->Initialize()) return false;
    FakeJniEnv& fake = FakeJniEnv::Instance();
    fake.SetJavaVM(g_jvm);
    fake.Init(*host);
    fake.AttachHostEnv(env);
#ifdef ARM32_BRIDGE_REDIRECT_EXTERNAL_STORAGE_TO_APP_FILES
    fake.SetExternalStorageDirectoryOverride(g_files_dir);
    LOGI("Guest external-storage root: '%s'", g_files_dir.c_str());
#endif

    std::array<std::vector<uint8_t>, portcfg::kGuestModules.size()> images;
    std::vector<GuestModuleImage> modules;
    modules.reserve(portcfg::kGuestModules.size());
    for (size_t i = 0; i < portcfg::kGuestModules.size(); ++i) {
        const std::string entry = std::string(portcfg::kGuestAssetPrefix) + portcfg::kGuestModules[i];
        if (!ExtractFromApk(g_apk_path, entry, images[i])) {
            LOGE("Unable to extract guest module: %s", entry.c_str());
            return false;
        }
        modules.push_back({portcfg::kGuestModules[i], images[i].data(), images[i].size()});
    }
    std::vector<const char*> apk_paths;
    apk_paths.reserve(g_apk_paths.size());
    for (const std::string& path : g_apk_paths) apk_paths.push_back(path.c_str());
    if (IndexApks(apk_paths.data(), apk_paths.size()) != 0 || !host->LoadModulesFromMemory(modules)) return false;
#if defined(ARM32_BRIDGE_ENABLE_MCSM_HIDE_BORDER_OVERRIDE) && \
    ARM32_BRIDGE_ENABLE_MCSM_HIDE_BORDER_OVERRIDE
    if (!InstallMCSMHideBorderOverride(*host)) return false;
#endif
#if ARM32_BRIDGE_ENABLE_TELLTALE_ZLIB_ACCELERATION
    InstallTelltaleZlibAcceleration(*host);
#endif
#if defined(ARM32_BRIDGE_ENABLE_TELLTALE_ADD_CALLBACK_ACCELERATION) && \
    ARM32_BRIDGE_ENABLE_TELLTALE_ADD_CALLBACK_ACCELERATION
    InstallTelltalePropertySetAddCallbackAcceleration(*host);
#endif
#if defined(ARM32_BRIDGE_ENABLE_TELLTALE_GET_KEY_INFO_ACCELERATION) && \
    ARM32_BRIDGE_ENABLE_TELLTALE_GET_KEY_INFO_ACCELERATION
    InstallTelltaleGetKeyInfoAcceleration(*host);
#endif
    InstallTelltaleCurrentDirectoryFix(*host);
    if (!InstallMCSMAppFilesUserLocation(*host)) return false;
    if (!InstallMCSMEpisodeDirectory(*host, g_files_dir)) return false;
#if ARM32_BRIDGE_ENABLE_TELLTALE_DIAGNOSTIC_PROBES
    InstallTelltaleRenderFrameProbe(*host);
    InstallTelltaleRenderExecuteProbe(*host);
    InstallTelltaleSceneProbes(*host);
    InstallTelltaleDoLoadProbe(*host);
    InstallTelltaleStartupProbes(*host);
    InstallTelltaleTTPCallErrorProbe(*host);
    InstallTelltaleArchiveProbe(*host);
#else
    LOGI("Telltale diagnostic probes disabled for production.");
#endif
    g_host = std::move(host);
    if (!g_host->RunModuleInitializers()) return false;

    for (const char* module_name : {"libSDL2.so", "libfmod.so"}) {
        ElfLoader* module = g_host->FindModule(module_name);
        const uint32_t on_load = module ? module->GetSymbolAddress("JNI_OnLoad") : 0;
        if (on_load) {
            const uint32_t version = g_host->RunFunction(on_load, {fake.VmTableGuestAddr(), 0});
            LOGI("Guest %s JNI_OnLoad -> 0x%08X", module_name, version);
        }
    }
    if (!ResolveGuestSymbols()) { g_host.reset(); return false; }
    if (const uint32_t suspended = g_host->FindSymbol("_ZN10GameEngine17mbSuspendGameLoopE")) {
        g_host->MemoryWrite8(suspended, 0);
        LOGI("Cleared initial GameEngine suspend flag.");
    }
#if defined(ARM32_BRIDGE_ENABLE_MCSM_WIDESCREEN_OVERRIDE) && \
    ARM32_BRIDGE_ENABLE_MCSM_WIDESCREEN_OVERRIDE
    if (TelltaleWidescreenOverrideEnabled() && !InstallMCSMGameplayAspectHooks(*g_host))
        LOGE("MCSM widescreen split is installed, but its aspect hooks are unavailable for this guest build.");
#endif
    g_ready = true;
    LOGI("Telltale guest runtime ready.");

#if ARM32_BRIDGE_ENABLE_RUNTIME_WATCHDOG
    static bool watchdog_started = false;
    if (!watchdog_started) {
        watchdog_started = true;
        DynarmicHost* runtime = g_host.get();
        const uint32_t frame_num = runtime->FindSymbol("_ZN7Metrics9mFrameNumE");
        const uint32_t frame_time = runtime->FindSymbol("_ZN7Metrics10mFrameTimeE");
        const uint32_t actual_time = runtime->FindSymbol("_ZN7Metrics16mActualFrameTimeE");
        const uint32_t suspended = runtime->FindSymbol("_ZN10GameEngine17mbSuspendGameLoopE");
        const uint32_t quit = runtime->FindSymbol("_ZN10GameEngine15mbRequestedQuitE");
        const uint32_t window = runtime->FindSymbol("_ZN10GameWindow10smpGameWinE");
        const uint32_t scale = runtime->FindSymbol("_ZN7Metrics6mScaleE");
        const uint32_t next_time = runtime->FindSymbol("_ZN7Metrics14mNextFrameTimeE");
        const uint32_t fixed_time = runtime->FindSymbol("_ZN7Metrics14mFixedTimeStepE");
        const uint32_t tick_value = runtime->FindSymbol("_ZN7Metrics17mTimeGetTimeValueE");
        const uint32_t use_ticks = runtime->FindSymbol("_ZN7Metrics16mbUseTimeGetTimeE");
        const uint32_t get_ticks = runtime->FindSymbol("SDL_GetTicks");
        const uint32_t render_enabled = runtime->FindSymbol("_ZN12RenderDevice17mbEnableRenderingE");
        const uint32_t render_reinit = runtime->FindSymbol("_ZN12RenderDevice20mbReInitializeDeviceE");
        const uint32_t render_delay = runtime->FindSymbol("_ZN12RenderDevice18mRenderDelayFramesE");
        const uint32_t render_in_frame = runtime->FindSymbol("_ZN12RenderDevice9mbInFrameE");
        const uint32_t device_initialized = runtime->FindSymbol("_ZN12RenderDevice20mDeviceIsInitializedE");
        const uint32_t render_caps = runtime->FindSymbol("_ZN12RenderDevice11mRenderCapsE");
        const uint32_t device_width = runtime->FindSymbol("_ZN12RenderDevice12mDeviceWidthE");
        const uint32_t device_height = runtime->FindSymbol("_ZN12RenderDevice13mDeviceHeightE");
        const uint32_t game_width = runtime->FindSymbol("_ZN12RenderDevice10mGameWidthE");
        const uint32_t game_height = runtime->FindSymbol("_ZN12RenderDevice11mGameHeightE");
        const uint32_t current_thread = runtime->FindSymbol("_ZN12RenderDevice16mCurrentThreadIDE");
        const uint32_t render_target_fbo = runtime->FindSymbol("_ZN12RenderDevice16mRenderTargetFBOE");
        const uint32_t blit_target_fbo = runtime->FindSymbol("_ZN12RenderDevice14mBlitTargetFBOE");
        const uint32_t global_obj_cache = runtime->FindSymbol("_ZN11ObjCacheMgr16spGlobalObjCacheE");
        const uint32_t render_thread_enable = runtime->FindSymbol("gMultithreadRenderEnable");
        const uint32_t scene_count = runtime->FindSymbol("_ZN5Scene17msActiveSceneListE");
        const ElfLoader* game_engine = runtime->FindModule("libGameEngine.so");
        const uint32_t render_thread_global = game_engine ? game_engine->GetBaseAddress() + 0x10C0328 : 0;
        const uint32_t render_thread_id_global = game_engine ? game_engine->GetBaseAddress() + 0x10C0338 : 0;
        const uint32_t active_scene_head_global = game_engine ? game_engine->GetBaseAddress() + 0x10E9BAC : 0;
        const uint32_t added_scene_data = game_engine ? game_engine->GetBaseAddress() + 0x10EBD30 : 0;
        const uint32_t added_scene_count = game_engine ? game_engine->GetBaseAddress() + 0x10EBD34 : 0;
        const uint32_t added_scene_capacity = game_engine ? game_engine->GetBaseAddress() + 0x10EBD38 : 0;
        const uint32_t do_open_scene_addr = game_engine ? game_engine->GetBaseAddress() + 0x10EBDC8 : 0;
        const uint32_t do_open_scene_name = game_engine ? game_engine->GetBaseAddress() + 0x10EB388 : 0;
        const uint32_t pending_scene_count = game_engine ? game_engine->GetBaseAddress() + 0x10EBB9C : 0;
        const uint32_t pending_scene_capacity = game_engine ? game_engine->GetBaseAddress() + 0x10EBBA0 : 0;
        const uint32_t pending_scene_data = game_engine ? game_engine->GetBaseAddress() + 0x10EBBA4 : 0;
        const uint32_t game_initialized = game_engine ? game_engine->GetBaseAddress() + 0x10E8B10 : 0;
        const uint32_t render_recursion = game_engine ? game_engine->GetBaseAddress() + 0x10E8B74 : 0;
        const uint32_t script_load_file = runtime->FindSymbol("_ZN13ScriptManager10smLoadFileE");
        const uint32_t script_recent_file = runtime->FindSymbol("_ZN13ScriptManager15sMostRecentFileE");
        const uint32_t script_state = runtime->FindSymbol("_ZN13ScriptManager17smpExecutingStateE");
        const uint32_t script_thread = runtime->FindSymbol("_ZN13ScriptManager18smpExecutingThreadE");
        const uint32_t async_load = runtime->FindSymbol("_ZN16AsyncLoadManager11smSingletonE");
        const uint32_t script_threads = game_engine ? game_engine->GetBaseAddress() + 0x10EB348 : 0;
        std::thread([runtime, frame_num, frame_time, actual_time, suspended, quit, window,
                     scale, next_time, fixed_time, tick_value, use_ticks, get_ticks,
                     render_enabled, render_reinit, render_delay, render_in_frame,
                     device_initialized, render_caps, device_width, device_height,
                     game_width, game_height, current_thread, render_target_fbo,
                     blit_target_fbo, global_obj_cache, render_thread_enable, scene_count,
                     render_thread_global, render_thread_id_global, active_scene_head_global,
                     game_initialized, render_recursion, added_scene_data, added_scene_count,
                     added_scene_capacity, do_open_scene_addr, do_open_scene_name, pending_scene_count,
                     pending_scene_capacity, pending_scene_data, script_load_file, script_recent_file,
                     script_state, script_thread, async_load, script_threads]() {
            for (int i = 0; i < 8; ++i) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                runtime->LogGuestExecution();
                auto read_float = [runtime](uint32_t address) {
                    uint32_t bits = address ? runtime->MemoryRead32(address) : 0;
                    float value = 0;
                    memcpy(&value, &bits, sizeof(value));
                    return value;
                };
                auto read_string = [runtime](uint32_t object) {
                    const uint32_t data = object ? runtime->MemoryRead32(object) : 0;
                    const uint32_t length = data ? runtime->MemoryRead32(data - 12) : 0;
                    if (!data || !length || length > 4096) return std::string{};
                    return std::string(reinterpret_cast<const char*>(runtime->GetGuestMemoryBase() + data), length);
                };
                const uint32_t render_thread = render_thread_global ? runtime->MemoryRead32(render_thread_global) : 0;
                const uint32_t render_index = render_thread ? runtime->MemoryRead32(render_thread + 400) : 0;
                const uint32_t render_slot = render_thread && render_index < 4
                    ? runtime->MemoryRead32(render_thread + 336 + render_index * 4) : 0;
                const uint32_t render_frame = render_slot ? runtime->MemoryRead32(render_slot + 68) : 0;
                const uint32_t render_views = render_frame ? runtime->MemoryRead32(render_frame + 28) : 0;
                LOGI("Game loop watch: frame=%u dt=%f actual=%f scale=%f next=%f fixed=%f tickBase=%u ticks=%u useTicks=%u suspended=%u quit=%u window=0x%08X",
                     frame_num ? runtime->MemoryRead32(frame_num) : 0,
                     read_float(frame_time), read_float(actual_time), read_float(scale), read_float(next_time), read_float(fixed_time),
                     tick_value ? runtime->MemoryRead32(tick_value) : 0,
                     get_ticks ? runtime->RunFunction(get_ticks) : 0,
                     use_ticks ? runtime->MemoryRead8(use_ticks) : 0,
                     suspended ? runtime->MemoryRead8(suspended) : 0,
                     quit ? runtime->MemoryRead8(quit) : 0,
                     window ? runtime->MemoryRead32(window) : 0);
                LOGI("Render watch: enabled=%u reinit=%u delay=%d inFrame=%u deviceInit=%u caps=0x%08X device=%ux%u game=%ux%u currentThread=%u targetFbo=%u blitFbo=%u objCache=0x%08X mt=%u renderThread=0x%08X busy=%u recursion=%u worker=%u",
                     render_enabled ? runtime->MemoryRead8(render_enabled) : 0,
                     render_reinit ? runtime->MemoryRead8(render_reinit) : 0,
                     render_delay ? static_cast<int32_t>(runtime->MemoryRead32(render_delay)) : 0,
                     render_in_frame ? runtime->MemoryRead8(render_in_frame) : 0,
                     device_initialized ? runtime->MemoryRead8(device_initialized) : 0,
                     render_caps ? runtime->MemoryRead32(render_caps) : 0,
                     device_width ? runtime->MemoryRead32(device_width) : 0,
                     device_height ? runtime->MemoryRead32(device_height) : 0,
                     game_width ? runtime->MemoryRead32(game_width) : 0,
                     game_height ? runtime->MemoryRead32(game_height) : 0,
                     current_thread ? runtime->MemoryRead32(current_thread) : 0,
                     render_target_fbo ? runtime->MemoryRead32(render_target_fbo) : 0,
                     blit_target_fbo ? runtime->MemoryRead32(blit_target_fbo) : 0,
                     global_obj_cache ? runtime->MemoryRead32(global_obj_cache) : 0,
                     render_thread_enable ? runtime->MemoryRead8(render_thread_enable) : 0,
                     render_thread,
                     render_thread ? runtime->MemoryRead32(render_thread + 432) : 0,
                     render_recursion ? runtime->MemoryRead32(render_recursion) : 0,
                     render_thread_id_global ? runtime->MemoryRead32(render_thread_id_global) : 0);
                const uint32_t added_data_ptr = added_scene_data ? runtime->MemoryRead32(added_scene_data) : 0;
                const uint32_t open_addr_data = do_open_scene_addr ? runtime->MemoryRead32(do_open_scene_addr) : 0;
                LOGI("Render graph: gameInit=%u scenes=%u sceneHead=0x%08X added=%u/%u data=0x%08X pending=%u/%u data=0x%08X doOpen='%s' name='%s' index=%u slot=0x%08X frame=0x%08X views=%u state=%u/%u/%u/%u/%u atomic=%u",
                     game_initialized ? runtime->MemoryRead8(game_initialized) : 0,
                     scene_count ? runtime->MemoryRead32(scene_count) : 0,
                     active_scene_head_global ? runtime->MemoryRead32(active_scene_head_global) : 0,
                     added_scene_count ? runtime->MemoryRead32(added_scene_count) : 0,
                     added_scene_capacity ? runtime->MemoryRead32(added_scene_capacity) : 0,
                     added_data_ptr,
                     pending_scene_count ? runtime->MemoryRead32(pending_scene_count) : 0,
                     pending_scene_capacity ? runtime->MemoryRead32(pending_scene_capacity) : 0,
                     pending_scene_data ? runtime->MemoryRead32(pending_scene_data) : 0,
                     read_string(do_open_scene_addr).c_str(), read_string(do_open_scene_name).c_str(),
                     render_index, render_slot, render_frame, render_views,
                     render_thread ? runtime->MemoryRead32(render_thread + 352) : 0,
                     render_thread ? runtime->MemoryRead32(render_thread + 364) : 0,
                     render_thread ? runtime->MemoryRead32(render_thread + 372) : 0,
                     render_thread ? runtime->MemoryRead32(render_thread + 376) : 0,
                     render_thread ? runtime->MemoryRead32(render_thread + 384) : 0,
                     render_thread ? runtime->MemoryRead32(render_thread + 424) : 0);
                const std::string load_file = read_string(script_load_file);
                const std::string recent_file = read_string(script_recent_file);
                const uint32_t async_object = async_load ? runtime->MemoryRead32(async_load) : 0;
                LOGI("Script watch: load='%s' recent='%s' state=0x%08X thread=0x%08X async=0x%08X threadList=0x%08X",
                     load_file.c_str(), recent_file.c_str(),
                     script_state ? runtime->MemoryRead32(script_state) : 0,
                     script_thread ? runtime->MemoryRead32(script_thread) : 0,
                     async_object, script_threads ? runtime->MemoryRead32(script_threads) : 0);
                LOGI("Async graph: stopping=%u main=%08X/%08X async=%08X/%08X/%08X",
                     async_object ? runtime->MemoryRead8(async_object) : 0,
                     async_object ? runtime->MemoryRead32(async_object + 8) : 0,
                     async_object ? runtime->MemoryRead32(async_object + 12) : 0,
                     async_object ? runtime->MemoryRead32(async_object + 16) : 0,
                     async_object ? runtime->MemoryRead32(async_object + 20) : 0,
                     async_object ? runtime->MemoryRead32(async_object + 24) : 0);
            }
        }).detach();
    }
#endif
    return true;
}

static uint32_t ObjectArg(JNIEnv* env, jobject object) {
    FakeJniEnv& fake = FakeJniEnv::Instance();
    fake.AttachHostEnv(env);
    return fake.AddObjectRef(object);
}
static uint32_t FloatArg(jfloat value) { uint32_t bits; memcpy(&bits, &value, sizeof(bits)); return bits; }
static uint32_t Low(jlong value) { return static_cast<uint32_t>(static_cast<uint64_t>(value)); }
static uint32_t High(jlong value) { return static_cast<uint32_t>(static_cast<uint64_t>(value) >> 32); }
static uint32_t Call(JNIEnv* env, jobject object, uint32_t symbol, std::vector<uint32_t> args = {}) {
    if (!EnsureGameLoaded(env) || !symbol) return 0;
    args.insert(args.begin(), ObjectArg(env, object));
    args.insert(args.begin(), FakeJniEnv::Instance().EnvTableGuestAddr());
    return g_host->RunFunction(symbol, args);
}

static void Native_nativeInit(JNIEnv* env, jclass cls) {
    LOGI("guest nativeInit enter");
    const uint32_t result = Call(env, cls, g_symbols.nativeInit);
    LOGI("guest nativeInit returned 0x%08X", result);
    if (g_host) ShutdownOpenSLES(g_host.get());
}
static jint Native_nativeAddJoystick(JNIEnv* env, jclass cls, jint id, jstring name, jstring desc,
                                     jint vendor, jint product, jint buttons, jint axes, jint hats) {
    return static_cast<jint>(Call(env, cls, g_symbols.nativeAddJoystick,
        {static_cast<uint32_t>(id), ObjectArg(env, name), ObjectArg(env, desc), static_cast<uint32_t>(vendor),
         static_cast<uint32_t>(product), static_cast<uint32_t>(buttons), static_cast<uint32_t>(axes), static_cast<uint32_t>(hats)}));
}
static void Native_nativeFlipBuffers(JNIEnv* env, jclass cls) { Call(env, cls, g_symbols.nativeFlipBuffers); }
static void Native_nativeLowMemory(JNIEnv* env, jclass cls) { Call(env, cls, g_symbols.nativeLowMemory); }
static void Native_nativePause(JNIEnv* env, jclass cls) {
    Call(env, cls, g_symbols.nativePause);
    if (g_host) PauseAudioPlayback(g_host.get());
}
static void Native_nativeQuit(JNIEnv* env, jclass cls) { Call(env, cls, g_symbols.nativeQuit); }
static jint Native_nativeRemoveJoystick(JNIEnv* env, jclass cls, jint id) { return Call(env, cls, g_symbols.nativeRemoveJoystick, {static_cast<uint32_t>(id)}); }
static void Native_nativeResume(JNIEnv* env, jclass cls) {
    if (g_host) ResumeAudioPlayback(g_host.get());
    // The guest transition owns unpause/unmute; pre-clearing its flag skips both.
    Call(env, cls, g_symbols.nativeResume);
}
static void Native_onNativeAccel(JNIEnv* env, jclass cls, jfloat x, jfloat y, jfloat z) { Call(env, cls, g_symbols.onNativeAccel, {FloatArg(x), FloatArg(y), FloatArg(z)}); }
static void Native_onNativeHat(JNIEnv* env, jclass cls, jint a, jint b, jint c, jint d) { Call(env, cls, g_symbols.onNativeHat, {(uint32_t)a,(uint32_t)b,(uint32_t)c,(uint32_t)d}); }
static void Native_onNativeJoy(JNIEnv* env, jclass cls, jint a, jint b, jfloat c) { Call(env, cls, g_symbols.onNativeJoy, {(uint32_t)a,(uint32_t)b,FloatArg(c)}); }
static void Native_onNativeKeyDown(JNIEnv* env, jclass cls, jint key) { Call(env, cls, g_symbols.onNativeKeyDown, {(uint32_t)key}); }
static void Native_onNativeKeyUp(JNIEnv* env, jclass cls, jint key) { Call(env, cls, g_symbols.onNativeKeyUp, {(uint32_t)key}); }
static void Native_onNativeKeyboardFocusLost(JNIEnv* env, jclass cls) { Call(env, cls, g_symbols.onNativeKeyboardFocusLost); }
static jint Native_onNativePadDown(JNIEnv* env, jclass cls, jint a, jint b) { return Call(env, cls, g_symbols.onNativePadDown, {(uint32_t)a,(uint32_t)b}); }
static jint Native_onNativePadUp(JNIEnv* env, jclass cls, jint a, jint b) { return Call(env, cls, g_symbols.onNativePadUp, {(uint32_t)a,(uint32_t)b}); }
static void Native_onNativeResize(JNIEnv* env, jclass cls, jint format, jint width, jint height) {
    Call(env, cls, g_symbols.onNativeResize, {(uint32_t)format,(uint32_t)width,(uint32_t)height});
}
static void Native_onNativeSurfaceChanged(JNIEnv* env, jclass cls) { Call(env, cls, g_symbols.onNativeSurfaceChanged); }
static void Native_onNativeSurfaceDestroyed(JNIEnv* env, jclass cls) { Call(env, cls, g_symbols.onNativeSurfaceDestroyed); }
static void Native_onNativeTouch(JNIEnv* env, jclass cls, jint a, jint b, jint c, jfloat x, jfloat y, jfloat p) {
    Call(env, cls, g_symbols.onNativeTouch, {(uint32_t)a,(uint32_t)b,(uint32_t)c,FloatArg(x),FloatArg(y),FloatArg(p)});
}
static void Native_nativeCommitText(JNIEnv* env, jobject obj, jstring text, jint cursor) {
    Call(env, obj, g_symbols.nativeCommitText, {ObjectArg(env, text), static_cast<uint32_t>(cursor)});
}
static void Native_nativeSetComposingText(JNIEnv* env, jobject obj, jstring text, jint cursor) {
    Call(env, obj, g_symbols.nativeSetComposingText, {ObjectArg(env, text), static_cast<uint32_t>(cursor)});
}
static jlong Native_fmodGetSize(JNIEnv* env, jclass cls, jlong codec) {
    const uint32_t lo = Call(env, cls, g_symbols.fmodGetSize, {Low(codec), High(codec)});
    return static_cast<jlong>((static_cast<uint64_t>(g_host->GetResultHigh()) << 32) | lo);
}
static jint Native_fmodReadAt(JNIEnv* env, jclass cls, jlong codec, jlong offset, jbyteArray data, jint size) {
    return static_cast<jint>(Call(env, cls, g_symbols.fmodReadAt,
        {Low(codec), High(codec), Low(offset), High(offset), ObjectArg(env, data), static_cast<uint32_t>(size)}));
}
static void Native_nativeOnPurchaseComplete(JNIEnv* env, jclass cls, jstring sku, jboolean ok, jstring token) {
    Call(env, cls, g_symbols.nativeOnPurchaseComplete, {ObjectArg(env, sku), static_cast<uint32_t>(ok), ObjectArg(env, token)});
}
static void Native_nativeOnPermissionComplete(JNIEnv* env, jclass cls, jint permission, jboolean granted) {
    Call(env, cls, g_symbols.nativeOnPermissionComplete,
         {static_cast<uint32_t>(permission), static_cast<uint32_t>(granted)});
}

static const JNINativeMethod kSdlMethods[] = {
    {"nativeAddJoystick", "(ILjava/lang/String;Ljava/lang/String;IIIII)I", (void*)Native_nativeAddJoystick},
    {"nativeFlipBuffers", "()V", (void*)Native_nativeFlipBuffers}, {"nativeInit", "()V", (void*)Native_nativeInit},
    {"nativeLowMemory", "()V", (void*)Native_nativeLowMemory}, {"nativePause", "()V", (void*)Native_nativePause},
    {"nativeQuit", "()V", (void*)Native_nativeQuit}, {"nativeRemoveJoystick", "(I)I", (void*)Native_nativeRemoveJoystick},
    {"nativeResume", "()V", (void*)Native_nativeResume}, {"onNativeAccel", "(FFF)V", (void*)Native_onNativeAccel},
    {"onNativeHat", "(IIII)V", (void*)Native_onNativeHat}, {"onNativeJoy", "(IIF)V", (void*)Native_onNativeJoy},
    {"onNativeKeyDown", "(I)V", (void*)Native_onNativeKeyDown}, {"onNativeKeyUp", "(I)V", (void*)Native_onNativeKeyUp},
    {"onNativeKeyboardFocusLost", "()V", (void*)Native_onNativeKeyboardFocusLost},
    {"onNativePadDown", "(II)I", (void*)Native_onNativePadDown}, {"onNativePadUp", "(II)I", (void*)Native_onNativePadUp},
    {"onNativeResize", "(III)V", (void*)Native_onNativeResize},
    {"onNativeSurfaceChanged", "()V", (void*)Native_onNativeSurfaceChanged},
    {"onNativeSurfaceDestroyed", "()V", (void*)Native_onNativeSurfaceDestroyed},
    {"onNativeTouch", "(IIIFFF)V", (void*)Native_onNativeTouch},
};
static const JNINativeMethod kInputMethods[] = {
    {"nativeCommitText", "(Ljava/lang/String;I)V", (void*)Native_nativeCommitText},
    {"nativeSetComposingText", "(Ljava/lang/String;I)V", (void*)Native_nativeSetComposingText},
};
static const JNINativeMethod kCodecMethods[] = {
    {"fmodGetSize", "(J)J", (void*)Native_fmodGetSize}, {"fmodReadAt", "(JJ[BI)I", (void*)Native_fmodReadAt},
};
static const JNINativeMethod kTelltaleMethods[] = {
    {"nativeOnPermissionComplete", "(IZ)V", (void*)Native_nativeOnPermissionComplete},
    {"nativeOnPurchaseComplete", "(Ljava/lang/String;ZLjava/lang/String;)V", (void*)Native_nativeOnPurchaseComplete},
};

static bool RegisterTable(JNIEnv* env, const char* name, const JNINativeMethod* methods, jint count) {
    jclass cls = env->FindClass(name);
    if (!cls) { env->ExceptionClear(); LOGE("Class not found: %s", name); return false; }
    if (env->RegisterNatives(cls, methods, count) != JNI_OK) {
        if (env->ExceptionCheck()) { env->ExceptionDescribe(); env->ExceptionClear(); }
        LOGE("RegisterNatives failed: %s", name); return false;
    }
    LOGI("Registered %d natives on %s", count, name);
    return true;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_jvm = vm;
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    if (!RegisterTable(env, portcfg::kSdlActivityClass, kSdlMethods, std::size(kSdlMethods)) ||
        !RegisterTable(env, portcfg::kSdlInputClass, kInputMethods, std::size(kInputMethods)) ||
        !RegisterTable(env, portcfg::kFmodMediaCodecClass, kCodecMethods, std::size(kCodecMethods)) ||
        !RegisterTable(env, portcfg::kTelltaleActivityClass, kTelltaleMethods, std::size(kTelltaleMethods))) {
        return JNI_ERR;
    }
    LOGI("JNI_OnLoad: ARM64 Telltale host registered 26 guest natives");
    return JNI_VERSION_1_6;
}
