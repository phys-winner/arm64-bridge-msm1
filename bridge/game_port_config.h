#pragma once

// Minecraft: Story Mode 1.37 (Mali) guest configuration.
// Game-specific behavior is enabled here; hooks live behind config gates in the shared Telltale loader.
#define ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS 0
#define ARM32_BRIDGE_REDIRECT_EXTERNAL_STORAGE_TO_APP_FILES 1
#define ARM32_BRIDGE_ENABLE_PERMISSION_NATIVE 1
#define ARM32_BRIDGE_ENABLE_MCSM_HIDE_BORDER_OVERRIDE 1
#define ARM32_BRIDGE_ENABLE_MCSM_RESOURCE_HOOKS 1
#define ARM32_BRIDGE_ENABLE_MCSM_WIDESCREEN_OVERRIDE 1
#define ARM32_BRIDGE_ENABLE_TOUCH_DIAGNOSTICS 0
#define ARM32_BRIDGE_ENABLE_TELLTALE_DIAGNOSTIC_PROBES 0
#define ARM32_BRIDGE_ENABLE_HEAP_DIAGNOSTICS 0
#define ARM32_BRIDGE_ENABLE_RUNTIME_WATCHDOG 0
#define ARM32_BRIDGE_ENABLE_AUDIO_DIAGNOSTICS 0
#define ARM32_BRIDGE_ENABLE_TELLTALE_ZLIB_ACCELERATION 0
#define ARM32_BRIDGE_ENABLE_TELLTALE_ZLIB_DIAGNOSTICS 0
#define ARM32_BRIDGE_ENABLE_TELLTALE_ADD_CALLBACK_ACCELERATION 0
#define ARM32_BRIDGE_ENABLE_TELLTALE_ADD_CALLBACK_INDEX 0
#define ARM32_BRIDGE_ENABLE_TELLTALE_GET_KEY_INFO_ACCELERATION 0
#define ARM32_BRIDGE_ENABLE_TELLTALE_PROPERTYSET_DIAGNOSTICS 0
#define ARM32_BRIDGE_ENABLE_GL_SHADER_DIAGNOSTICS 0

#include <array>

namespace portcfg {
inline constexpr const char* kPackageName = "com.telltalegames.minecraft100";
inline constexpr const char* kSdlActivityClass = "org/libsdl/app/SDLActivity";
inline constexpr const char* kSdlInputClass = "org/libsdl/app/SDLInputConnection";
inline constexpr const char* kFmodMediaCodecClass = "org/fmod/MediaCodec";
inline constexpr const char* kTelltaleActivityClass = "com/telltalegames/telltale/TelltaleActivity";
inline constexpr std::array<const char*, 5> kGuestModules = {
    "libSDL2.so",
    "libfmod.so",
    "libfmodstudio.so",
    "libGameEngine.so",
    "libmain.so",
};
inline constexpr const char* kGuestAssetPrefix = "assets/guestlib/armeabi-v7a/";
}
