"""Source guards for ARM32_BRIDGE_ENABLE_LOGGING option and ((void)0) fallback."""
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def main():
    cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    build_script = (ROOT / "build_arm64.ps1").read_text(encoding="utf-8")

    option = re.search(
        r"option\(ARM32_BRIDGE_ENABLE_LOGGING\s+"
        r'"[^"]+"\s+(ON|OFF)\)',
        cmake,
    )
    assert option and option.group(1) == "OFF", "ARM32_BRIDGE_ENABLE_LOGGING must default to OFF"
    assert "ARM32_BRIDGE_ENABLE_LOGGING=$<BOOL:${ARM32_BRIDGE_ENABLE_LOGGING}>" in cmake

    assert "[switch]$EnableLogging" in build_script
    assert "-DARM32_BRIDGE_ENABLE_LOGGING=$LoggingEnabled" in build_script

    cpp_files = [
        "dynarmic_host.cpp",
        "elf_loader.cpp",
        "jni_bridge.cpp",
        "jni_fake_env.cpp",
        "telltale_addcallback_fastpath.cpp",
        "telltale_propertyset_fastpath.cpp",
        "thunk_manager.cpp",
        "thunks_android.cpp",
        "thunks_gl.cpp",
        "thunks_gl_gles2_core.cpp",
        "thunks_libc.cpp",
        "thunks_opensles.cpp",
    ]

    for fname in cpp_files:
        content = (SRC / fname).read_text(encoding="utf-8")
        assert "#if ARM32_BRIDGE_ENABLE_LOGGING" in content, f"{fname} missing #if ARM32_BRIDGE_ENABLE_LOGGING"
        assert "#define LOGE(...) ((void)0)" in content, f"{fname} missing LOGE ((void)0)"
        if fname != "thunks_gl_gles2_core.cpp":
            assert "#define LOGI(...) ((void)0)" in content, f"{fname} missing LOGI ((void)0)"

    print("ARM32_BRIDGE_ENABLE_LOGGING definition and fallback checks: PASS")


if __name__ == "__main__":
    main()
