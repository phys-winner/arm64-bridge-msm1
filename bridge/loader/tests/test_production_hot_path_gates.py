"""Source guards for production diagnostic gates and dense thunk dispatch."""
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def main():
    heap = (SRC / "dynarmic_host.cpp").read_text(encoding="utf-8")
    run_function = heap.split("uint32_t DynarmicHost::RunFunction", 1)[1].split(
        "void DynarmicHost::InvalidateGuestCode", 1
    )[0]
    before_run = run_function.split("hr = jit.Run();", 1)[0]
    after_run = run_function.split("hr = jit.Run();", 1)[1]
    cache_clear = "jit.ClearHalt(Dynarmic::HaltReason::CacheInvalidation);"
    assert cache_clear not in before_run
    assert cache_clear in after_run

    guest_free = heap.split("void DynarmicHost::GuestFree", 1)[1].split(
        "size_t DynarmicHost::GuestAllocSize", 1
    )[0]
    for counter in ("ignored", "freed"):
        pattern = (
            r"#if ARM32_BRIDGE_ENABLE_HEAP_DIAGNOSTICS"
            r"(?:(?!#endif).)*static std::atomic<uint32_t> " + counter + r"\{0\};"
            r"(?:(?!#endif).)*#endif"
        )
        assert re.search(pattern, guest_free, re.DOTALL), counter

    libc = (SRC / "thunks_libc.cpp").read_text(encoding="utf-8")
    assert '#include "game_port_config.h"' in libc
    assert re.search(
        r"#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS\s+"
        r"static std::atomic<uint32_t> g_path_trace_count\{0\};.*?"
        r"#define PATH_DIAG_LOGI.*?#else\s+"
        r"#define PATH_DIAG_LOGI\(\.\.\.\) \(\(void\)0\)",
        libc,
        re.DOTALL,
    )
    assert "if (TracePathCall())" not in libc.replace(
        "#define PATH_DIAG_LOGI(...) do { if (TracePathCall())", ""
    )
    virtual_fd = libc.split("struct VirtualFd", 1)[1].split("};", 1)[0]
    assert re.search(
        r"#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS\s+"
        r"uint32_t trace_count = 0;\s+#endif",
        virtual_fd,
    )
    for message in (
        "ApkRead:",
        "IndexApk: replacing packaged entry",
        "IndexApk entry",
        "IndexApk: Indexed",
        "fopen: APK direct stream opened",
        "open: APK direct stream opened",
        "mmap: fd=",
    ):
        line = next(line for line in libc.splitlines() if message in line)
        assert "VFS_DIAG_LOGI" in line, line
    assert libc.count("PATH_DIAG_LOGI(") >= 10
    for message in ('LOGI("read vfd=', 'LOGI("pread vfd='):
        position = libc.index(message)
        gate = libc.rfind("#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS", 0, position)
        assert gate >= 0 and libc.find("#endif", gate) > position, message

    header = (SRC / "thunk_manager.h").read_text(encoding="utf-8")
    manager = (SRC / "thunk_manager.cpp").read_text(encoding="utf-8")
    assert "std::vector<ThunkHandler> m_id_to_handler;" in header
    assert "std::unordered_map<uint32_t, ThunkHandler> m_id_to_handler;" not in header
    assert "m_id_to_handler.reserve(1024);" in manager
    assert "m_id_to_handler.push_back(std::move(handler));" in manager
    assert "m_id_to_handler.find(thunk_id)" not in manager
    assert "static_cast<size_t>(thunk_id - 1)" in manager
    assert "m_id_to_handler[handler_index](jit, m_host);" in manager
    assert "m_id_to_name.find(thunk_id)" in manager

    print("Production hot-path gates and dense thunk dispatch: PASS")


if __name__ == "__main__":
    main()
