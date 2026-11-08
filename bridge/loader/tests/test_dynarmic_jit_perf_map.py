"""Source-level guards for the optional ARM64 Dynarmic perf-map diagnostic."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main():
    cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    build_script = (ROOT / "build_arm64.ps1").read_text(encoding="utf-8")
    patch = (
        ROOT
        / "patches"
        / "dynarmic"
        / "0001-arm64-a32-limit-prelude-icache-invalidation.patch"
    ).read_text(encoding="utf-8")

    assert "option(ARM32_BRIDGE_ENABLE_JIT_PERF_MAP" in cmake
    assert 'ARM32_BRIDGE_JIT_PERF_MAP_DIRECTORY "/data/local/tmp"' in cmake
    assert "DYNARMIC_ENABLE_ARM64_PERF_MAP=1" in cmake
    assert "DYNARMIC_ARM64_PERF_MAP_DIRECTORY" in cmake
    assert "[switch]$EnableJitPerfMap" in build_script
    assert "[string]$JitPerfMapDirectory = '/data/local/tmp'" in build_script

    assert "#if defined(DYNARMIC_ENABLE_ARM64_PERF_MAP)" in patch
    assert '"%s/perf-%d.map"' in patch
    assert '"0x%016" PRIxPTR " 0x%zx %s\\n"' in patch
    assert '"dynarmic_a32_prelude"' in patch
    assert '"dynarmic_a32_%c_%08" PRIx32 "_d%016" PRIx64' in patch
    assert "PerfMapRegister(block_info.entry_point, block_info.size" in patch
    assert "perf_map_registration_count % 64 == 0" in patch

    print("Optional ARM64 Dynarmic JIT perf-map diagnostic: PASS")


if __name__ == "__main__":
    main()
