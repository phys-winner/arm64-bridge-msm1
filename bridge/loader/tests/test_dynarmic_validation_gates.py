"""Production defaults for expensive Dynarmic translation-time validation."""

from pathlib import Path
import re


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

    option = re.search(
        r"option\(ARM32_BRIDGE_ENABLE_DYNARMIC_VALIDATION\s+"
        r'"[^"]+"\s+(ON|OFF)\)',
        cmake,
    )
    assert option and option.group(1) == "OFF"

    cmake_gate = cmake.split(
        "if(ARM32_BRIDGE_ENABLE_DYNARMIC_VALIDATION)", 1
    )[1].split("endif()", 1)[0]
    assert "target_compile_definitions(dynarmic PRIVATE" in cmake_gate
    assert "DYNARMIC_ENABLE_JIT_VALIDATION=1" in cmake_gate
    assert cmake.count("DYNARMIC_ENABLE_JIT_VALIDATION=1") == 1
    assert "DYNARMIC_IGNORE_ASSERTS" not in cmake

    assert "[switch]$EnableDynarmicValidation" in build_script
    assert (
        "$DynarmicValidationEnabled = if ($EnableDynarmicValidation) { 'ON' } "
        "else { 'OFF' }"
    ) in build_script
    assert (
        '"-DARM32_BRIDGE_ENABLE_DYNARMIC_VALIDATION=$DynarmicValidationEnabled"'
        in build_script
    )

    guard = "+#if defined(DYNARMIC_ENABLE_JIT_VALIDATION)"
    assert patch.count(guard) == 3
    for call in (
        "Optimization::VerificationPass(ir_block);",
        "reg_alloc.AssertAllUnlocked();",
        "reg_alloc.AssertNoMoreUses();",
    ):
        call_at = patch.index(call)
        guard_at = patch.rfind(guard, 0, call_at)
        end_at = patch.find("+#endif", call_at)
        assert guard_at >= 0 and end_at > call_at, call

    print("Dynarmic production validation gates: PASS")


if __name__ == "__main__":
    main()
