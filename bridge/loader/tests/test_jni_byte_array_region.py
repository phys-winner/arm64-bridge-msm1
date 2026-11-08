"""Source guard for the AAPCS32/JNI SetByteArrayRegion bridge."""
from pathlib import Path


source = (Path(__file__).resolve().parents[1] / "src/jni_fake_env.cpp").read_text(
    encoding="utf-8"
)
body = source.split("case 832: { // SetByteArrayRegion", 1)[1].split(
    "// ---- strings", 1
)[0]

assert "MemoryRead32(sp)" in body, "the fifth JNI argument must be read from the guest stack"
assert "GetArrayLength(array)" in body
assert "start > array_length" in body and "length > array_length - start" in body
assert "GuestRangeValid" in body
assert "SetByteArrayRegion(array, start, length" in body

vm_dispatch = source.split("void FakeJniEnv::DispatchVmSlot", 1)[1].split(
    "void FakeJniEnv::DispatchEnvSlot", 1
)[0]
assert 'LOGI("[JNI-VM] slot ' not in vm_dispatch

print("JNI SetByteArrayRegion bridge checks: PASS")
