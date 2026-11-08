#!/usr/bin/env python3
"""Remove MCSM's 720p Surface framebuffer cap in the ARM32 guest engine.

Application_SDL::ScaleScreen reads the Android display width/height into
lr/r12. The original arithmetic at 0x57db9c..0x57dbf4 caps height to 720
and scales width before calling setFramebufferSize and storing the global
render dimensions. A branch to 0x57dbf8 uses the original display dimensions
for both operations. The rest of ScaleScreen, including DPI setup, runs.
"""
from __future__ import annotations

import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GUEST = ROOT / "app/assets/guestlib/armeabi-v7a/libGameEngine.so"
BACKUP = ROOT / "work/tmp/libGameEngine.before_full_resolution.so"
ORIGINAL_SHA256 = "49fb717eb6336a532b511eaf1d93477c751e2cefa5c1e42f14a1b41a0441ff3d"
PATCH_OFFSET = 0x57DB9C
OLD = bytes.fromhex("90ca07ee")  # vmov s15, r12
NEW = bytes.fromhex("150000ea")  # b 0x57dbf8


def main() -> None:
    data = GUEST.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != ORIGINAL_SHA256:
        raise RuntimeError(f"unexpected guest SHA-256: {digest}")
    if data[PATCH_OFFSET:PATCH_OFFSET + 4] != OLD:
        raise RuntimeError("ScaleScreen instruction differs from verified source")
    if BACKUP.exists() and BACKUP.read_bytes() != data:
        raise RuntimeError("existing full-resolution backup differs from guest")
    if not BACKUP.exists():
        BACKUP.parent.mkdir(parents=True, exist_ok=True)
        BACKUP.write_bytes(data)
    patched = bytearray(data)
    patched[PATCH_OFFSET:PATCH_OFFSET + 4] = NEW
    GUEST.write_bytes(patched)
    print(f"patched {GUEST} offset=0x{PATCH_OFFSET:X} sha256={hashlib.sha256(patched).hexdigest()}")


if __name__ == "__main__":
    main()
