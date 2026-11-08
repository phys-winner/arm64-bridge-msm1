# ARM64 bridge for Minecraft: Story Mode — Season One

A source-only ARM32-to-ARM64 compatibility bridge for **Minecraft: Story Mode,
Season One, Android 1.37 (Mali)**. It runs the original ARMv7 native libraries
inside an `arm64-v8a` Android process using Dynarmic's A32 JIT. Host thunks handle
OpenGL ES, JNI, Android services, libc and OpenSL ES calls. This is a game-specific
restoration project, not a general Android emulator.

**GitHub description:** ARM32-to-ARM64 Android bridge for Minecraft: Story Mode S1, powered by Dynarmic, with restoration and packaging scripts.

## Contents

- `bridge/loader/src/`: ELF loading, guest memory, JIT integration, JNI and host thunks.
- `bridge/game_port_config.h`: package, guest module list and Minecraft feature gates.
- `bridge/loader/patches/dynarmic/`: JIT changes applied to a build-directory copy of upstream sources.
- `bridge/loader/tests/`: source checks and native loader/qsort tests.
- `work/tools/`: input analysis, guarded patches, APK packaging and static verification.
- `work/source_inputs.json` and `work/episode_assignment.json`: input identity locks and packaging assignments required by the scripts; metadata only.

Game APKs, guest libraries, episode archives, OBBs, decoded app sources, textures,
saves, keys, SDK tools and dependency sources are not distributed here. Supply
your own legally obtained game files. No game download links or tool binaries
are included.

## Status and limitations

Historical tests cover menus and limited gameplay. Complete Episodes 1–8
acceptance, long sessions, saves, audio, lifecycle transitions, graphics and input
coverage remain incomplete. Hardware Back followed by re-entry has previously
produced a black screen; a fresh launch recovered the title.

The build enforces at least 16 KiB ELF LOAD alignment. This static property does
not establish runtime compatibility with 16 KiB devices. These sources have not
passed a complete game acceptance run.

The bridge builds independently. Packaging requires an externally prepared,
compatible decoded app and split scaffolds. A fresh clone does not reconstruct
all Java, resource and manifest integration changes. The original base cache
and Episode 2–8 ZIPs are currently unavailable in the maintainer's workspace,
so a complete APK set has not been rebuilt for this source publication. The
original input hashes are preserved.

## External dependencies

The current build scripts target **Windows with PowerShell**:

- Git and Python 3.10 or newer; Python scripts use the standard library.
- Android SDK, NDK **27.2.12479018**, SDK CMake **3.22.1** and Ninja.
- Boost **1.83.0** headers from an [official release archive](https://archives.boost.io/release/1.83.0/source/). The selected root must contain `boost/version.hpp`.
- [Dynarmic](https://github.com/azahar-emu/dynarmic) at `e77b1ba0b7da7cbe93021b01a663acfe7c4dd516`, with recursive submodules. Its dependencies, including fmt, mcl and oaknut, stay in that external checkout. Cross-compilation uses the bundled upstream dependencies.

Prepare Dynarmic outside this repository:

```powershell
git clone --no-checkout https://github.com/azahar-emu/dynarmic.git ../dynarmic
git -C ../dynarmic checkout e77b1ba0b7da7cbe93021b01a663acfe7c4dd516
git -C ../dynarmic submodule update --init --recursive
```

The checkout must be clean and at the exact revision above. Configure and build
run offline once dependencies are present. The patch is applied to a generated
copy, leaving the external checkout unchanged. Keep the checkout outside the
selected build directory. Use a short build path on Windows to avoid Ninja
path-length limits.

## Build

Run from the repository root. This example assumes dependencies in sibling
directories and the SDK in its standard Windows location. Set `ANDROID_SDK_ROOT`
or pass `-SdkRoot` for another SDK location.

```powershell
./bridge/loader/build_arm64.ps1 `
  -GameConfigDir "$PWD/bridge" `
  -DynarmicSourceDir "$PWD/../dynarmic" `
  -BoostSourceDir "$PWD/../boost_1_83_0" `
  -BuildDirectory "$env:TEMP/msm1-build" `
  -OutputDirectory "$PWD/out/bridge"
```

Alternatively, set `DYNARMIC_SOURCE_DIR` and `BOOST_ROOT`. The default output is
`libmain.so`, built for `arm64-v8a` and Android API 26. The script checks
ELF64/AArch64 and segment alignment. Logging, JIT perf maps and expensive
Dynarmic validation default to OFF. Diagnostic switches are `-EnableLogging`,
`-EnableJitPerfMap` and `-EnableDynarmicValidation`.

## Integration and game tooling

The app's Java side loads the host library as `main`. Original ARMv7 libraries
listed in `game_port_config.h` belong under `assets/guestlib/armeabi-v7a/`; the
ARM64 bridge belongs under `lib/arm64-v8a/`. Java classes and native signatures
must match the bridge's JNI registration. Replacing one library in an arbitrary
APK is insufficient.

The scripts retain the workspace layout:

- `original/`: the APK and eight exact cache ZIPs listed in `work/source_inputs.json`.
- `app/`: externally prepared decoded base, original guest libraries and integrated bridge.
- `splits/`: episode and optional split scaffolds for `package_cache_apks.py`.
- `tools/android/`: optional tool layout; alternatively set `ANDROID_TOOL_ROOT` to an external directory containing `apktool.jar` and `sdk/build-tools/36.1.0/` with `aapt2.exe` and `zipalign.exe`.
- `out/`, `work/tmp/` and `work/logs/`: ignored outputs and diagnostics.

APK tooling also needs Java, apktool and Android build-tools. Set `JAVA_EXE` to
the Java executable, or use Java on PATH. Set `ANDROID_SIGNING_DIR` to an external
directory containing `apksigner.jar`, `testkey.pk8` and `testkey.x509.pem`. Keys
and certificates stay outside Git. Set `MCSM_SIGNER_SHA256` to the expected
certificate SHA-256 fingerprint for your own signer; the default is the historical
public Android test certificate fingerprint. Every APK in one install set must
use the same signer. A different signer can prevent updates over an existing install.

From a fully prepared workspace:

```powershell
python -B work/tools/package_cache_apks.py --output-dir out/rebuild --logs-dir work/logs/rebuild
python -B work/tools/verify_mcsm_release_set.py --release-dir out/rebuild
```

Use `--help` on packaging commands for explicit tool and input parameters.
`apk_build.py` is a separate incremental packager expecting `app/splits/`, unlike
the root-level `splits/` used above. `patch_full_resolution.py` and
`patch_boot_offline.py` accept exact original preimages and reject mismatches;
do not reapply them to patched inputs. Analysis scripts operate on local files.

## Checks

These Python checks need neither game payloads nor an Android device:

```powershell
Get-ChildItem bridge/loader/tests/test_*.py | ForEach-Object {
  python -B $_.FullName
  if ($LASTEXITCODE -ne 0) { throw "Check failed: $($_.Name)" }
}
python -B work/tools/test_package_cache_apks.py
python -B work/tools/test_publication_settings.py
```

CMake targets `guest_qsort_test` and `elf_loader_test` are Android executables,
excluded from the default build; running them requires an appropriate device.
Source checks and static APK verification do not prove gameplay correctness.
Use `bridge/loader/check_symbols.py --help` for guest import coverage and
`memcheck.sh` for memory sampling of a debuggable app. Pass device selection via
`DEV`; never hardcode a device serial in tracked source.

## License

Original bridge code and project scripts are licensed under **GPL-3.0-or-later**.
[LICENSE](LICENSE) contains GNU GPL version 3. You may choose that version or any
later version published by the Free Software Foundation.

External dependencies retain their own licenses: Dynarmic uses 0BSD, Boost uses
the Boost Software License 1.0, and Dynarmic submodules retain their respective
notices. The included patch modifies 0BSD-licensed Dynarmic code; retain its
upstream notice with the patched dependency. No license to proprietary game code,
assets or trademarks is granted.

Minecraft and Minecraft: Story Mode belong to their respective owners. This
unofficial project is not affiliated with or endorsed by Mojang, Microsoft or Telltale.
