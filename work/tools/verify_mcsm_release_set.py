from __future__ import annotations

import hashlib
import argparse
import json
from pathlib import Path
import re
import subprocess
import zipfile
import zlib


from apk_build import JAVA, SIGN_ROOT, TOOL_ROOT, EXPECTED_CERT as CERT_SHA256

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "com.telltalegames.minecraft100"
VERSION_CODE = "10137"
VERSION_NAME = "1.37"
EXPECTED_HIDE_ASSETS = {
    "assets/telltale/files/Net/ui_vignette1.d3dtx",
    "assets/telltale/files/Net/ui_vignette2.d3dtx",
}
WIDESCREEN_MARKER_ASSET = "assets/telltale/widescreen.enable"
WIDESCREEN_MARKER_BYTES = b"widescreen\n"
OFFLINE_BOOT_PATCH_ASSET = "assets/telltale/obb/patch.10135.com.telltalegames.minecraft100.obb"
OFFLINE_BOOT_PATCH_ORIGINAL_CRC32 = "513ded75"
OFFLINE_BOOT_PATCH_SHA256 = "c878df1745984e827f2903158257b45258a3a06cf91b569f0817e2bbcbadec55"
SIGNER = SIGN_ROOT / "apksigner.jar"
AAPT2 = TOOL_ROOT / "sdk" / "build-tools" / "36.1.0" / "aapt2.exe"
ZIPALIGN = TOOL_ROOT / "sdk" / "build-tools" / "36.1.0" / "zipalign.exe"


def run(argv: list[str]) -> str:
    result = subprocess.run(argv, cwd=ROOT, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True,
                            errors="replace", shell=False, check=False)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {argv[0]}\n{result.stdout}")
    return result.stdout


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Statically verify a Minecraft: Story Mode cache APK release set.")
    parser.add_argument("--release-dir", type=Path,
                        default=ROOT / "out" / "mcsm_bridge_candidate_003")
    release = parser.parse_args().release_dir.resolve()
    if not release.is_relative_to(ROOT):
        raise RuntimeError(f"release directory must remain inside the project: {release}")
    split_dir = release / "cache_splits"
    assignment = json.loads((ROOT / "work" / "episode_assignment.json").read_text(encoding="utf-8"))
    groups = assignment["package_groups"]
    apks = {"base": release / "base.apk"}
    for episode in range(2, 9):
        group = f"split_episode_{episode:02d}"
        apks[group] = split_dir / f"{group}.apk"
    apks["hide_border"] = split_dir / "split_hide_border.apk"
    apks["widescreen"] = split_dir / "split_widescreen.apk"
    if set(groups) != set(apks) - {"hide_border", "widescreen"}:
        raise RuntimeError("release APK group list does not match the locked episode assignment")

    for dependency in (JAVA, SIGNER, AAPT2, ZIPALIGN):
        if not dependency.is_file():
            raise RuntimeError(f"required verification tool missing: {dependency}")

    results = []
    total_payload_bytes = 0
    for group, apk in apks.items():
        if not apk.is_file():
            raise RuntimeError(f"release APK missing: {apk}")
        with zipfile.ZipFile(apk, "r") as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            if len(names) != len(set(names)):
                raise RuntimeError(f"duplicate ZIP entry in {apk.name}")
            if any(entry.file_size >= 2**31 for entry in entries):
                raise RuntimeError(f"entry exceeds signed 32-bit limit in {apk.name}")
            assets = {entry.filename: entry for entry in entries
                      if entry.filename.startswith("assets/telltale/")}
            if group == "hide_border":
                hide_payloads = {}
                expected = {}
                for asset in EXPECTED_HIDE_ASSETS:
                    hide_bytes = (ROOT / "splits" / "hide_border" / asset).read_bytes()
                    if len(hide_bytes) != 131339 or hide_bytes[:4] != b"5VSM" or any(hide_bytes[267:]):
                        raise RuntimeError(f"hide-border texture is not a transparent MCSM 1.37 D3DTX: {asset}")
                    hide_payloads[asset] = hide_bytes
                    expected[asset] = {
                        "size_bytes": len(hide_bytes),
                        "crc32": f"{zlib.crc32(hide_bytes) & 0xFFFFFFFF:08x}",
                        "source_sha256": hashlib.sha256(hide_bytes).hexdigest(),
                    }
                split_name = "split_hide_border"
            elif group == "widescreen":
                expected = {WIDESCREEN_MARKER_ASSET: {
                    "size_bytes": len(WIDESCREEN_MARKER_BYTES),
                    "crc32": f"{zlib.crc32(WIDESCREEN_MARKER_BYTES) & 0xFFFFFFFF:08x}",
                }}
                split_name = "split_widescreen"
            else:
                expected = {row["asset_path"]: row for row in assignment["assignments"]
                            if row["package_group"] == group}
                split_name = "" if group == "base" else group
            if set(assets) != set(expected):
                raise RuntimeError(f"asset set mismatch in {apk.name}: "
                                   f"missing={sorted(set(expected)-set(assets))}, "
                                   f"extra={sorted(set(assets)-set(expected))}")
            payload_bytes = 0
            for asset, row in expected.items():
                entry = assets[asset]
                if entry.compress_type != zipfile.ZIP_STORED:
                    raise RuntimeError(f"cache asset is compressed: {apk.name}:{asset}")
                expected_crc = int(row["crc32"], 16)
                if group == "base" and asset == OFFLINE_BOOT_PATCH_ASSET:
                    if row["crc32"] != OFFLINE_BOOT_PATCH_ORIGINAL_CRC32:
                        raise RuntimeError("locked original offline boot patch CRC changed")
                    patched_bytes = (ROOT / "app" / asset).read_bytes()
                    if hashlib.sha256(patched_bytes).hexdigest() != OFFLINE_BOOT_PATCH_SHA256:
                        raise RuntimeError("reviewed offline boot patch source changed")
                    expected_crc = zlib.crc32(patched_bytes) & 0xFFFFFFFF
                    if archive.read(asset) != patched_bytes:
                        raise RuntimeError("base APK offline boot patch differs from reviewed source")
                if entry.file_size != row["size_bytes"] or entry.CRC != expected_crc:
                    raise RuntimeError(f"cache asset size/CRC mismatch: {apk.name}:{asset}")
                if group == "hide_border" and archive.read(asset) != hide_payloads[asset]:
                    raise RuntimeError("hide-border APK payload differs from the reviewed source asset")
                if group == "widescreen" and archive.read(asset) != WIDESCREEN_MARKER_BYTES:
                    raise RuntimeError("widescreen marker differs from the reviewed bytes")
                payload_bytes += entry.file_size

        badging = run([str(AAPT2), "dump", "badging", str(apk)])
        identity = (f"package: name='{PACKAGE}' versionCode='{VERSION_CODE}' "
                    f"versionName='{VERSION_NAME}'")
        if split_name:
            identity += f" split='{split_name}'"
        if identity not in badging:
            raise RuntimeError(f"package/version/split identity mismatch in {apk.name}")
        xmltree = run([str(AAPT2), "dump", "xmltree", str(apk),
                       "--file", "AndroidManifest.xml"])
        if group != "base" and ("hasCode" not in xmltree or "false" not in xmltree):
            raise RuntimeError(f"hasCode=false missing in {apk.name}")
        if group != "base" and re.search(r"classes(?:\d+)?\.dex", "\n".join(names)):
            raise RuntimeError(f"code-free cache package contains DEX: {apk.name}")

        signature = run([str(JAVA), "-jar", str(SIGNER), "verify", "--verbose",
                         "--print-certs", str(apk)])
        cert_match = re.search(r"certificate SHA-256 digest:\s*([0-9a-f]{64})",
                               signature, re.IGNORECASE)
        if not cert_match or cert_match.group(1).lower() != CERT_SHA256:
            raise RuntimeError(f"signing certificate mismatch in {apk.name}")
        run([str(ZIPALIGN), "-c", "-P", "16", "4", str(apk)])

        total_payload_bytes += payload_bytes
        verified = ["package_identity", "ZIP_STORED_assets", "payload_size_crc",
                    "signing_certificate", "16KiB_zipalign"]
        if group != "base":
            verified.extend(["hasCode_false", "no_dex"])
        results.append({
            "group": group,
            "apk": str(apk),
            "sha256": sha256(apk),
            "size_bytes": apk.stat().st_size,
            "split": split_name,
            "asset_count": len(assets),
            "payload_uncompressed_bytes": payload_bytes,
            "certificate_sha256": cert_match.group(1).lower(),
            "verified": verified,
        })

    expected_total = (assignment["assigned_uncompressed_bytes"] +
                      results[-2]["payload_uncompressed_bytes"] +
                      results[-1]["payload_uncompressed_bytes"])
    if total_payload_bytes != expected_total:
        raise RuntimeError("release payload byte total does not match assignment plus optional split resources")
    report = {
        "result": "RELEASE_APK_SET_STATIC_VERIFICATION_PASSED",
        "package": PACKAGE,
        "version_code": int(VERSION_CODE),
        "version_name": VERSION_NAME,
        "certificate_sha256": CERT_SHA256,
        "assignment_sha256": sha256(ROOT / "work" / "episode_assignment.json"),
        "russian_localization_split": False,
        "episode_groups": sorted(groups),
        "hide_border_assets": sorted(EXPECTED_HIDE_ASSETS),
        "payload_uncompressed_bytes_including_optional_splits": total_payload_bytes,
        "artifacts": results,
    }
    output = release / "release_set_manifest.json"
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
