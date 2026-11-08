#!/usr/bin/env python3
"""Compile APK scaffolds and stream the locked cache assignment into them."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
import zlib

from apk_build import JAVA, SIGN_ROOT, TOOL_ROOT, EXPECTED_CERT, BuildError, file_hash, parse_badging, parse_certificate
from process_tools import run_process
from verify_mcsm_release_set import OFFLINE_BOOT_PATCH_ASSET, OFFLINE_BOOT_PATCH_SHA256


INT32_MAX = 2**31 - 1
ANDROID = "{http://schemas.android.com/apk/res/android}"
SPLITS = {"split_episode_02": "episode_02", "split_episode_03": "episode_03",
          "split_episode_04": "episode_04", "split_episode_05": "episode_05",
          "split_episode_06": "episode_06", "split_episode_07": "episode_07",
          "split_episode_08": "episode_08"}
ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ASSIGNMENT = ROOT / "work" / "episode_assignment.json"
DEFAULT_OUTPUT = ROOT / "out" / "cache_release"
DEFAULT_LOGS = ROOT / "work" / "logs" / "cache_package"
SCAFFOLD_EXCLUDES = {
    # IDA database accidentally staged beside the guest library; it is research
    # data, not an Android asset or part of the ARM32 guest payload.
    "assets/guestlib/armeabi-v7a/libGameEngine.so.i64",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run_checked(argv: list[str], *, cwd: Path, logs: Path, timeout_s: float) -> str:
    result = run_process(argv, cwd=cwd, output_dir=logs, timeout_s=timeout_s)
    if result.outcome != "succeeded":
        raise RuntimeError(f"operation {result.outcome}; stdout={result.stdout_log}; stderr={result.stderr_log}")
    return Path(result.stdout_log).read_text(encoding="utf-8", errors="replace")


def check_source(root: Path, group: str, package_group: str) -> tuple[Path, str]:
    source = root / "app" if group == "base" else root / "splits" / group
    if not source.is_dir():
        raise ValueError(f"APK scaffold is missing: {source}")
    for filename in ("AndroidManifest.xml", "apktool.yml"):
        if not (source / filename).is_file():
            raise ValueError(f"APK scaffold is incomplete: {source / filename}")
    manifest = ET.parse(source / "AndroidManifest.xml").getroot()
    if manifest.attrib.get("package") != "com.telltalegames.minecraft100":
        raise ValueError(f"unexpected package in {source / 'AndroidManifest.xml'}")
    if group == "base":
        if manifest.attrib.get("split") is not None:
            raise ValueError("base scaffold declares split identity")
        split_name = ""
        metadata = (source / "apktool.yml").read_text(encoding="utf-8")
        if "minSdkVersion: 24" not in metadata or "targetSdkVersion: 37" not in metadata:
            raise ValueError("base scaffold SDK metadata must be modernized to minSdk 24 / targetSdk 37 before packaging")
    else:
        split_name = manifest.attrib.get("split", "")
        if split_name != f"split_{group}":
            raise ValueError(f"split manifest identity drift for {group}: {split_name!r}")
        application = manifest.find("application")
        if application is None or application.attrib.get(ANDROID + "hasCode") != "false":
            raise ValueError(f"{group} must declare application android:hasCode=false")
        if manifest.attrib.get(ANDROID + "splitTypes") != "cache":
            raise ValueError(f"{group} must declare android:splitTypes=cache")
        if manifest.findall("uses-split"):
            raise ValueError(f"{group} must not depend on another split")
        metadata = (source / "apktool.yml").read_text(encoding="utf-8")
        if "minSdkVersion: 24" not in metadata or "targetSdkVersion: 37" not in metadata:
            raise ValueError(f"{group} SDK metadata must be minSdk 24 / targetSdk 37")
    return source, split_name


def copy_scaffold(unsigned_apk: Path, merged_apk: Path, payloads: list[dict],
                  source_archives: dict[str, zipfile.ZipFile]) -> dict:
    with zipfile.ZipFile(unsigned_apk, "r") as scaffold:
        infos = scaffold.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise ValueError(f"duplicate entries in compiled scaffold {unsigned_apk}")
        if any(info.file_size >= INT32_MAX for info in infos):
            raise ValueError(f"scaffold entry reaches INT32_MAX: {unsigned_apk}")
        if any(info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) for info in infos):
            raise ValueError("compiled scaffold uses an unsupported ZIP compression method")
        payload_paths = {row["asset_path"] for row in payloads}
        existing = {info.filename: info for info in infos if info.filename in payload_paths}
        for row in payloads:
            info = existing.get(row["asset_path"])
            if info is None:
                continue
            if info.compress_type != zipfile.ZIP_STORED or info.file_size != row["size_bytes"]:
                raise ValueError(f"existing scaffold payload has wrong size or compression: {info.filename}")
            if info.filename == OFFLINE_BOOT_PATCH_ASSET:
                if hashlib.sha256(scaffold.read(info)).hexdigest() != OFFLINE_BOOT_PATCH_SHA256:
                    raise ValueError("existing boot patch differs from the reviewed source")
            elif f"{info.CRC:08x}" != row["crc32"]:
                raise ValueError(f"existing scaffold payload differs from locked source: {info.filename}")

        expected_bytes = sum(row["size_bytes"] for row in payloads)
        copied_bytes = 0
        copied_entries = 0
        payload_crc = {name: {"size_bytes": info.file_size, "crc32": f"{info.CRC:08x}", "method": "ZIP_STORED"}
                       for name, info in existing.items()}
        with zipfile.ZipFile(merged_apk, "w", allowZip64=False) as output:
            output.comment = scaffold.comment
            excluded_scaffold_entries = []
            for info in infos:
                if info.filename in SCAFFOLD_EXCLUDES:
                    excluded_scaffold_entries.append(info.filename)
                    continue
                clone = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                clone.compress_type = info.compress_type
                clone.comment = info.comment
                clone.extra = info.extra
                clone.internal_attr = info.internal_attr
                clone.external_attr = info.external_attr
                clone.create_system = info.create_system
                clone.flag_bits = info.flag_bits & 0x800  # retain only the UTF-8 filename flag
                with scaffold.open(info, "r") as source, output.open(clone, "w", force_zip64=False) as dest:
                    while True:
                        block = source.read(4 * 1024 * 1024)
                        if not block:
                            break
                        dest.write(block)
                        copied_bytes += len(block)
                copied_entries += 1

            for row in payloads:
                if row["asset_path"] in existing:
                    continue
                archive = source_archives[row["source_archive"]]
                source_info = archive.getinfo(row["source_entry"])
                if (source_info.file_size != row["size_bytes"] or
                        f"{source_info.CRC:08x}" != row["crc32"]):
                    raise ValueError(f"source ZIP entry drifted: {row['source_archive']}:{row['source_entry']}")
                zip_info = zipfile.ZipInfo(row["asset_path"], date_time=(2020, 1, 1, 0, 0, 0))
                zip_info.compress_type = zipfile.ZIP_STORED
                zip_info.file_size = row["size_bytes"]
                zip_info.CRC = source_info.CRC
                zip_info.create_system = 3
                zip_info.external_attr = 0o100644 << 16
                running_crc = 0
                written = 0
                with archive.open(source_info, "r") as source, output.open(zip_info, "w", force_zip64=False) as dest:
                    while True:
                        block = source.read(8 * 1024 * 1024)
                        if not block:
                            break
                        dest.write(block)
                        running_crc = zlib.crc32(block, running_crc)
                        written += len(block)
                crc = f"{running_crc & 0xffffffff:08x}"
                if written != row["size_bytes"] or crc != row["crc32"]:
                    raise ValueError(f"streamed payload failed size/CRC verification: {row['asset_path']}")
                payload_crc[row["asset_path"]] = {"size_bytes": written, "crc32": crc, "method": "ZIP_STORED"}

    merged_size = merged_apk.stat().st_size
    if merged_size >= INT32_MAX:
        raise ValueError(f"merged unsigned APK reaches INT32_MAX: {merged_size}")
    with zipfile.ZipFile(merged_apk, "r") as check:
        rows = check.infolist()
        if len(rows) != len({row.filename for row in rows}):
            raise ValueError("duplicate ZIP entries after streaming payloads")
        if any(row.file_size >= INT32_MAX or row.header_offset >= INT32_MAX for row in rows):
            raise ValueError("merged APK requires ZIP64 or signed-32-bit offsets")
        if len(payload_crc) != len(payloads):
            raise ValueError("one or more streamed payloads were not verified")
        for path in payload_crc:
            info = check.getinfo(path)
            if info.compress_type != zipfile.ZIP_STORED or info.file_size != payload_crc[path]["size_bytes"] or f"{info.CRC:08x}" != payload_crc[path]["crc32"]:
                raise ValueError(f"APK central-directory metadata differs for {path}")
    return {"scaffold_entry_count": copied_entries, "scaffold_excluded_entries": excluded_scaffold_entries,
            "scaffold_uncompressed_bytes": copied_bytes,
            "payload_entry_count": len(payloads), "payload_uncompressed_bytes": expected_bytes,
            "payload_verification": payload_crc, "merged_unsigned_size_bytes": merged_size}


def validate_final(apk: Path, *, group: str, split_name: str, aapt2: Path, zipalign: Path,
                   java: Path, signer: Path, key: Path, cert: Path, root: Path,
                   logs: Path, timeout_s: float) -> dict:
    certificate = parse_certificate(run_checked([str(java), "-jar", str(signer), "verify", "--verbose", "--print-certs", str(apk)], cwd=root, logs=logs, timeout_s=timeout_s))
    if certificate != EXPECTED_CERT:
        raise ValueError(f"signing certificate mismatch for {group}: {certificate}")
    run_checked([str(zipalign), "-c", "-P", "16", "4", str(apk)], cwd=root, logs=logs, timeout_s=timeout_s)
    identity = parse_badging(run_checked([str(aapt2), "dump", "badging", str(apk)], cwd=root, logs=logs, timeout_s=timeout_s))
    expected = {"package": "com.telltalegames.minecraft100", "version_code": "10137",
                "version_name": "1.37", "split": split_name}
    if any(identity.get(key_name) != value for key_name, value in expected.items()):
        raise ValueError(f"package identity mismatch for {group}: {identity}")
    with zipfile.ZipFile(apk, "r") as archive:
        rows = archive.infolist()
        if len(rows) != len({row.filename for row in rows}):
            raise ValueError(f"duplicate ZIP names in signed APK {group}")
        if any(row.file_size >= INT32_MAX or row.header_offset >= INT32_MAX for row in rows):
            raise ValueError(f"APK {group} contains a ZIP64-sized entry or offset")
        assets = [row for row in rows if row.filename.startswith("assets/telltale/")]
        if any(row.compress_type != zipfile.ZIP_STORED for row in assets):
            raise ValueError(f"Telltale payload must be ZIP_STORED in {group}")
    if apk.stat().st_size >= INT32_MAX:
        raise ValueError(f"signed APK {group} reaches INT32_MAX")
    return {"identity": identity, "certificate_sha256": certificate,
            "apk_size_bytes": apk.stat().st_size, "apk_sha256": sha256_file(apk),
            "telltale_asset_count": len(assets), "zipalign_16k_checked": True}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=ROOT)
    parser.add_argument("--tool-root", type=Path, default=TOOL_ROOT)
    parser.add_argument("--java", type=Path, default=JAVA)
    parser.add_argument("--build-tools", default="36.1.0")
    parser.add_argument("--framework-path", type=Path, default=ROOT / "work" / "tool-cache" / "apktool-framework")
    parser.add_argument("--assignment", type=Path, default=DEFAULT_ASSIGNMENT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--logs-dir", type=Path, default=DEFAULT_LOGS)
    parser.add_argument("--target", choices=["all", "base", *SPLITS.keys()], default="all")
    parser.add_argument("--timeout", type=float, default=1800)
    args = parser.parse_args(argv)

    root = args.project_root.resolve(strict=True)
    assignment_path = args.assignment.resolve(strict=True)
    output_dir = args.output_dir.resolve()
    if not output_dir.is_relative_to(root):
        raise SystemExit("output-dir must remain inside project-root")
    logs_dir = args.logs_dir.resolve()
    tools = args.tool_root.resolve(strict=True)
    java = args.java.resolve(strict=True)
    apktool, aapt2, zipalign = tools / "apktool.jar", tools / "sdk" / "build-tools" / args.build_tools / "aapt2.exe", tools / "sdk" / "build-tools" / args.build_tools / "zipalign.exe"
    signer, key, cert = SIGN_ROOT / "apksigner.jar", SIGN_ROOT / "testkey.pk8", SIGN_ROOT / "testkey.x509.pem"
    for path in (apktool, aapt2, zipalign, signer, key, cert):
        if not path.is_file():
            raise SystemExit(f"required build input missing: {path}")
    args.framework_path.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    manifest = json.loads(assignment_path.read_text(encoding="utf-8"))
    expected_groups = manifest["package_groups"]
    targets = ["base", *SPLITS] if args.target == "all" else [args.target]
    all_sources = manifest["source_archives"]
    source_paths = {name: root / "original" / name for name in all_sources}
    for name, meta in all_sources.items():
        path = source_paths[name]
        if not path.is_file() or path.stat().st_size != next(row["size_bytes"] for row in json.loads((root / "work" / "source_inputs.json").read_text(encoding="utf-8"))["inputs"] if row["name"] == name):
            raise SystemExit(f"source archive missing or size changed: {path}")
        if sha256_file(path) != meta["sha256"]:
            raise SystemExit(f"source archive hash mismatch: {path}")

    archive_handles: dict[str, zipfile.ZipFile] = {}
    published: list[Path] = []
    report = {"result": "CACHE_APK_SET_PACKAGED", "assignment": str(assignment_path),
              "output_dir": str(output_dir), "targets": {}, "runtime_acceptance": False}
    output_dir.mkdir(parents=True, exist_ok=True)
    output_names = ["base.apk" if target == "base" else f"{target}.apk" for target in targets]
    if args.target == "all":
        output_names += ["split_hide_border.apk", "split_widescreen.apk"]
    if any((output_dir / name).exists() for name in output_names):
        raise SystemExit("refusing to overwrite an existing cache-release APK")
    stage_parent = root / "work" / "tmp"
    stage_parent.mkdir(parents=True, exist_ok=True)
    stage_root = Path(tempfile.mkdtemp(prefix="cache-apk-stage-", dir=stage_parent))
    try:
        for name, path in source_paths.items():
            archive_handles[name] = zipfile.ZipFile(path, "r")
        for target in targets:
            group = "base" if target == "base" else target
            source_group = "base" if group == "base" else SPLITS[group]
            scaffold, split_name = check_source(root, source_group, group)
            rows = [row for row in manifest["assignments"] if row["package_group"] == group]
            expected = expected_groups[group]
            observed_bytes = sum(row["size_bytes"] for row in rows)
            if len(rows) != expected["entry_count"] or observed_bytes != expected["uncompressed_bytes"]:
                raise ValueError(f"assignment summary mismatch for {group}")
            if len({row["asset_path"] for row in rows}) != len(rows):
                raise ValueError(f"duplicate asset path in group {group}")
            for row in rows:
                if row["source_sha256"] != all_sources[row["source_archive"]]["sha256"]:
                    raise ValueError(f"assignment source hash lock mismatch: {row['source_archive']}")
                if row["size_bytes"] >= INT32_MAX:
                    raise ValueError(f"single APK entry reaches INT32_MAX: {row['asset_path']}")

            work = stage_root / group
            work.mkdir()
            unsigned = work / "scaffold.apk"
            merged = work / "merged-unsigned.apk"
            aligned = work / "aligned.apk"
            signed = work / "signed.apk"
            build_log = run_checked([str(java), "-jar", str(apktool), "b", str(scaffold), "-f", "--aapt", str(aapt2), "--frame-path", str(args.framework_path.resolve()), "-o", str(unsigned)], cwd=root, logs=logs_dir, timeout_s=args.timeout)
            (work / "apktool-summary.txt").write_text(build_log, encoding="utf-8")
            merge_report = copy_scaffold(unsigned, merged, rows, archive_handles)
            run_checked([str(zipalign), "-f", "-P", "16", "4", str(merged), str(aligned)], cwd=root, logs=logs_dir, timeout_s=args.timeout)
            run_checked([str(java), "-jar", str(signer), "sign", "--key", str(key), "--cert", str(cert), "--v1-signing-enabled", "true", "--v2-signing-enabled", "true", "--v3-signing-enabled", "true", "--out", str(signed), str(aligned)], cwd=root, logs=logs_dir, timeout_s=args.timeout)
            final_check = validate_final(signed, group=group, split_name=split_name, aapt2=aapt2, zipalign=zipalign, java=java, signer=signer, key=key, cert=cert, root=root, logs=logs_dir, timeout_s=args.timeout)
            filename = "base.apk" if group == "base" else f"{group}.apk"
            destination = output_dir / filename
            os.replace(signed, destination)
            published.append(destination)
            report["targets"][group] = {**merge_report, **final_check, "artifact": str(destination)}
            print(json.dumps({"target": group, "result": "SIGNED_AND_VALIDATED", **report["targets"][group]}, ensure_ascii=False), flush=True)
        if args.target == "all":
            from build_hide_border import main as build_hide_border
            from build_widescreen import main as build_widescreen
            for name, build in (("hide_border", build_hide_border), ("widescreen", build_widescreen)):
                destination = output_dir / f"split_{name}.apk"
                published.append(destination)
                build(["--output", str(destination)])
                verified = json.loads(destination.with_suffix(".verify.json").read_text(encoding="utf-8"))
                report["targets"][f"split_{name}"] = {
                    "identity": {"package": verified["package"], "version_code": str(verified["versionCode"]),
                                 "version_name": verified["versionName"], "split": verified["split"]},
                    "certificate_sha256": verified["certificate_sha256"],
                    "apk_size_bytes": verified["size_bytes"], "apk_sha256": verified["sha256"],
                    "artifact": verified["apk"], "verification": verified,
                }
        if len({(row["identity"]["package"], row["identity"]["version_code"], row["identity"]["version_name"], row["certificate_sha256"]) for row in report["targets"].values()}) != 1:
            raise ValueError("cache APK set package/version/signer identity mismatch")
        report_path = output_dir / "package_report.json"
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"result": report["result"], "targets": {name: {"apk_size_bytes": row["apk_size_bytes"], "apk_sha256": row["apk_sha256"]} for name, row in report["targets"].items()}, "report": str(report_path)}, ensure_ascii=False, indent=2))
    except BaseException:
        for path in published:
            if path.exists():
                path.unlink()
            for suffix in (".signature.txt", ".verify.json"):
                sidecar = Path(str(path) + suffix) if suffix == ".signature.txt" else path.with_suffix(suffix)
                if sidecar.exists():
                    sidecar.unlink()
        raise
    finally:
        for archive in archive_handles.values():
            archive.close()
        shutil.rmtree(stage_root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, BuildError, ET.ParseError) as exc:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        print(json.dumps({"result": "CACHE_APK_PACKAGE_FAILED", "diagnostic": str(exc)}, ensure_ascii=False, indent=2))
        raise SystemExit(1)
