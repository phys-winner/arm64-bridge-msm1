#!/usr/bin/env python3
"""Build the checked, explicit Minecraft: Story Mode cache-to-APK assignment."""
from __future__ import annotations

import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path

from scan_ttarch2_indexes import parse_ttarch2


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "work" / "episode_assignment.json"
PACKAGE_PREFIX = "com.telltalegames.minecraft100/files/"
EXPECTED_INPUTS = {
    "01774-Minecraft-Story-Mode-v1-37-cache-Mali.zip": ("a1b6372bd019807d2d784e831a3c89a98b73891bcf8746b14e523b864c7a2783", 3, 780_425_083),
    "01774-Minecraft-Story-Mode-v1-37-ep2-Mali-cache.zip": ("7f3d191adb90eb1c395bfc5b245743e7da6f1cf0ad7acbc3b69ae75013596d1e", 47, 782_607_477),
    "01774-Minecraft-Story-Mode-v1-37-ep3-Mali-cache.zip": ("faf11fc5ae2dcc7809ded129a28d52e16e827574ebe6bc3d6a99ee13b232b18a", 46, 603_019_159),
    "01774-Minecraft-Story-Mode-v1-37-ep4-Mali-cache.zip": ("717e6172bfa17b8c06c0fe0cd758dab08b756d4db573c48eacb4240b7ed7773a", 50, 795_695_895),
    "01774-Minecraft-Story-Mode-v1-37-ep5-Mali-cache.zip": ("c9f75489f0c7141293c9d00852da5cca81c9af20725e0f04fb85591c6d9581cc", 97, 1_390_679_319),
    "01774-Minecraft-Story-Mode-v1-37-ep6-Mali-cache.zip": ("87154836ffde6a3495abfd784295eeb5419a157324e4bc3f34e676663b345879", 48, 475_254_911),
    "01774-Minecraft-Story-Mode-v1-37-ep7-Mali-cache.zip": ("a48f5ca1aa2cffe437c08c9527c85e1ab13e73f0f6fc824c6d49e65f977fdb77", 45, 913_863_569),
    "01774-Minecraft-Story-Mode-v1-37-ep8-Mali-cache.zip": ("12aa32e6e81cf19c35abd82a198588fcf17b7a21ea67d037bdea78c2ef3c5b22", 46, 612_377_389),
}
EXPECTED_GROUPS = {
    "base": (3, 780_425_011),
    "split_episode_02": (44, 782_606_828),
    "split_episode_03": (43, 603_018_510),
    "split_episode_04": (46, 795_670_270),
    "split_episode_05": (93, 1_390_653_694),
    "split_episode_06": (44, 473_802_004),
    "split_episode_07": (41, 912_706_533),
    "split_episode_08": (42, 610_955_433),
}
EXPECTED_ORPHANS = {
    4: {"MCSM_android_Android_104_M104_compressed.ttarch2"},
    5: {"MCSM_android_Android_104_M104_compressed.ttarch2"},
    6: {"MCSM_android_JesseMale106_dlog.ttarch2"},
    7: {"MCSM_android_JesseMale105_dlog.ttarch2"},
    8: {"MCSM_android_JesseMale108_dlog.ttarch2"},
}
ORPHAN_ACTIVE_DATA = {
    4: "MCSM_android_Android_104_M104_data.ttarch2",
    5: "MCSM_android_Android_104_M104_data.ttarch2",
    6: "MCSM_android_Minecraft106_data.ttarch2",
    7: "MCSM_android_Minecraft107_data.ttarch2",
    8: "MCSM_android_Minecraft108_data.ttarch2",
}
EXPECTED_DLOG_ORPHANS = {
    6: (160, 20, 140),
    7: (112, 14, 98),
    8: (120, 15, 105),
}
TRANSIENT_FILES = {
    "Temp/IN_token": "Per-install/account response state, not durable game content; avoid shipping a stale token snapshot.",
    "Temp/IN_cloud_save_choices": "Cached server cloud-save response, not the local save set; local saves remain supported.",
}
COMMON_MARKER = "Temp/IN_TelltaleSeries101_patch_etc1"
EXPECTED_COMMON_MARKER = (104, "f78142db")
RESREF = re.compile(rb"[\"']([^\"']+\.ttarch2)[\"']")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _episode_number(name: str) -> int | None:
    match = re.search(r"-ep(\d+)-", name)
    return int(match.group(1)) if match else None


def _archive_entry_index(archive: zipfile.ZipFile, infos: list[zipfile.ZipInfo], filename: str) -> dict:
    info = next((row for row in infos if row.filename.rsplit("/", 1)[-1] == filename), None)
    if info is None:
        raise ValueError(f"required archive is missing: {filename}")
    with archive.open(info) as stream:
        return parse_ttarch2(stream, info.file_size, filename)


def _validate_orphans(archive: zipfile.ZipFile, infos: list[zipfile.ZipInfo], episode: int) -> dict:
    archive_names = {row.filename.rsplit("/", 1)[-1] for row in infos if row.filename.lower().endswith(".ttarch2")}
    references = set()
    for row in infos:
        if row.filename.lower().endswith(".lua"):
            data = archive.read(row)
            references.update(value.decode("utf-8", "strict").rsplit("/", 1)[-1] for value in RESREF.findall(data))
    missing = references - archive_names
    orphans = archive_names - references
    expected = EXPECTED_ORPHANS.get(episode, set())
    if missing or orphans != expected:
        raise ValueError(f"episode {episode} archive references drifted: missing={sorted(missing)}, orphans={sorted(orphans)}")
    active = set()
    if orphans:
        data_index = _archive_entry_index(archive, infos, ORPHAN_ACTIVE_DATA[episode])
        active = {row["name"] for row in data_index["entries"]}
    rows = []
    for filename in sorted(orphans):
        orphan_index = _archive_entry_index(archive, infos, filename)
        names = {row["name"] for row in orphan_index["entries"]}
        if not names or not names <= active:
            raise ValueError(f"episode {episode} unreferenced archive is not covered by its active archive: {filename}")
        if episode in EXPECTED_DLOG_ORPHANS:
            expected_counts = EXPECTED_DLOG_ORPHANS[episode]
            observed = (len(names), sum(name.endswith(".dlog") for name in names), sum(name.endswith(".landb") for name in names))
            if observed != expected_counts:
                raise ValueError(f"episode {episode} unreferenced dialogue archive contents drifted: {observed}")
        elif filename.endswith("M104_compressed.ttarch2"):
            if names != {"adv_sorenCourtyard104Destroyed.scene"}:
                raise ValueError(f"episode {episode} compressed-scene archive contents drifted: {sorted(names)}")
        rows.append({"filename": filename, "logical_entry_count": len(names),
                     "classification": "unreferenced duplicate container; source descriptors reference the containing data archive"})
    return {"referenced_archives": len(references), "orphan_archives": rows,
            "active_archive": ORPHAN_ACTIVE_DATA.get(episode)}


def main() -> int:
    input_lock = json.loads((ROOT / "work" / "source_inputs.json").read_text(encoding="utf-8"))
    by_name = {row["name"]: row for row in input_lock["inputs"]}
    assignments = []
    exclusions = []
    source_summary = {}
    archive_reports = {}

    for source_name, (expected_sha, expected_count, expected_bytes) in EXPECTED_INPUTS.items():
        locked = by_name.get(source_name)
        if locked is None or locked.get("sha256") != expected_sha:
            raise ValueError(f"source input lock mismatch: {source_name}")
        source_path = ROOT / "original" / source_name
        if not source_path.is_file() or source_path.stat().st_size != locked.get("size_bytes"):
            raise ValueError(f"source archive missing or size changed: {source_name}")
        with zipfile.ZipFile(source_path) as archive:
            infos = [row for row in archive.infolist() if not row.is_dir()]
            total_bytes = sum(row.file_size for row in infos)
            if len(infos) != expected_count or total_bytes != expected_bytes:
                raise ValueError(f"source archive inventory drifted: {source_name} count={len(infos)} bytes={total_bytes}")
            episode = _episode_number(source_name)
            if episode is not None:
                archive_reports[str(episode)] = _validate_orphans(archive, infos, episode)
            source_summary[source_name] = {"sha256": expected_sha, "entry_count": len(infos), "uncompressed_bytes": total_bytes}

            for info in infos:
                source_entry = info.filename
                row = {"source_archive": source_name, "source_entry": source_entry,
                       "source_sha256": expected_sha, "size_bytes": info.file_size,
                       "crc32": f"{info.CRC:08x}", "source_zip_method": info.compress_type}
                group = None
                logical_path = None
                reason = None
                if source_entry == "pdalife.url":
                    reason = "third-party promotional URL metadata; not game content"
                elif source_entry.lower().endswith(".obb") and episode is None:
                    group = "base"
                    logical_path = "obb/" + source_entry.rsplit("/", 1)[-1]
                elif source_entry.startswith(PACKAGE_PREFIX) and episode is not None:
                    logical_path = source_entry[len(PACKAGE_PREFIX):]
                    group = f"split_episode_{episode:02d}"
                    if logical_path in TRANSIENT_FILES:
                        reason = TRANSIENT_FILES[logical_path]
                    elif logical_path == COMMON_MARKER:
                        if info.file_size != EXPECTED_COMMON_MARKER[0] or f"{info.CRC:08x}" != EXPECTED_COMMON_MARKER[1]:
                            raise ValueError("shared Telltale series marker changed")
                        if episode == 2:
                            group = "base"
                        else:
                            reason = "identical shared series marker is assigned once in base"
                    elif logical_path.startswith("Net/") and logical_path.rsplit("/", 1)[-1] in EXPECTED_ORPHANS.get(episode, set()):
                        reason = "unreferenced duplicate archive; active descriptor data is retained"
                else:
                    raise ValueError(f"unclassified source entry: {source_name}:{source_entry}")

                if reason is not None:
                    row.update(disposition="excluded", reason=reason)
                    exclusions.append(row)
                else:
                    if group is None or logical_path is None:
                        raise ValueError(f"incomplete assignment: {source_name}:{source_entry}")
                    asset_path = "assets/telltale/" + (logical_path if group == "base" and logical_path.startswith("obb/")
                                                       else "files/" + logical_path)
                    if asset_path.startswith("/") or ".." in Path(asset_path).parts:
                        raise ValueError(f"unsafe asset path: {asset_path}")
                    row.update(disposition="include", package_group=group, asset_path=asset_path)
                    assignments.append(row)

    groups = {}
    for row in assignments:
        summary = groups.setdefault(row["package_group"], {"entry_count": 0, "uncompressed_bytes": 0, "asset_paths": []})
        summary["entry_count"] += 1
        summary["uncompressed_bytes"] += row["size_bytes"]
        summary["asset_paths"].append(row["asset_path"])
    for name, expected in EXPECTED_GROUPS.items():
        observed = groups.get(name)
        if observed is None or (observed["entry_count"], observed["uncompressed_bytes"]) != expected:
            raise ValueError(f"package group {name} drifted: {observed}; expected {expected}")
        if len(observed["asset_paths"]) != len(set(observed["asset_paths"])):
            raise ValueError(f"duplicate asset path inside package group {name}")
        observed["asset_paths"].sort()

    by_asset = {}
    for row in assignments:
        by_asset.setdefault(row["asset_path"], []).append(row)
    collisions = []
    for asset_path, rows in sorted(by_asset.items()):
        if len(rows) < 2:
            continue
        identities = {(row["size_bytes"], row["crc32"]) for row in rows}
        if len(identities) != 1:
            raise ValueError(f"unexplained cross-APK asset collision: {asset_path}")
        collisions.append({"asset_path": asset_path, "policy": "same size and CRC32; source archives remain separately SHA-256 locked",
                           "owners": [{"package_group": row["package_group"], "source_archive": row["source_archive"],
                                       "source_entry": row["source_entry"], "size_bytes": row["size_bytes"], "crc32": row["crc32"]}
                                      for row in rows]})

    expected_assigned_total = sum(size for _, size in EXPECTED_GROUPS.values())
    if sum(row["size_bytes"] for row in assignments) != expected_assigned_total:
        raise ValueError("assigned payload total does not match the fixed group totals")
    result = {
        "schema_version": 1,
        "game": "Minecraft: Story Mode Android 1.37 Mali",
        "source_inventory": "work/source_inputs.json",
        "cache_container_inventory": "work/cache_container_inventory.json",
        "cache_policy": "whole base OBB containers; direct stored game assets for later episodes; no runtime extraction",
        "language_policy": "episode-local descriptors/resources remain in each episode split; no separate Russian split",
        "source_archives": source_summary,
        "package_groups": groups,
        "episode_descriptor_audit": archive_reports,
        "assignment_count": len(assignments),
        "assigned_uncompressed_bytes": expected_assigned_total,
        "exclusion_count": len(exclusions),
        "excluded_uncompressed_bytes": sum(row["size_bytes"] for row in exclusions),
        "cross_apk_collisions": collisions,
        "assignments": sorted(assignments, key=lambda row: (row["package_group"], row["asset_path"])),
        "excluded_entries": sorted(exclusions, key=lambda row: (row["source_archive"], row["source_entry"])),
    }
    OUTPUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"result": "CACHE_ASSIGNMENT_PREPARED", "assignment_count": len(assignments),
                      "assigned_uncompressed_bytes": expected_assigned_total,
                      "exclusion_count": len(exclusions), "excluded_uncompressed_bytes": result["excluded_uncompressed_bytes"],
                      "groups": {name: {"entry_count": row["entry_count"], "uncompressed_bytes": row["uncompressed_bytes"]}
                                 for name, row in groups.items()},
                      "collisions": len(collisions), "output": str(OUTPUT)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
