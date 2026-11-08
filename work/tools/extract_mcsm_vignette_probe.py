from __future__ import annotations

import hashlib
import json
import sys
import zipfile
import zlib
from pathlib import Path

from scan_ttarch2_indexes import RangeReader, parse_nctt, parse_ttarch2


SOURCE_NAME = "01774-Minecraft-Story-Mode-v1-37-cache-Mali.zip"
OBB_NAME = "com.telltalegames.minecraft100/main.10129.com.telltalegames.minecraft100.obb"
TARGETS = {
    "MCSM_android-mali_Project_all.ttarch2": ["Vignette.lua", "Subtitle.lua"],
    "MCSM_android_UI_data.ttarch2": [
        "ui_vignette.scene", "ui_vignette_frame.prop", "ui_vignette.scene.preloadpackagerts",
        "ui_subtitle.scene", "ui_subtitle.scene.preloadpackagerts", "ui_subtitle.prop",
    ],
    "MCSM_android-mali_UI_txmesh.ttarch2": [
        "ui_vignette_frame.d3dmesh", "ui_vignette1.d3dtx", "ui_vignette2.d3dtx",
        "ui_subtitle_text.d3dmesh", "ui_subtitle_text.d3dtx",
    ],
    "MCSM_android_UI_anichore.ttarch2": ["ui_vignette_hide.chore", "ui_vignette_show.chore"],
}
OUTPUT_RELATIVE = Path("work/tmp/ttarch2_probe_001")


def extract_resource(stream, archive_size: int, archive_index: dict, entry: dict) -> bytes:
    start = archive_index["data_start"] + entry["relative_offset"]
    size = entry["size_bytes"]
    if archive_index["container"] == "NCTT":
        stream.seek(start)
        data = stream.read(size)
        if len(data) != size:
            raise ValueError(f"short NCTT resource {entry['name']}")
        return data
    if archive_index["container"] != "ZCTT":
        raise ValueError(f"unsupported archive container {archive_index['container']}")

    stream.seek(0)
    if stream.read(4) != b"ZCTT":
        raise ValueError("ZCTT magic changed between index and extraction")
    chunk_size = int.from_bytes(stream.read(4), "little")
    block_count = int.from_bytes(stream.read(4), "little")
    first_data_offset = int.from_bytes(stream.read(8), "little")
    ends = [int.from_bytes(stream.read(8), "little") for _ in range(block_count)]
    if first_data_offset != 20 + block_count * 8 or len(ends) != block_count:
        raise ValueError("invalid ZCTT block table")

    output = bytearray()
    resource_end = start + size
    first_block = start // chunk_size
    last_block = (resource_end - 1) // chunk_size if size else first_block - 1
    for block in range(first_block, last_block + 1):
        block_start = first_data_offset if block == 0 else ends[block - 1]
        block_end = ends[block]
        if block_end <= block_start or block_end > archive_size:
            raise ValueError(f"invalid compressed block range {block}")
        stream.seek(block_start)
        compressed = stream.read(block_end - block_start)
        if len(compressed) != block_end - block_start:
            raise ValueError(f"short compressed block {block}")
        try:
            decoded = zlib.decompress(compressed, -zlib.MAX_WBITS)
        except zlib.error:
            decoded = zlib.decompress(compressed)
        if len(decoded) > chunk_size:
            raise ValueError(f"decoded block {block} exceeds chunk size")
        uncompressed_block_start = block * chunk_size
        copy_start = max(start, uncompressed_block_start)
        copy_end = min(resource_end, uncompressed_block_start + len(decoded))
        output.extend(decoded[copy_start - uncompressed_block_start:copy_end - uncompressed_block_start])
    if len(output) != size:
        raise ValueError(f"short ZCTT resource {entry['name']}: {len(output)} != {size}")
    return bytes(output)


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    output = (root / OUTPUT_RELATIVE).resolve()
    if not output.is_relative_to((root / "work" / "tmp").resolve()):
        raise ValueError("probe output escaped work/tmp")
    if output.exists():
        raise FileExistsError(f"refusing to overwrite existing probe output: {output}")
    output.mkdir(parents=True)

    inventory = json.loads((root / "work" / "source_inputs.json").read_text(encoding="utf-8"))
    source_item = next(item for item in inventory["inputs"] if item["name"] == SOURCE_NAME)
    source_path = root / "original" / source_item["name"]
    extracted = []
    with zipfile.ZipFile(source_path) as source_zip:
        obb_info = source_zip.getinfo(OBB_NAME)
        with source_zip.open(obb_info) as obb:
            obb_index = parse_nctt(obb, obb_info.file_size, f"{SOURCE_NAME}:{OBB_NAME}")
            for archive_name, target_names in TARGETS.items():
                ttarch_entry = next((item for item in obb_index["entries"]
                                     if item["name"] == archive_name), None)
                if ttarch_entry is None:
                    raise ValueError(f"TTARCH2 archive not found in OBB: {archive_name}")
                ttarch = RangeReader(obb, obb_index["data_start"] + ttarch_entry["relative_offset"],
                                     ttarch_entry["size_bytes"])
                archive_index = parse_ttarch2(ttarch, ttarch_entry["size_bytes"], archive_name)
                for target_name in target_names:
                    resource = next((item for item in archive_index["entries"]
                                     if item["name"] == target_name), None)
                    if resource is None:
                        raise ValueError(f"resource not found: {archive_name}:{target_name}")
                    data = extract_resource(ttarch, ttarch_entry["size_bytes"], archive_index, resource)
                    target = output / f"{archive_name.removesuffix('.ttarch2')}__{target_name}"
                    target.write_bytes(data)
                    extracted.append({"archive": archive_name, "name": target_name,
                                      "path": target.relative_to(root).as_posix(),
                                      "size_bytes": len(data),
                                      "sha256": hashlib.sha256(data).hexdigest(),
                                      "container": archive_index["container"]})

    manifest = {"source": SOURCE_NAME, "obb_entry": OBB_NAME,
                "obb_sha256": "d6dfef81d97a66a029ca406a4e0c63dd4e7c94f7b6e5d1b2a45617f8210ded58",
                "files": extracted}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n",
                                            encoding="utf-8", newline="\n")
    for item in extracted:
        print(f"{item['archive']}::{item['name']} {item['size_bytes']} {item['sha256']}")
    print(f"output={OUTPUT_RELATIVE.as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
