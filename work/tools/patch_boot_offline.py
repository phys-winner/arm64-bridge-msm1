#!/usr/bin/env python3
"""Replace the MCSM 1.37 title-screen online gate with local DLC refresh.

The edit is confined to the bootTitle.lua bytecode in one ZCTT archive inside
the embedded patch OBB. It preserves the sizes and offsets of both containers.
"""
from __future__ import annotations

import hashlib
from io import BytesIO
from pathlib import Path
import sys
import zlib

from extract_mcsm_vignette_probe import extract_resource
from scan_ttarch2_indexes import RangeReader, parse_nctt, parse_ttarch2


ROOT = Path(__file__).resolve().parents[2]
OBB = ROOT / "app/assets/telltale/obb/patch.10135.com.telltalegames.minecraft100.obb"
ARCHIVE = "MCSM_android_Android_BF_Boot_data.ttarch2"
RESOURCE = "bootTitle.lua"
ORIGINAL_CHUNK_SHA256 = "842d296236638fdf3f0756243247fafb8057d816522e99f26f921a613a60f246"
PATCHED_CHUNK_SHA256 = "70de4229d5723c36b33f13b2a571598becd8b7deabe4a4ce0573ae55bfe7a24f"
EDIT = (
    (11310, bytes.fromhex("0006004000414000001d4000010680400041c000001d40000106004100414001001d4000"),
     bytes.fromhex("0006c04d001d40800006804b001d4080000600530041401300818013001d4080011f0080")),
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    with OBB.open("r+b") as stream:
        stream.seek(0, 2)
        obb_size = stream.tell()
        obb = parse_nctt(stream, obb_size, str(OBB))
        row = next(e for e in obb["entries"] if e["name"] == ARCHIVE)
        offset = obb["data_start"] + row["relative_offset"]
        stream.seek(offset)
        original_archive = stream.read(row["size_bytes"])
        archive = parse_ttarch2(BytesIO(original_archive), len(original_archive), ARCHIVE)
        if archive["container"] != "ZCTT" or archive["compressed_blocks"] != 3:
            raise RuntimeError("unexpected boot archive compression layout")
        resource = next(e for e in archive["entries"] if e["name"] == RESOURCE)
        original_chunk = extract_resource(BytesIO(original_archive), len(original_archive), archive, resource)
        if sha256(original_chunk) != ORIGINAL_CHUNK_SHA256:
            raise RuntimeError(f"unexpected bootTitle.lua SHA-256: {sha256(original_chunk)}")
        patched_chunk = bytearray(original_chunk)
        for position, old, new in EDIT:
            if patched_chunk[position:position + len(old)] != old or len(old) != len(new):
                raise RuntimeError(f"unexpected bootTitle.lua instruction bytes at {position}")
            patched_chunk[position:position + len(old)] = new
        if sha256(patched_chunk) != PATCHED_CHUNK_SHA256:
            raise RuntimeError("patched bootTitle.lua SHA-256 mismatch")

        # The script is entirely in the third 64 KiB block. Recompress it
        # more tightly and keep every original ZCTT block boundary.
        block_start = int.from_bytes(original_archive[28:36], "little")
        block_end = int.from_bytes(original_archive[36:44], "little")
        decoded = bytearray(zlib.decompress(original_archive[block_start:block_end], -15))
        position = archive["data_start"] + resource["relative_offset"] - 2 * archive["chunk_size"]
        if position < 0 or decoded[position:position + len(original_chunk)] != original_chunk:
            raise RuntimeError("unexpected bootTitle.lua decompressed location")
        decoded[position:position + len(patched_chunk)] = patched_chunk
        compressor = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15, memLevel=6)
        compressed = compressor.compress(decoded) + compressor.flush()
        if len(compressed) > block_end - block_start:
            raise RuntimeError("patched block no longer fits the source archive")
        patched_archive = (original_archive[:block_start] + compressed +
                           bytes(block_end - block_start - len(compressed)))
        if len(patched_archive) != len(original_archive):
            raise RuntimeError("boot archive size changed")
        check = parse_ttarch2(BytesIO(patched_archive), len(patched_archive), ARCHIVE)
        checked_chunk = extract_resource(BytesIO(patched_archive), len(patched_archive), check, resource)
        if checked_chunk != patched_chunk:
            raise RuntimeError("patched archive failed round-trip extraction")
        stream.seek(offset)
        stream.write(patched_archive)
        stream.flush()
        print(f"OBB={OBB}")
        print(f"archive_offset={offset} archive_bytes={len(patched_archive)} compressed_bytes={len(compressed)}")
        print(f"bootTitle.lua_sha256={sha256(patched_chunk)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
