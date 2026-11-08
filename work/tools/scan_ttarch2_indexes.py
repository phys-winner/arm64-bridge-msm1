from __future__ import annotations

import json
import math
import struct
import sys
import zipfile
import zlib
from collections import Counter
from pathlib import Path


CHUNK_NAME_BYTES = 0x10000
MAX_ENTRY_COUNT = 1_000_000
MAX_DIRECTORY_BYTES = 256 * 1024 * 1024
MAX_NAME_BYTES = 4096
TERMS = ("vignette", "border", "frame", "letterbox", "dialog", "subtitle", "cinema")


class ScanError(Exception):
    pass


class RangeReader:
    """Bounded seekable view over an OBB entry; it does not materialize the entry."""

    def __init__(self, stream, start: int, length: int):
        self.stream = stream
        self.start = start
        self.length = length
        self.position = 0

    def tell(self) -> int:
        return self.position

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            target = offset
        elif whence == 1:
            target = self.position + offset
        elif whence == 2:
            target = self.length + offset
        else:
            raise ValueError("invalid seek mode")
        if target < 0:
            raise ValueError("negative seek")
        self.position = min(target, self.length)
        return self.position

    def read(self, size: int = -1) -> bytes:
        remaining = self.length - self.position
        if size is None or size < 0:
            size = remaining
        size = min(size, remaining)
        self.stream.seek(self.start + self.position)
        data = self.stream.read(size)
        self.position += len(data)
        return data


def _read_exact(stream, size: int, what: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise ScanError(f"short {what}: expected {size}, got {len(data)}")
    return data


def _read_c_string(data: bytes, offset: int, end: int) -> str:
    if offset < 0 or offset >= end or end > len(data):
        raise ScanError("filename offset outside name table")
    nul = data.find(b"\0", offset, min(end, offset + MAX_NAME_BYTES + 1))
    if nul < 0:
        raise ScanError("unterminated/oversized filename")
    name = data[offset:nul].decode("ascii", errors="strict")
    if not name or "\\" in name or "\x00" in name:
        raise ScanError(f"invalid archive filename: {name!r}")
    return name


def _records_and_names(stream, *, header_bytes: int, name_size: int,
                       file_count: int, stream_size: int, label: str) -> dict:
    if file_count > MAX_ENTRY_COUNT:
        raise ScanError(f"{label}: unreasonable entry count {file_count}")
    records_size = file_count * 28
    names_start = header_bytes + records_size
    data_start = names_start + name_size
    if name_size > MAX_DIRECTORY_BYTES or data_start > MAX_DIRECTORY_BYTES:
        raise ScanError(f"{label}: directory/name table exceeds safety bound")
    if data_start > stream_size:
        raise ScanError(f"{label}: directory exceeds containing archive")

    stream.seek(header_bytes)
    record_bytes = _read_exact(stream, records_size, f"{label} file table")
    stream.seek(names_start)
    name_table = _read_exact(stream, name_size, f"{label} name table")

    entries = []
    ranges = []
    for index in range(file_count):
        crc64, relative_offset, size, ignored, name_block, name_offset = struct.unpack_from(
            "<QQIIHH", record_bytes, index * 28)
        name_position = name_block * CHUNK_NAME_BYTES + name_offset
        name = _read_c_string(name_table, name_position, len(name_table))
        start = data_start + relative_offset
        end = start + size
        if start < data_start or end < start or end > stream_size:
            raise ScanError(f"{label}: data range outside containing archive for {name!r}")
        ranges.append((start, end, name))
        entries.append({"name": name, "crc64": f"{crc64:016x}",
                        "relative_offset": relative_offset, "size_bytes": size})

    return {"entries": entries, "data_start": data_start,
            "max_data_end": max((end for _, end, _ in ranges), default=data_start),
            "range_count": len(ranges)}


def parse_nctt(stream, stream_size: int, label: str) -> dict:
    stream.seek(0)
    magic, _archive_size, version, name_size, file_count = struct.unpack(
        "<4sQ4sII", _read_exact(stream, 24, f"{label} NCTT header"))
    if magic != b"NCTT" or version not in (b"3ATT", b"4ATT"):
        raise ScanError(f"{label}: unsupported NCTT/version {magic!r}/{version!r}")
    header_bytes = 24
    if version == b"3ATT":
        stream.seek(24)
        _legacy_field = _read_exact(stream, 4, f"{label} legacy field")
        header_bytes += 4
    parsed = _records_and_names(stream, header_bytes=header_bytes,
                                name_size=name_size, file_count=file_count,
                                stream_size=stream_size, label=label)
    return {"container": "NCTT", "version": version.decode("ascii"),
            "chunk_size": CHUNK_NAME_BYTES, **parsed}


def _decompress_deflate(payload: bytes, label: str, index: int) -> bytes:
    try:
        return zlib.decompress(payload, -zlib.MAX_WBITS)
    except zlib.error as raw_error:
        try:
            return zlib.decompress(payload)
        except zlib.error as wrapped_error:
            raise ScanError(f"{label}: block {index} is not zlib/deflate ({raw_error}; {wrapped_error})")


def parse_zctt(stream, stream_size: int, label: str) -> dict:
    stream.seek(0)
    magic = _read_exact(stream, 4, f"{label} ZCTT magic")
    if magic != b"ZCTT":
        raise ScanError(f"{label}: unsupported compressed magic {magic!r}")
    chunk_size, block_count = struct.unpack("<II", _read_exact(stream, 8, f"{label} ZCTT header"))
    if not chunk_size or block_count <= 0 or block_count > 1_000_000:
        raise ScanError(f"{label}: invalid ZCTT chunk/count {chunk_size}/{block_count}")
    first_data_offset = struct.unpack("<Q", _read_exact(stream, 8, f"{label} first block offset"))[0]
    table_end = 20 + block_count * 8
    if first_data_offset != table_end or first_data_offset > stream_size:
        raise ScanError(f"{label}: unexpected ZCTT block table/data offset")
    offsets = list(struct.unpack("<" + "Q" * block_count,
                                 _read_exact(stream, block_count * 8, f"{label} ZCTT block table")))
    previous = first_data_offset
    block_ranges = []
    for index, end in enumerate(offsets):
        if end <= previous or end > stream_size:
            raise ScanError(f"{label}: invalid compressed block range {index}")
        block_ranges.append((previous, end))
        previous = end

    def decode(index: int) -> bytes:
        start, end = block_ranges[index]
        stream.seek(start)
        compressed = _read_exact(stream, end - start, f"{label} compressed block {index}")
        decoded = _decompress_deflate(compressed, label, index)
        if len(decoded) > chunk_size:
            raise ScanError(f"{label}: decoded block {index} exceeds {chunk_size} bytes")
        return decoded

    first = decode(0)
    if len(first) < 12:
        raise ScanError(f"{label}: short decompressed TTARCH2 header")
    version = first[:4]
    if version == b"3ATT":
        subheader_bytes = 16
        name_size, file_count = struct.unpack_from("<II", first, 8)
    elif version == b"4ATT":
        subheader_bytes = 12
        name_size, file_count = struct.unpack_from("<II", first, 4)
    else:
        raise ScanError(f"{label}: unsupported inner TTARCH2 version {version!r}")
    if file_count > MAX_ENTRY_COUNT:
        raise ScanError(f"{label}: unreasonable entry count {file_count}")
    directory_end = subheader_bytes + file_count * 28 + name_size
    if directory_end > MAX_DIRECTORY_BYTES:
        raise ScanError(f"{label}: directory/name table exceeds safety bound")
    needed_blocks = max(1, math.ceil(directory_end / chunk_size))
    if needed_blocks > block_count:
        raise ScanError(f"{label}: index requests blocks beyond archive")
    decompressed = bytearray(first)
    for index in range(1, needed_blocks):
        decompressed.extend(decode(index))
    if len(decompressed) < directory_end:
        raise ScanError(f"{label}: decompressed TTARCH2 index is truncated")

    if file_count:
        table_start = subheader_bytes
        records_end = table_start + file_count * 28
        name_table = bytes(decompressed[records_end:directory_end])
        record_bytes = bytes(decompressed[table_start:records_end])
    else:
        name_table = b""
        record_bytes = b""

    entries = []
    data_start = directory_end
    max_data_end = data_start
    for index in range(file_count):
        crc64, relative_offset, size, ignored, name_block, name_offset = struct.unpack_from(
            "<QQIIHH", record_bytes, index * 28)
        name_position = name_block * CHUNK_NAME_BYTES + name_offset
        name = _read_c_string(name_table, name_position, len(name_table))
        max_data_end = max(max_data_end, data_start + relative_offset + size)
        entries.append({"name": name, "crc64": f"{crc64:016x}",
                        "relative_offset": relative_offset, "size_bytes": size})

    estimated_uncompressed_size = block_count * chunk_size
    if max_data_end > estimated_uncompressed_size:
        raise ScanError(f"{label}: file ranges exceed the declared decompressed block capacity")
    return {"container": "ZCTT", "version": version.decode("ascii"),
            "chunk_size": chunk_size, "compressed_blocks": block_count,
            "index_bytes_decompressed": len(decompressed), "data_start": data_start,
            "max_data_end": max_data_end, "range_count": len(entries), "entries": entries}


def parse_ttarch2(stream, stream_size: int, label: str) -> dict:
    stream.seek(0)
    magic = _read_exact(stream, 4, f"{label} container magic")
    if magic == b"NCTT":
        return parse_nctt(stream, stream_size, label)
    if magic == b"ZCTT":
        return parse_zctt(stream, stream_size, label)
    raise ScanError(f"{label}: unsupported container magic {magic!r}")


def _add_candidates(result: dict, source: str, outer_entry: str, archive_index: dict,
                    candidates: dict[str, list[dict]]) -> None:
    for entry in archive_index["entries"]:
        lowered = entry["name"].casefold()
        for term in TERMS:
            if term in lowered and len(candidates[term]) < 1000:
                candidates[term].append({
                    "source": source, "archive": outer_entry,
                    "file": entry["name"], "crc64": entry["crc64"],
                    "size_bytes": entry["size_bytes"],
                    "relative_offset": entry["relative_offset"],
                    "container": archive_index["container"],
                })


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    inventory_path = root / "work" / "source_inputs.json"
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    result = {"schema_version": 1, "archives_scanned": 0, "archives_indexed": 0,
              "indexed_files": 0, "containers": {}, "candidate_terms": list(TERMS),
              "candidates": {term: [] for term in TERMS}, "errors": []}

    for source_item in inventory["inputs"]:
        if not source_item["name"].casefold().endswith(".zip"):
            continue
        source_name = source_item["name"]
        source_path = root / "original" / source_item["name"]
        with zipfile.ZipFile(source_path) as outer:
            for info in outer.infolist():
                if info.is_dir():
                    continue
                if info.filename.casefold().endswith(".obb"):
                    with outer.open(info) as obb_stream:
                        try:
                            obb_index = parse_nctt(obb_stream, info.file_size,
                                                   f"{source_name}:{info.filename}")
                        except (ScanError, struct.error, UnicodeError, ValueError) as exc:
                            result["errors"].append({"source": source_name,
                                                     "archive": info.filename,
                                                     "error": str(exc)[:400]})
                            continue
                        for inner in obb_index["entries"]:
                            if not inner["name"].casefold().endswith(".ttarch2"):
                                continue
                            result["archives_scanned"] += 1
                            reader = RangeReader(obb_stream, obb_index["data_start"] + inner["relative_offset"],
                                                 inner["size_bytes"])
                            try:
                                archive_index = parse_ttarch2(reader, inner["size_bytes"],
                                    f"{source_name}:{info.filename}:{inner['name']}")
                            except (ScanError, struct.error, UnicodeError, zlib.error, ValueError) as exc:
                                result["errors"].append({"source": source_name,
                                                         "archive": f"{info.filename}:{inner['name']}",
                                                         "error": str(exc)[:400]})
                                continue
                            result["archives_indexed"] += 1
                            result["indexed_files"] += len(archive_index["entries"])
                            result["containers"][archive_index["container"]] = result["containers"].get(archive_index["container"], 0) + 1
                            _add_candidates(result, source_name, f"{info.filename}:{inner['name']}",
                                            archive_index, result["candidates"])
                elif info.filename.casefold().endswith(".ttarch2"):
                    result["archives_scanned"] += 1
                    with outer.open(info) as archive_stream:
                        try:
                            archive_index = parse_ttarch2(archive_stream, info.file_size,
                                                          f"{source_name}:{info.filename}")
                        except (ScanError, struct.error, UnicodeError, zlib.error, ValueError) as exc:
                            result["errors"].append({"source": source_name,
                                                     "archive": info.filename,
                                                     "error": str(exc)[:400]})
                            continue
                    result["archives_indexed"] += 1
                    result["indexed_files"] += len(archive_index["entries"])
                    result["containers"][archive_index["container"]] = result["containers"].get(archive_index["container"], 0) + 1
                    _add_candidates(result, source_name, info.filename,
                                    archive_index, result["candidates"])

    result["output"] = "work/ttarch2_archive_index.json"
    out = root / result["output"]
    out.write_text(json.dumps(result, indent=2, ensure_ascii=True) + "\n",
                   encoding="utf-8", newline="\n")
    counts = {term: len(items) for term, items in result["candidates"].items()}
    print(f"archives_scanned={result['archives_scanned']} indexed={result['archives_indexed']} files={result['indexed_files']} errors={len(result['errors'])}")
    print(json.dumps({"containers": result["containers"], "candidate_hits": counts}, sort_keys=True))
    print(result["output"])
    return 0 if result["archives_indexed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
