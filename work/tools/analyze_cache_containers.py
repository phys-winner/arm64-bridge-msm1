from __future__ import annotations

import hashlib
import json
import struct
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path


class RangeReader:
    """Read a stored ZIP member by offsets without unpacking it to disk."""

    def __init__(self, path: Path, start: int, length: int):
        self._file = path.open("rb")
        self._start = start
        self._length = length
        self._pos = 0

    def seekable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            pos = offset
        elif whence == 1:
            pos = self._pos + offset
        elif whence == 2:
            pos = self._length + offset
        else:
            raise ValueError("invalid whence")
        if pos < 0:
            raise ValueError("negative seek")
        self._pos = min(pos, self._length)
        return self._pos

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = self._length - self._pos
        size = min(size, self._length - self._pos)
        if size <= 0:
            return b""
        self._file.seek(self._start + self._pos)
        data = self._file.read(size)
        self._pos += len(data)
        return data

    def close(self) -> None:
        self._file.close()


def stored_member_range(archive_path: Path, info: zipfile.ZipInfo) -> RangeReader:
    if info.compress_type != zipfile.ZIP_STORED or info.file_size != info.compress_size:
        raise ValueError(f"member is not a plain stored range: {info.filename}")
    with archive_path.open("rb") as stream:
        stream.seek(info.header_offset)
        local = stream.read(30)
        if len(local) != 30 or local[:4] != b"PK\x03\x04":
            raise ValueError(f"invalid local ZIP header: {info.filename}")
        name_length, extra_length = struct.unpack_from("<HH", local, 26)
        start = info.header_offset + 30 + name_length + extra_length
    return RangeReader(archive_path, start, info.file_size)


def read_nested_archive(archive_path: Path, info: zipfile.ZipInfo) -> dict:
    view = stored_member_range(archive_path, info)
    try:
        magic = view.read(16)
        view.seek(0)
        try:
            with zipfile.ZipFile(view) as nested:
                entries = [
                    {
                        "name": row.filename,
                        "size_bytes": row.file_size,
                        "compressed_bytes": row.compress_size,
                        "crc32": f"{row.CRC:08x}",
                        "method": row.compress_type,
                        "is_dir": row.is_dir(),
                    }
                    for row in nested.infolist()
                ]
                return {
                    "format": "ZIP",
                    "magic_hex": magic.hex(),
                    "entry_count": len(entries),
                    "uncompressed_bytes": sum(x["size_bytes"] for x in entries),
                    "entries": entries,
                }
        except zipfile.BadZipFile:
            return {"format": "opaque", "magic_hex": magic.hex()}
    finally:
        view.close()


def sha_member(archive: zipfile.ZipFile, name: str) -> str:
    digest = hashlib.sha256()
    with archive.open(name) as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    inventory_path = root / "work" / "source_inputs.json"
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    report: dict = {"schema_version": 1, "containers": [], "collisions": []}
    by_path: dict[str, list[dict]] = defaultdict(list)
    obb_files: list[tuple[Path, zipfile.ZipInfo, str]] = []

    for source in inventory["inputs"]:
        if not source["name"].lower().endswith(".zip"):
            continue
        path = root / "original" / source["name"]
        container = {"source": source["name"], "path": str(path), "entries": []}
        with zipfile.ZipFile(path) as outer:
            for info in outer.infolist():
                if info.is_dir() or info.filename == "pdalife.url":
                    continue
                row = {
                    "name": info.filename,
                    "size_bytes": info.file_size,
                    "compressed_bytes": info.compress_size,
                    "crc32": f"{info.CRC:08x}",
                    "method": info.compress_type,
                }
                container["entries"].append(row)
                if info.filename.lower().endswith(".obb"):
                    obb_files.append((path, info, source["name"]))
                else:
                    logical = info.filename
                    prefix = "com.telltalegames.minecraft100/files/"
                    if logical.startswith(prefix):
                        logical = logical[len(prefix):]
                    by_path[logical].append({"source": source["name"], **row})
        container["entry_count"] = len(container["entries"])
        container["uncompressed_bytes"] = sum(x["size_bytes"] for x in container["entries"])
        extensions = Counter(Path(x["name"]).suffix.lower() or "[no extension]" for x in container["entries"])
        container["extensions"] = dict(sorted(extensions.items()))
        container["largest_entries"] = sorted(container["entries"], key=lambda x: x["size_bytes"], reverse=True)[:12]
        container["border_candidates"] = [
            row for row in container["entries"]
            if any(token in row["name"].lower() for token in ("border", "vignette", "dialog", "frame", "overlay"))
        ]
        report["containers"].append(container)

    for logical, rows in sorted(by_path.items()):
        if len(rows) < 2:
            continue
        identities = {(row["size_bytes"], row["crc32"]) for row in rows}
        hashes = []
        if len(identities) > 1:
            for row in rows:
                path = root / "original" / row["source"]
                with zipfile.ZipFile(path) as archive:
                    hashes.append({"source": row["source"], "sha256": sha_member(archive, row["name"])})
        report["collisions"].append(
            {"logical_path": logical, "identical_by_size_crc": len(identities) == 1, "entries": rows, "verified_sha256": hashes}
        )

    report["obb_containers"] = []
    for archive_path, info, source_name in obb_files:
        report["obb_containers"].append(
            {
                "source": source_name,
                "name": info.filename,
                "size_bytes": info.file_size,
                "compressed_bytes": info.compress_size,
                "outer_method": info.compress_type,
                "inner_inventory": read_nested_archive(archive_path, info),
            }
        )

    output = root / "work" / "cache_container_inventory.json"
    output.write_text(json.dumps(report, indent=2), encoding="utf-8", newline="\n")
    print(f"containers={len(report['containers'])} collisions={len(report['collisions'])} obbs={len(report['obb_containers'])}")
    print(f"inventory={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
