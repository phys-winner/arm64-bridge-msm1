from __future__ import annotations

import hashlib
import json
import shutil
import sys
import zipfile
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    source = root / "original" / "01774-Minecraft-Story-Mode-v1-37-cache-Mali.zip"
    destination = root / "work" / "tmp" / "baseline_external_obb"
    destination.mkdir(parents=True, exist_ok=True)
    rows = []
    with zipfile.ZipFile(source) as archive:
        for info in archive.infolist():
            if not info.filename.lower().endswith(".obb"):
                continue
            name = Path(info.filename).name
            output = destination / name
            with archive.open(info) as incoming, output.open("wb") as outgoing:
                shutil.copyfileobj(incoming, outgoing, length=8 * 1024 * 1024)
            if output.stat().st_size != info.file_size:
                raise RuntimeError(f"size mismatch for {info.filename}")
            rows.append(
                {
                    "source_archive": source.name,
                    "source_entry": info.filename,
                    "device_test_path": f"Android/obb/com.telltalegames.minecraft100/{name}",
                    "temporary_host_path": str(output),
                    "size_bytes": output.stat().st_size,
                    "outer_crc32": f"{info.CRC:08x}",
                    "sha256": sha256(output),
                }
            )
    if len(rows) != 2:
        raise RuntimeError(f"expected two baseline OBBs, found {len(rows)}")
    result = root / "work" / "baseline_external_obb.json"
    result.write_text(json.dumps(rows, indent=2), encoding="utf-8", newline="\n")
    print(f"obbs={len(rows)} evidence={result}")
    for row in rows:
        print(f"{row['device_test_path']}\t{row['size_bytes']}\t{row['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
