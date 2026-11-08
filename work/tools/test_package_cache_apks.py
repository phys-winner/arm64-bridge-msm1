"""Check that prepackaged base assets are verified and not duplicated."""

import tempfile
import zipfile
import zlib
from pathlib import Path

from package_cache_apks import copy_scaffold


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        scaffold = root / "scaffold.apk"
        source_path = root / "source.zip"
        merged = root / "merged.apk"
        with zipfile.ZipFile(scaffold, "w") as archive:
            archive.writestr("assets/telltale/files/a", b"existing")
        with zipfile.ZipFile(source_path, "w") as archive:
            archive.writestr("b", b"streamed")
        rows = [
            {"asset_path": "assets/telltale/files/a", "size_bytes": 8,
             "crc32": f"{zlib.crc32(b'existing'):08x}"},
            {"asset_path": "assets/telltale/files/b", "size_bytes": 8,
             "crc32": f"{zlib.crc32(b'streamed'):08x}",
             "source_archive": "source.zip", "source_entry": "b"},
        ]
        with zipfile.ZipFile(source_path) as source:
            result = copy_scaffold(scaffold, merged, rows, {"source.zip": source})
            assert result["payload_entry_count"] == 2
            with zipfile.ZipFile(merged) as archive:
                assert archive.namelist().count("assets/telltale/files/a") == 1
                assert archive.read("assets/telltale/files/b") == b"streamed"
            rows[0]["crc32"] = "00000000"
            try:
                copy_scaffold(scaffold, merged, rows, {"source.zip": source})
            except ValueError:
                pass
            else:
                raise AssertionError("altered existing asset was accepted")
    print("cache APK scaffold self-check: ok")


if __name__ == "__main__":
    main()
