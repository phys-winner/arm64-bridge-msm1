from __future__ import annotations

import argparse
import os
from pathlib import Path
import zipfile


ROOT = Path(__file__).resolve().parents[2]
NAMES = (["base.apk"] + [f"split_episode_{episode:02d}.apk" for episode in range(2, 9)]
         + ["split_hide_border.apk", "split_widescreen.apk"])


def main() -> None:
    parser = argparse.ArgumentParser(description="Rebuild the base and episode cache distribution archive.")
    parser.add_argument("--release-dir", type=Path, default=ROOT / "pub")
    args = parser.parse_args()
    release = args.release_dir.resolve()
    if not release.is_relative_to(ROOT):
        raise RuntimeError("release directory must remain inside the project")
    sources = [release / "cache_splits" / name for name in NAMES]
    if any(not path.is_file() for path in sources):
        raise RuntimeError("a base or episode split is missing")
    output = release / "cache_splits.zip"
    temporary = release / "cache_splits.zip.new"
    if temporary.exists():
        raise RuntimeError(f"inspect existing unfinished archive before retry: {temporary}")
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED,
                             compresslevel=1, allowZip64=True) as archive:
            for source in sources:
                archive.write(source, source.name)
        with zipfile.ZipFile(temporary) as archive:
            members = archive.infolist()
            if [item.filename for item in members] != NAMES:
                raise RuntimeError("archive member list changed")
            for item, source in zip(members, sources):
                if item.file_size != source.stat().st_size:
                    raise RuntimeError(f"archive member size differs: {item.filename}")
        os.replace(temporary, output)
        print(f"{output}: {output.stat().st_size} bytes, {len(NAMES)} APKs")
    except Exception:
        # Keep the incomplete archive for inspection; the previous release ZIP stays intact.
        raise


if __name__ == "__main__":
    main()
