#!/usr/bin/env python3
"""Build and verify the standalone, code-free MCSM hide-border split."""
from __future__ import annotations

import hashlib
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile


from apk_build import JAVA, SIGN_ROOT, TOOL_ROOT, EXPECTED_CERT

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "splits" / "hide_border"
DEFAULT_OUTPUT = ROOT / "out" / "mcsm_bridge_candidate_002" / "split_hide_border.apk"
APKTOOL = TOOL_ROOT / "apktool.jar"
ZIPALIGN = TOOL_ROOT / "sdk" / "build-tools" / "36.1.0" / "zipalign.exe"
AAPT2 = TOOL_ROOT / "sdk" / "build-tools" / "36.1.0" / "aapt2.exe"
SIGNER = SIGN_ROOT / "apksigner.jar"
KEY = SIGN_ROOT / "testkey.pk8"
CERT = SIGN_ROOT / "testkey.x509.pem"
EXPECTED = {
    "assets/telltale/files/Net/ui_vignette1.d3dtx",
    "assets/telltale/files/Net/ui_vignette2.d3dtx",
}


def run(argv: list[str], *, cwd: Path, log) -> None:
    result = subprocess.run(argv, cwd=cwd, stdout=log, stderr=subprocess.STDOUT,
                            shell=False, check=False)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {argv[0]}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    output = parser.parse_args(argv).output.resolve()
    if not output.is_relative_to(ROOT):
        raise SystemExit(f"output must remain inside the project: {output}")
    for path in (SOURCE / "AndroidManifest.xml", SOURCE / "apktool.yml",
                 *(SOURCE / asset for asset in EXPECTED),
                 JAVA, APKTOOL, ZIPALIGN, AAPT2, SIGNER, KEY, CERT):
        if not path.is_file():
            raise SystemExit(f"required input is missing: {path}")
    if output.exists() or Path(str(output) + ".signature.txt").exists():
        raise SystemExit(f"refusing to overwrite an existing output: {output}")

    temp_root = ROOT / "work" / "tmp"
    temp_root.mkdir(parents=True, exist_ok=True)
    build_root = Path(tempfile.mkdtemp(prefix="hide-border-build-", dir=temp_root))
    output.parent.mkdir(parents=True, exist_ok=True)
    log_path = build_root / "build.log"
    try:
        unsigned = build_root / "unsigned.apk"
        aligned = build_root / "aligned.apk"
        with log_path.open("w", encoding="utf-8") as log:
            run([str(JAVA), "-jar", str(APKTOOL), "b", str(SOURCE), "-o", str(unsigned),
                 "-p", str(ROOT / "work" / "tool-cache" / "apktool-framework")], cwd=ROOT, log=log)
            run([str(ZIPALIGN), "-P", "16", "-f", "4", str(unsigned), str(aligned)], cwd=ROOT, log=log)
            run([str(JAVA), "-jar", str(SIGNER), "sign", "--key", str(KEY), "--cert", str(CERT),
                 "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
                 "--v3-signing-enabled", "true", "--out", str(output), str(aligned)], cwd=ROOT, log=log)

        signature_path = Path(str(output) + ".signature.txt")
        with signature_path.open("w", encoding="utf-8") as signature:
            run([str(JAVA), "-jar", str(SIGNER), "verify", "--verbose", "--print-certs", str(output)], cwd=ROOT, log=signature)
        cert_match = re.search(r"certificate SHA-256 digest:\s*([0-9a-f]{64})",
                               signature_path.read_text(encoding="utf-8"), re.IGNORECASE)
        if not cert_match or cert_match.group(1).lower() != EXPECTED_CERT:
            raise RuntimeError("split signing certificate does not match the required fingerprint")

        with zipfile.ZipFile(output) as archive:
            rows = archive.infolist()
            names = [row.filename for row in rows]
            if len(names) != len(set(names)):
                raise RuntimeError("split APK has duplicate ZIP entry names")
            assets = {name for name in names if name.startswith("assets/")}
            if assets != EXPECTED:
                raise RuntimeError(f"split APK assets mismatch: {sorted(assets)}")
            for asset in sorted(EXPECTED):
                payload = archive.getinfo(asset)
                data = archive.read(asset)
                if payload.compress_type != zipfile.ZIP_STORED:
                    raise RuntimeError(f"vignette texture is not ZIP_STORED: {asset}")
                if len(data) != 131339 or data[:4] != b"5VSM" or any(data[267:]):
                    raise RuntimeError(f"vignette texture is not a transparent MCSM 1.37 D3DTX: {asset}")
            if any(re.fullmatch(r"classes(?:\d+)?\.dex", name) for name in names):
                raise RuntimeError("code-free split unexpectedly contains DEX")
            if any(row.file_size >= 2**31 for row in rows):
                raise RuntimeError("split APK entry reaches the signed 32-bit limit")

        badging = subprocess.check_output([str(AAPT2), "dump", "badging", str(output)],
                                           cwd=ROOT, text=True, errors="replace", shell=False)
        identity = "package: name='com.telltalegames.minecraft100' versionCode='10137' versionName='1.37' split='split_hide_border'"
        if identity not in badging:
            raise RuntimeError("badging package/version/split identity mismatch")
        xmltree = subprocess.check_output([str(AAPT2), "dump", "xmltree", str(output),
                                           "--file", "AndroidManifest.xml"],
                                          cwd=ROOT, text=True, errors="replace", shell=False)
        if "hasCode" not in xmltree or "false" not in xmltree or "splitTypes" not in xmltree or "cache" not in xmltree:
            raise RuntimeError("compiled manifest is missing hasCode=false or splitTypes=cache")
        run([str(ZIPALIGN), "-c", "-P", "16", "4", str(output)], cwd=ROOT, log=subprocess.DEVNULL)
        report = {
            "result": "BUILT_STATIC_VERIFICATION_PASSED",
            "runtime_resource_discovery": "NOT_YET_VERIFIED",
            "apk": str(output),
            "sha256": sha256(output),
            "size_bytes": output.stat().st_size,
            "split": "split_hide_border",
            "package": "com.telltalegames.minecraft100",
            "versionCode": 10137,
            "versionName": "1.37",
            "minSdk": 24,
            "targetSdk": 37,
            "hasCode": False,
            "asset_entries": sorted(assets),
            "asset_compression": "ZIP_STORED",
            "certificate_sha256": cert_match.group(1).lower(),
        }
        report_path = output.with_suffix(".verify.json")
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
    finally:
        shutil.rmtree(build_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
