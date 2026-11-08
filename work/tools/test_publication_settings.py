"""Check portable tool configuration and signer validation without game data."""
import os
from pathlib import Path
import subprocess
import sys


def main():
    fingerprint = "12" * 32
    env = dict(os.environ, JAVA_EXE="java-custom", ANDROID_TOOL_ROOT="external-tools",
               ANDROID_SIGNING_DIR="external-signing", MCSM_SIGNER_SHA256=fingerprint.upper())
    check = '''
from pathlib import Path
import apk_build as a
import build_hide_border as h
import build_widescreen as w
import package_cache_apks as p
import verify_mcsm_release_set as v
assert a.JAVA == h.JAVA == w.JAVA == p.JAVA == v.JAVA == Path("java-custom")
assert a.SIGN_ROOT == p.SIGN_ROOT == Path("external-signing")
assert h.SIGNER == w.SIGNER == v.SIGNER == a.SIGN_ROOT / "apksigner.jar"
assert a.TOOL_ROOT == h.TOOL_ROOT == w.TOOL_ROOT == p.TOOL_ROOT == v.TOOL_ROOT == Path("external-tools")
assert a.EXPECTED_CERT == h.EXPECTED_CERT == w.EXPECTED_CERT == p.EXPECTED_CERT == v.CERT_SHA256 == "12" * 32
assert a.parse_certificate("Signer #1 certificate SHA-256 digest: " + "12" * 32) == "12" * 32
try:
    a.parse_certificate("Signer #1 certificate SHA-256 digest: " + "34" * 32)
except a.BuildError:
    pass
else:
    raise AssertionError("wrong signer accepted")
'''
    cwd = Path(__file__).resolve().parent
    subprocess.run([sys.executable, "-B", "-c", check], cwd=cwd, env=env, check=True)
    env["MCSM_SIGNER_SHA256"] = "invalid"
    result = subprocess.run([sys.executable, "-B", "-c", "import apk_build"],
                            cwd=cwd, env=env, capture_output=True, text=True)
    assert result.returncode != 0 and "64-digit SHA-256" in result.stderr
    print("Portable publication settings and signer validation: PASS")


if __name__ == "__main__":
    main()
