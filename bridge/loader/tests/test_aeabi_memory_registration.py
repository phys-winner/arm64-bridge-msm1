"""Every AEABI memory variant must have one production registration."""
from collections import Counter
from pathlib import Path
import re

source = Path(__file__).resolve().parents[1] / "src/thunks_libc.cpp"
actual = Counter(re.findall(r'RegisterThunk\s*\(\s*"(__aeabi_mem(?:cpy|move|set|clr)(?:4|8)?)"', source.read_text(encoding="utf-8")))
expected = Counter({"__aeabi_mem" + operation + suffix: 1
                    for operation in ("cpy", "move", "set", "clr") for suffix in ("", "4", "8")})
assert actual == expected, actual
print("AEABI memory registration checks OK: 12 names, one registration each")
