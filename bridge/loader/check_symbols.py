"""Audit ELF32 ARM relocation imports against typed bridge and guest providers.

Usage: python check_symbols.py <guest.so> [more.so ...] --src <bridge/src> [--json report.json]

The supplied order is the runtime's explicit global guest load group. ELF metadata
and source declarations prove coverage, not handler ABI correctness or execution.
Unknown dependencies, versions and provider types fail closed.
"""

import argparse
import glob
import hashlib
import json
import os
import re
import struct
import sys
from collections import Counter

ELF32_HEADER_SIZE = 52
ELF32_SECTION_HEADER_SIZE = 40
ELF32_SYMBOL_SIZE = 16
ELF32_REL_SIZE = 8
EI_CLASS, EI_DATA, ELFCLASS32, ELFDATA2LSB, EM_ARM = 4, 5, 1, 1, 40
SHN_UNDEF = 0
SHT_RELA, SHT_DYNAMIC, SHT_REL, SHT_DYNSYM = 4, 6, 9, 11
SHT_GNU_VERDEF, SHT_GNU_VERNEED, SHT_GNU_VERSYM = 0x6FFFFFFD, 0x6FFFFFFE, 0x6FFFFFFF
STB_GLOBAL, STB_WEAK = 1, 2
STT_NOTYPE, STT_OBJECT, STT_FUNC = 0, 1, 2
TYPE_NAMES = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 6: "TLS"}
BIND_NAMES = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}
REL_NAMES = {0: "R_ARM_NONE", 2: "R_ARM_ABS32", 3: "R_ARM_REL32", 21: "R_ARM_GLOB_DAT", 22: "R_ARM_JUMP_SLOT", 23: "R_ARM_RELATIVE"}


def checked_slice(data, offset, size, label):
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValueError("%s is outside the ELF file" % label)
    return data[offset:offset + size]


def read_c_string(data, offset, label):
    if offset < 0 or offset >= len(data):
        raise ValueError("%s string offset is outside its table" % label)
    terminator = data.find(b"\0", offset)
    if terminator < 0:
        raise ValueError("%s string is unterminated" % label)
    return data[offset:terminator].decode("latin1")


def canonical_name(name):
    return name.split("@", 1)[0]


def read_library(path):
    with open(path, "rb") as stream:
        elf = stream.read()
    if len(elf) < ELF32_HEADER_SIZE or elf[:4] != b"\x7fELF":
        raise ValueError("%s is not an ELF file" % path)
    if elf[EI_CLASS] != ELFCLASS32 or elf[EI_DATA] != ELFDATA2LSB:
        raise ValueError("%s is not little-endian ELF32" % path)
    if struct.unpack_from("<HH", elf, 16) != (3, EM_ARM):
        raise ValueError("%s is not an ARM ET_DYN ELF" % path)
    section_offset, = struct.unpack_from("<I", elf, 32)
    section_entry_size, section_count = struct.unpack_from("<HH", elf, 46)
    if section_entry_size < ELF32_SECTION_HEADER_SIZE or not section_count:
        raise ValueError("%s has invalid or absent ELF32 section headers" % path)
    checked_slice(elf, section_offset, section_entry_size * section_count, "section-header table")
    sections = []
    for index in range(section_count):
        fields = struct.unpack_from("<IIIIIIIIII", elf, section_offset + index * section_entry_size)
        sections.append(dict(type=fields[1], offset=fields[4], size=fields[5], link=fields[6],
                             info=fields[7], entry_size=fields[9]))

    def section_data(section, label):
        return checked_slice(elf, section["offset"], section["size"], label)

    def linked_strings(section):
        if section["link"] >= len(sections):
            raise ValueError("invalid dynamic string-table link")
        return section_data(sections[section["link"]], "linked string table")

    indices = [i for i, s in enumerate(sections) if s["type"] == SHT_DYNSYM]
    if len(indices) != 1:
        raise ValueError("expected exactly one dynamic-symbol table")
    dynsym_index = indices[0]
    dynsym = sections[dynsym_index]
    if dynsym["entry_size"] not in (0, ELF32_SYMBOL_SIZE) or dynsym["size"] % ELF32_SYMBOL_SIZE:
        raise ValueError("unsupported or truncated ELF32 dynamic-symbol entries")
    dynstr = linked_strings(dynsym)
    symbol_data = section_data(dynsym, ".dynsym")
    symbols = []
    for offset in range(0, len(symbol_data), ELF32_SYMBOL_SIZE):
        name_offset, value, size, info, other, shndx = struct.unpack_from("<IIIBBH", symbol_data, offset)
        raw_name = read_c_string(dynstr, name_offset, ".dynstr") if name_offset else ""
        symbols.append(dict(name=raw_name, raw_name=raw_name, index=offset // 16,
                            value=value, size=size, bind=info >> 4, type=info & 15,
                            visibility=other & 3, shndx=shndx, version_index=0,
                            version="", version_file="", version_hidden=False, relocations=[]))
    needed, soname = [], os.path.basename(path)
    version_names = {}
    versym = None
    for section in sections:
        kind = section["type"]
        if kind == SHT_RELA and section["size"]:
            raise ValueError("%s uses unsupported SHT_RELA relocations" % path)
        if kind == SHT_DYNAMIC:
            data, strings = section_data(section, ".dynamic"), linked_strings(section)
            if len(data) % 8:
                raise ValueError("truncated dynamic table")
            for offset in range(0, len(data), 8):
                tag, value = struct.unpack_from("<II", data, offset)
                if tag == 0:
                    break
                if tag in (7, 8) and value or tag == 20 and value != 17:
                    raise ValueError("unsupported dynamic RELA relocation table")
                if tag == 1:
                    needed.append(read_c_string(strings, value, "DT_NEEDED"))
                elif tag == 14:
                    soname = read_c_string(strings, value, "DT_SONAME")
            else:
                raise ValueError("unterminated dynamic table")
        elif kind == SHT_GNU_VERSYM:
            if versym is not None or section["link"] != dynsym_index:
                raise ValueError("invalid or duplicate version-symbol table")
            versym = section_data(section, ".gnu.version")
            if len(versym) != len(symbols) * 2:
                raise ValueError("version-symbol count does not match .dynsym")
        elif kind in (SHT_GNU_VERNEED, SHT_GNU_VERDEF):
            data, strings = section_data(section, "version table"), linked_strings(section)
            offset = 0
            for entry in range(section["info"]):
                if kind == SHT_GNU_VERNEED:
                    version, count, file_offset, aux, following = struct.unpack(
                        "<HHIII", checked_slice(data, offset, 16, "version need"))
                    file = read_c_string(strings, file_offset, "version dependency")
                else:
                    version, flags, index, count, _hash, aux, following = struct.unpack(
                        "<HHHHIII", checked_slice(data, offset, 20, "version definition"))
                    file = ""
                if version != 1 or not count or not aux:
                    raise ValueError("invalid version record")
                auxiliary = offset + aux
                for item in range(count):
                    if kind == SHT_GNU_VERNEED:
                        _hash, _flags, index, name_offset, next_aux = struct.unpack(
                            "<IHHII", checked_slice(data, auxiliary, 16, "version need auxiliary"))
                    else:
                        name_offset, next_aux = struct.unpack(
                            "<II", checked_slice(data, auxiliary, 8, "version definition auxiliary"))
                    name = read_c_string(strings, name_offset, "version name")
                    if kind == SHT_GNU_VERNEED or item == 0:
                        key = index & 0x7FFF
                        if key in version_names and version_names[key] != (name, file):
                            raise ValueError("conflicting version index")
                        version_names[key] = (name, file)
                    if item + 1 < count and not next_aux:
                        raise ValueError("truncated version auxiliary chain")
                    auxiliary += next_aux
                if entry + 1 < section["info"] and not following:
                    raise ValueError("truncated version chain")
                offset += following
    for symbol in symbols:
        index = struct.unpack_from("<H", versym, symbol["index"] * 2)[0] if versym else 0
        symbol["version_index"], symbol["version_hidden"] = index & 0x7FFF, bool(index & 0x8000)
        if symbol["version_index"] > 1:
            if symbol["version_index"] not in version_names:
                raise ValueError("symbol references undefined version index")
            symbol["version"], symbol["version_file"] = version_names[symbol["version_index"]]
        suffix = symbol["raw_name"].partition("@")[2].lstrip("@")
        if suffix and suffix != symbol["version"]:
            raise ValueError("literal symbol version does not match version table: " + symbol["raw_name"])
        if symbol["version_file"] and symbol["version_file"] not in needed:
            raise ValueError("symbol version dependency is not DT_NEEDED")

    relocation_counts = Counter()
    for section in sections:
        if section["type"] != SHT_REL or section["link"] != dynsym_index:
            continue
        if section["entry_size"] not in (0, ELF32_REL_SIZE) or section["size"] % ELF32_REL_SIZE:
            raise ValueError("unsupported or truncated ELF32 relocation entries")
        data = section_data(section, "relocation table")
        for offset in range(0, len(data), ELF32_REL_SIZE):
            target, info = struct.unpack_from("<II", data, offset)
            index, kind = info >> 8, info & 255
            if kind not in REL_NAMES:
                raise ValueError("unsupported ARM relocation type %d" % kind)
            relocation_counts[REL_NAMES[kind]] += 1
            if not index or kind == 0:
                continue
            if index >= len(symbols):
                raise ValueError("relocation references an invalid dynamic symbol")
            if kind == 23:
                raise ValueError("R_ARM_RELATIVE unexpectedly references a symbol")
            symbols[index]["relocations"].append(dict(target=target, type=kind))
    exports = [s for s in symbols if s["name"] and s["shndx"] != SHN_UNDEF
               and s["bind"] in (STB_GLOBAL, STB_WEAK) and s["visibility"] in (0, 3)
               and (versym is None or s["version_index"] != 0)]
    imports = [s for s in symbols if s["name"] and s["shndx"] == SHN_UNDEF and s["relocations"]]
    return dict(path=str(path), sha256=hashlib.sha256(elf).hexdigest(), soname=soname, needed=needed,
                symbols=symbols, exports=exports, imports=imports, relocation_counts=dict(relocation_counts),
                has_version_table=versym is not None)


def get_symbols(path):
    """Compatibility view; the audit below retains the full records."""
    library = read_library(path)
    return ({s["name"] for s in library["exports"]},
            {s["name"] for s in library["imports"] if s["bind"] != STB_WEAK})


def strip_cpp_comments(source):
    # Preserve strings (including paths with //), and preserve source line numbers.
    tokens = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*'
    return re.sub(tokens, lambda m: re.sub(r"[^\n]", " ", m[0]) if m[0].startswith("/") else m[0],
                  source, flags=re.DOTALL)


def delimited(source, start):
    """Return one balanced C++ (), [] or {} group, skipping quoted tokens."""
    stack = []
    quote = None
    escaped = False
    for index in range(start, len(source)):
        char = source[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
        elif char in "([{":
            stack.append(char)
        elif char in ")]}":
            if not stack or {')': '(', ']': '[', '}': '{'}[char] != stack.pop():
                raise ValueError("unbalanced C++ provider declaration")
            if not stack:
                return source[start + 1:index], index + 1
    raise ValueError("unterminated C++ provider declaration")


def arguments(text):
    result, start, index = [], 0, 0
    while index < len(text):
        char = text[index]
        if char in "([{":
            _, index = delimited(text, index)
            continue
        if char in "\"'":
            quote = char
            index += 1
            while index < len(text) and text[index] != quote:
                index += 2 if text[index] == "\\" else 1
        elif char == ",":
            result.append(text[start:index].strip())
            start = index + 1
        index += 1
    return result + [text[start:].strip()]


def literal(text):
    return text[1:-1] if re.fullmatch(r'"[^"\\]*"', text.strip()) else None


def function_bodies(source):
    result = {}
    for match in re.finditer(r"\b(?:void|bool|uint32_t)\s+(?:\w+::)?(\w+)\s*\(", source):
        _, end = delimited(source, match.end() - 1)
        start = end + len(source[end:]) - len(source[end:].lstrip())
        if start < len(source) and source[start] == "{":
            body, end = delimited(source, start)
            result[match[1]] = (start, end, body)
    return result


def read_contract(src_dir):
    if not os.path.isdir(src_dir):
        raise ValueError("provider source directory does not exist: " + str(src_dir))
    sources = []
    for path in sorted(glob.glob(os.path.join(src_dir, "*.cpp"))):
        with open(path, encoding="utf-8") as stream:
            sources.append(strip_cpp_comments(stream.read()))
    source = "\n".join(sources)
    def literals(name):
        match = re.search(r"\b" + name + r"\s*\[\s*\]\s*=\s*\{([^}]+)\}", source)
        return re.findall(r'"([^"\\]+)"', match[1]) if match else []
    bodies = function_bodies(source)
    scopes = {}
    root = bodies.get("RegisterAllThunks", (0, 0, ""))[2]
    active = []
    for match in re.finditer(r'm_registration_libraries\s*=\s*\{([^}]*)\}|\b(Register\w+)\s*\(', root):
        if match[1] is not None:
            active = re.findall(r'"([^"\\]+)"', match[1])
        elif active:
            scopes[match[2]] = list(active)
    for _ in range(len(bodies)):
        changed = False
        for name, libraries in list(scopes.items()):
            for called in re.findall(r"\b(Register\w+)\s*\(", bodies.get(name, (0, 0, ""))[2]):
                if called in bodies and called not in ("RegisterThunk", "RegisterSymbol", "RegisterDataSymbol") and called not in scopes:
                    scopes[called] = libraries
                    changed = True
        if not changed:
            break
    return dict(system_libraries=literals("kBridgeSystemLibraries"),
                version_pairs=literals("kBridgeVersionPairs"), registration_scopes=scopes,
                guest_scope="global-load-group")


def registered_providers(src_dir):
    # ponytail: lexical inventory, not C++ execution; computed providers need explicit declarations.
    providers = {}
    scopes = read_contract(src_dir)["registration_scopes"]
    for path in sorted(glob.glob(os.path.join(src_dir, "*.cpp"))):
        with open(path, encoding="utf-8") as stream:
            original = stream.read()
        source = strip_cpp_comments(original)
        bodies = function_bodies(source)
        policies = {m[1]: (m[2], m[3].strip()) for m in re.finditer(
            r"//\s*provider-policy:\s*(\S+)\s+(offline|enosys|unsupported)\s+([^\n]+)", original)}
        helpers = {}
        for match in re.finditer(r"\bauto\s+(\w+)\s*=\s*\[[^\]]*\]\s*\(", source):
            params, end = delimited(source, match.end() - 1)
            body_start = end + len(source[end:]) - len(source[end:].lstrip())
            if body_start >= len(source) or source[body_start] != "{":
                continue
            body, _ = delimited(source, body_start)
            first = arguments(params)[0]
            param = re.search(r"\b(\w+)\s*$", first)
            if not param:
                continue
            calls = re.findall(r"\b(RegisterThunk|RegisterSymbol|RegisterDataSymbol)\s*\(\s*" + param[1] + r"\b", body)
            kinds = {STT_FUNC if name == "RegisterThunk" else STT_OBJECT for name in calls}
            if len(kinds) == 1:
                call = re.search(r"\b(?:RegisterThunk|RegisterSymbol|RegisterDataSymbol)\s*\(\s*" + param[1] + r"\b", body)
                call_args = arguments(delimited(body, body.index("(", call.start()))[0])
                expression = call_args[1] if len(call_args) > 1 else ""
                parameter_names = [re.search(r"\b(\w+)\s*$", arg) for arg in arguments(params)]
                helpers[match[1]] = (kinds.pop(), expression, [param[1] if param else "" for param in parameter_names])
        names = ["RegisterThunk", "RegisterSymbol", "RegisterDataSymbol", "AllocAndRegisterIID", *helpers]
        for match in re.finditer(r"\b(" + "|".join(map(re.escape, names)) + r")\s*\(", source):
            text, _ = delimited(source, match.end() - 1)
            args = arguments(text)
            name_index = 2 if match[1] == "AllocAndRegisterIID" else 0
            if len(args) <= name_index or not literal(args[name_index]):
                continue
            name = literal(args[name_index])
            kind = helpers.get(match[1], (STT_FUNC if match[1] == "RegisterThunk" else STT_OBJECT, ""))[0]
            handler = helpers[match[1]][1] if match[1] in helpers else args[1] if len(args) > 1 else ""
            if match[1] in helpers and handler in helpers[match[1]][2]:
                parameter_index = helpers[match[1]][2].index(handler)
                handler = args[parameter_index] if parameter_index < len(args) else handler
            empty = bool(kind == STT_FUNC and (re.search(r"\]\s*\([^)]*\)\s*\{\s*\}\s*$", handler)
                         or handler in ("{}", "nullptr", "ThunkHandler{}", "ThunkHandler()")))
            policy, reason = policies.get(name, ("enosys-branch" if re.search(r"\bENOSYS\b", handler) else "", ""))
            owner = next((owner for owner, (start, end, _) in bodies.items() if start < match.start() < end), "")
            libraries = list(scopes.get(owner, []))
            if match[1] == "RegisterDataSymbol" and len(args) > 2:
                libraries = re.findall(r'"([^"\\]+)"', args[2])
            providers.setdefault(name, []).append(dict(name=name, type=kind, source=os.path.basename(path),
                line=source.count("\n", 0, match.start()) + 1, registration=match[1],
                scope="bridge-global", libraries=libraries, version="runtime-contract", empty=empty,
                policy=policy, policy_reason=reason))
    return providers


def registered_thunks(src_dir):
    return set(registered_providers(src_dir))


def type_matches(import_type, export_type, relocations=()):
    if import_type == STT_OBJECT:
        return export_type == STT_OBJECT
    if import_type == STT_FUNC:
        return export_type in (STT_FUNC, STT_NOTYPE)
    if import_type == STT_NOTYPE:
        if any(r["type"] == 22 for r in relocations):
            return export_type in (STT_FUNC, STT_NOTYPE)
        return export_type in (STT_NOTYPE, STT_FUNC, STT_OBJECT)
    return False


def version_matches(import_symbol, export_symbol):
    if import_symbol["version"]:
        return import_symbol["version"] == export_symbol["version"]
    return not export_symbol["version_hidden"]


def audit(libraries, providers, contract):
    rows, errors, dependencies, rejected = [], [], [], []
    sonames = [library["soname"] for library in libraries]
    if len(sonames) != len(set(sonames)):
        errors.append("duplicate guest SONAME in global load group")
    guest_exports = {}
    for library in libraries:
        for symbol in library["exports"]:
            guest_exports.setdefault(symbol["name"], []).append((library["soname"], symbol))
    for library in libraries:
        for needed in library["needed"]:
            source = "guest" if needed in sonames else "bridge" if needed in contract["system_libraries"] else "missing"
            dependencies.append(dict(library=library["soname"], needed=needed, provider=source))
            if source == "missing":
                errors.append("%s: unsupported DT_NEEDED %s" % (library["soname"], needed))
            elif source == "guest" and sonames.index(needed) >= sonames.index(library["soname"]):
                errors.append("%s: initializer dependency %s must precede requester" % (library["soname"], needed))
        for symbol in library["imports"]:
            row = dict(symbol, library=library["soname"], provider=None, status="unresolved", rejections=[])
            valid_import = symbol["bind"] in (STB_GLOBAL, STB_WEAK) and symbol["visibility"] in (0, 3)
            if not valid_import:
                row["import_error"] = "unsupported import binding or visibility"
            for module, candidate in guest_exports.get(symbol["name"], []) if valid_import else []:
                reason = ""
                if not type_matches(symbol["type"], candidate["type"], symbol["relocations"]):
                    reason = "type"
                elif not version_matches(symbol, candidate):
                    reason = "version"
                elif symbol["version_file"] and symbol["version_file"] != module:
                    reason = "version/scope"
                if reason:
                    row["rejections"].append(dict(provider=module, reason=reason, type=candidate["type"], version=candidate["version"]))
                    continue
                row.update(status="guest", provider=dict(name=symbol["name"], module=module, type=candidate["type"],
                    scope="global-load-group", version=candidate["version"], value=candidate["value"],
                    bind=candidate["bind"], visibility=candidate["visibility"]))
                break
            if not row["provider"] and valid_import:
                # Registration rejects duplicate names at runtime; only the first declaration can win.
                candidate = providers.get(symbol["name"], [None])[0]
                if candidate:
                    reason = ""
                    if not type_matches(symbol["type"], candidate["type"], symbol["relocations"]):
                        reason = "type"
                    elif symbol["version"] and (symbol["version_file"] + ":" + symbol["version"] not in contract["version_pairs"]
                                               or symbol["version_file"] not in candidate["libraries"]):
                        reason = "version/scope"
                    if reason:
                        row["rejections"].append(dict(provider="bridge", reason=reason, type=candidate["type"], version="runtime-contract"))
                    else:
                        row.update(status="bridge", provider=candidate)
            if not row["provider"]:
                row["status"] = "weak-zero" if symbol["bind"] == STB_WEAK else "unresolved"
                if row["status"] == "unresolved":
                    errors.append("%s: unresolved %s %s%s" % (library["soname"], TYPE_NAMES.get(symbol["type"], str(symbol["type"])),
                        symbol["name"], "@" + symbol["version"] if symbol["version"] else ""))
            for rejection in row["rejections"]:
                rejected.append(dict(library=library["soname"], name=symbol["name"], import_type=symbol["type"], **rejection))
            rows.append(row)
    duplicates = {name: declarations for name, declarations in providers.items() if len(declarations) > 1}
    for name, declarations in duplicates.items():
        if len({item["type"] for item in declarations}) > 1:
            errors.append("conflicting provider registrations: " + name)
    unresolved = [row for row in rows if row["status"] == "unresolved"]
    named_undefined = [s for library in libraries for s in library["symbols"] if s["name"] and s["shndx"] == 0]
    summaries = [dict(path=lib["path"], sha256=lib.get("sha256", ""), soname=lib["soname"], needed=lib["needed"],
                      exports=len(lib["exports"]), imports=len(lib["imports"]),
                      has_version_table=lib["has_version_table"], relocation_counts=lib["relocation_counts"]) for lib in libraries]
    return dict(coverage_only=True, runtime_abi_verified=False, contract=contract, libraries=summaries,
        dependencies=dependencies, imports=rows, providers=providers, duplicates=duplicates,
        rejected_candidates=rejected, errors=errors,
        functional_policy_blockers=[dict(library=row["library"], name=row["name"],
            policy=row["provider"].get("policy") or "empty-handler") for row in rows
            if row["provider"] and (row["provider"].get("empty") or row["provider"].get("policy") in ("enosys", "enosys-branch", "unsupported"))],
        policies=[provider for items in providers.values() for provider in items if provider["policy"]],
        empty_handlers=[provider for items in providers.values() for provider in items if provider["empty"]],
        summary=dict(named_undefined_rows=len(named_undefined), canonical_undefined_names=len({canonical_name(s["name"]) for s in named_undefined}),
            relocation_import_rows=len(rows), strong_import_rows=sum(s["bind"] != STB_WEAK for s in rows),
            weak_import_rows=sum(s["bind"] == STB_WEAK for s in rows),
            versioned_import_rows=sum(bool(s["version"]) for s in rows),
            dependency_rows=len(dependencies), missing_dependency_rows=sum(d["provider"] == "missing" for d in dependencies),
            weak_zero_rows=sum(s["status"] == "weak-zero" for s in rows), unresolved_strong_rows=len(unresolved),
            unresolved_type_rows=sum(any(r["reason"] == "type" for r in row["rejections"]) for row in unresolved),
            unresolved_version_scope_rows=sum(any(r["reason"].startswith("version") for r in row["rejections"]) for row in unresolved),
            provider_names=len(providers), resolved_guest_rows=sum(s["status"] == "guest" for s in rows),
            resolved_bridge_rows=sum(s["status"] == "bridge" for s in rows),
            selected_empty_rows=sum(bool(s["provider"] and s["provider"].get("empty")) for s in rows),
            selected_policy_rows=sum(bool(s["provider"] and s["provider"].get("policy")) for s in rows)))


def print_report(report):
    print("Scope: global-load-group in supplied order; source coverage is NOT runtime ABI proof.")
    for library in report["libraries"]:
        print("%-22s exports=%5d imports=%4d versions=%s" % (library["soname"], library["exports"], library["imports"], library["has_version_table"]))
        print("  DT_NEEDED: " + ", ".join(library["needed"]))
    print("\nSummary: " + json.dumps(report["summary"], sort_keys=True))
    for error in report["errors"]:
        print("[ERROR] " + error)
    for row in report["rejected_candidates"]:
        if row["reason"] == "type":
            print("[REJECTED TYPE CANDIDATE] %s:%s import=%s provider=%s export=%s" % (
                row["library"], row["name"], TYPE_NAMES.get(row["import_type"]), row["provider"], TYPE_NAMES.get(row["type"])))
    print("\nIntentional/observed policy declarations (%d):" % len(report["policies"]))
    for provider in report["policies"]:
        print("  %s %s %s:%d %s" % (provider["name"], provider["policy"], provider["source"], provider["line"], provider["policy_reason"]))
    print("\nRegistered-but-empty handlers (%d):" % len(report["empty_handlers"]))
    for provider in report["empty_handlers"]:
        selected = sum(row["provider"] == provider for row in report["imports"])
        print("  %s %s:%d selected-import-rows=%d" % (provider["name"], provider["source"], provider["line"], selected))
    if report["duplicates"]:
        print("Duplicate source registrations: " + ", ".join(sorted(report["duplicates"])))
    print("\nCoverage gate: " + ("BLOCKED" if report["errors"] else "PASSED (handler contracts and device gate remain separate)"))
    blockers = Counter(row["name"] for row in report["functional_policy_blockers"])
    print("Functional gate: " + ("BLOCKED / requires implementation or policy review" if blockers else "UNVERIFIED (not tested by source inventory)"))
    for name, count in sorted(blockers.items()):
        print("  [FUNCTIONAL POLICY] %s selected-import-rows=%d" % (name, count))


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("libraries", nargs="+")
    parser.add_argument("--src", default="src")
    parser.add_argument("--json", dest="json_path")
    args = parser.parse_args(argv)
    try:
        libraries = [read_library(path) for path in args.libraries]
        providers = registered_providers(args.src)
        report = audit(libraries, providers, read_contract(args.src))
    except (OSError, ValueError, struct.error) as error:
        print("Audit input error: %s" % error, file=sys.stderr)
        return 2
    print_report(report)
    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
