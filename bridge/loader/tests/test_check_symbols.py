import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("check_symbols", ROOT / "check_symbols.py")
check_symbols = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_symbols)


def make_elf32(relocation_symbol_indexes=(1, 2), relocation_type=check_symbols.SHT_REL):
    dynstr = b"\0needed\0weak_needed\0provided\0unused\0"
    name_needed = dynstr.index(b"needed")
    name_weak = dynstr.index(b"weak_needed")
    name_provided = dynstr.index(b"provided")
    name_unused = dynstr.index(b"unused")
    dynsym = b"".join(
        (
            b"\0" * 16,
            struct.pack("<IIIBBH", name_needed, 0, 0, 0x12, 0, 0),
            struct.pack("<IIIBBH", name_weak, 0, 0, 0x22, 0, 0),
            struct.pack("<IIIBBH", name_provided, 0, 0, 0x12, 0, 1),
            struct.pack("<IIIBBH", name_unused, 0, 0, 0x12, 0, 0),
        )
    )
    relocations = b"".join(
        struct.pack("<II", 0x1000 + index * 4, symbol_index << 8 | 22)
        for index, symbol_index in enumerate(relocation_symbol_indexes)
    )
    dynstr_offset = 0x80
    dynsym_offset = 0xC0
    relocation_offset = 0x140
    section_offset = 0x200
    elf = bytearray(section_offset + 4 * check_symbols.ELF32_SECTION_HEADER_SIZE)
    ident = b"\x7fELF\x01\x01\x01" + b"\0" * 9
    struct.pack_into(
        "<16sHHIIIIIHHHHHH",
        elf,
        0,
        ident,
        3,
        check_symbols.EM_ARM,
        1,
        0,
        0,
        section_offset,
        0,
        check_symbols.ELF32_HEADER_SIZE,
        0,
        0,
        check_symbols.ELF32_SECTION_HEADER_SIZE,
        4,
        0,
    )
    elf[dynstr_offset:dynstr_offset + len(dynstr)] = dynstr
    elf[dynsym_offset:dynsym_offset + len(dynsym)] = dynsym
    elf[relocation_offset:relocation_offset + len(relocations)] = relocations
    section = lambda index, values: struct.pack_into(
        "<IIIIIIIIII", elf, section_offset + index * check_symbols.ELF32_SECTION_HEADER_SIZE, *values
    )
    section(0, (0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    section(1, (0, 3, 0, 0, dynstr_offset, len(dynstr), 0, 0, 1, 0))
    section(2, (0, check_symbols.SHT_DYNSYM, 0, 0, dynsym_offset, len(dynsym), 1, 0, 4, 16))
    section(3, (0, relocation_type, 0, 0, relocation_offset, len(relocations), 2, 0, 4, 8))
    return bytes(elf)


def make_versioned_elf32(defined=False, hidden=False):
    elf = bytearray(make_elf32())
    old_table = 0x200
    sections = [list(struct.unpack_from("<IIIIIIIIII", elf, old_table + i * 40)) for i in range(4)]
    strings = bytes(elf[sections[1][4]:sections[1][4] + sections[1][5]]) + b"libc.so\0LIBC\0"
    sections[1][4], sections[1][5] = len(elf), len(strings)
    elf.extend(strings)
    dynamic = struct.pack("<IIII", 1, strings.index(b"libc.so"), 0, 0)
    versions = [0, 1, 1, 1, 1]
    versions[3 if defined else 1] = 2 | (0x8000 if hidden else 0)
    if defined:
        record = struct.pack("<HHHHIII", 1, 0, 2, 1, 0, 20, 0) + struct.pack("<II", strings.index(b"LIBC"), 0)
        kind = check_symbols.SHT_GNU_VERDEF
    else:
        record = struct.pack("<HHIII", 1, 1, strings.index(b"libc.so"), 16, 0)
        record += struct.pack("<IHHII", 0, 0, 2, strings.index(b"LIBC"), 0)
        kind = check_symbols.SHT_GNU_VERNEED
    extras = [(check_symbols.SHT_DYNAMIC, dynamic, 1, 0, 8),
              (check_symbols.SHT_GNU_VERSYM, struct.pack("<5H", *versions), 2, 0, 2),
              (kind, record, 1, 1, 0)]
    for section_type, payload, link, info, entsize in extras:
        sections.append([0, section_type, 0, 0, len(elf), len(payload), link, info, 4, entsize])
        elf.extend(payload)
    struct.pack_into("<I", elf, 32, len(elf))
    struct.pack_into("<H", elf, 48, len(sections))
    for section in sections:
        elf.extend(struct.pack("<10I", *section))
    return elf


def symbol(name="needed", kind=2, **kwargs):
    result = dict(name=name, raw_name=name, index=1, value=0, size=0, bind=1, type=kind, visibility=0,
                  shndx=0, version_index=0, version="", version_file="", version_hidden=False,
                  relocations=[dict(target=0x1000, type=22)])
    result.update(kwargs)
    return result


def library(name="guest.so", imports=(), exports=(), needed=()):
    return dict(path=name, soname=name, imports=list(imports), exports=list(exports), needed=list(needed),
                symbols=list(imports) + list(exports), has_version_table=False, relocation_counts={})


def provider(name="needed", kind=2, **kwargs):
    result = dict(name=name, type=kind, libraries=["libc.so"], source="test.cpp", line=1,
                  registration="RegisterThunk", scope="bridge-global", version="runtime-contract",
                  empty=False, policy="", policy_reason="")
    result.update(kwargs)
    return result


CONTRACT = dict(system_libraries=["libc.so"], version_pairs=["libc.so:LIBC"],
                registration_scopes={}, guest_scope="global-load-group")


class CheckSymbolsTests(unittest.TestCase):
    def elf_file(self, data):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "guest.so"
        path.write_bytes(data)
        return path

    def test_uses_only_relocation_backed_strong_imports(self):
        exports, imports = check_symbols.get_symbols(self.elf_file(make_elf32()))
        self.assertEqual(exports, {"provided"})
        self.assertEqual(imports, {"needed"})

    def test_rejects_invalid_relocation_symbol(self):
        with self.assertRaisesRegex(ValueError, "invalid dynamic symbol"):
            check_symbols.get_symbols(self.elf_file(make_elf32((9,))))

    def test_rejects_rela_not_supported_by_loader(self):
        with self.assertRaisesRegex(ValueError, "SHT_RELA"):
            check_symbols.get_symbols(self.elf_file(make_elf32((1,), check_symbols.SHT_RELA)))

    def test_finds_functions_data_and_opensl_iids_without_comments(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "providers.cpp"
            source.write_text(
                "// RegisterThunk(\"comment\", ignored)\n"
                "RegisterThunk(\"function\", handler);\n"
                "RegisterSymbol(\"data\", address);\n"
                "RegisterDataSymbol(\"other_data\", address);\n"
                "auto register_helper = [&](const char* name, auto handler) { RegisterThunk(name, handler); };\n"
                "auto define_data = [&](const char* name, auto size) { RegisterDataSymbol(name, size); };\n"
                "register_helper(\"helper_function\", handler);\n"
                "define_data(\"helper_data\", size);\n"
                "register_unproven(\"not_a_provider\", handler);\n"
                "auto wrapped = [&](const char* name, auto handler) { RegisterThunk(name, handler); };\n"
                "wrapped(\"wrapped_function\", handler);\n"
                "AllocAndRegisterIID(manager, host, \"SL_IID_ENGINE\", value);\n",
                encoding="utf-8",
            )
            self.assertEqual(
                check_symbols.registered_thunks(directory),
                {"function", "data", "other_data", "helper_function", "helper_data", "wrapped_function", "SL_IID_ENGINE"},
            )

    def test_retains_types_relocations_and_unreferenced_inventory(self):
        result = check_symbols.read_library(self.elf_file(make_elf32()))
        self.assertEqual(len([s for s in result["symbols"] if s["name"] and s["shndx"] == 0]), 3)
        self.assertEqual([s["bind"] for s in result["imports"]], [1, 2])
        self.assertEqual(result["imports"][0]["type"], check_symbols.STT_FUNC)
        self.assertEqual(result["imports"][0]["relocations"], [{"target": 0x1000, "type": 22}])

    def test_excludes_local_and_hidden_exports(self):
        for binding, visibility in [(0, 0), (1, 1), (1, 2)]:
            with self.subTest(binding=binding, visibility=visibility):
                elf = bytearray(make_elf32())
                elf[0xC0 + 3 * 16 + 12] = binding << 4 | 2
                elf[0xC0 + 3 * 16 + 13] = visibility
                self.assertEqual(check_symbols.get_symbols(self.elf_file(elf))[0], set())

    def test_version_local_export_is_hidden_only_when_versym_exists(self):
        self.assertEqual(check_symbols.get_symbols(self.elf_file(make_elf32()))[0], {"provided"})
        elf = make_versioned_elf32(defined=True)
        table, = struct.unpack_from("<I", elf, 32)
        versions_offset, = struct.unpack_from("<I", elf, table + 5 * 40 + 16)
        struct.pack_into("<H", elf, versions_offset + 3 * 2, 0)
        self.assertEqual(check_symbols.get_symbols(self.elf_file(elf))[0], set())

    def test_invalid_import_binding_or_visibility_never_resolves(self):
        for binding, visibility in [(0, 0), (3, 0), (1, 1), (1, 2), (2, 1), (2, 2)]:
            with self.subTest(binding=binding, visibility=visibility):
                request = symbol(bind=binding, visibility=visibility)
                guests = [library("provider.so", exports=[symbol(shndx=1)]), library(imports=[request])]
                report = check_symbols.audit(guests, {"needed": [provider()]}, CONTRACT)
                row = report["imports"][0]
                self.assertIsNone(row["provider"])
                self.assertIn("import_error", row)
                self.assertEqual(row["status"], "weak-zero" if binding == 2 else "unresolved")
                self.assertEqual(bool(report["errors"]), binding != 2)
        allowed = library(imports=[symbol(visibility=3)])
        self.assertEqual(check_symbols.audit([allowed], {"needed": [provider()]}, CONTRACT)["errors"], [])

    def test_parses_needed_and_symbol_version_requirement(self):
        result = check_symbols.read_library(self.elf_file(make_versioned_elf32()))
        self.assertEqual(result["needed"], ["libc.so"])
        self.assertEqual(result["imports"][0]["version"], "LIBC")
        self.assertEqual(result["imports"][0]["version_file"], "libc.so")
        self.assertEqual(result["imports"][0]["version_index"], 2)
        self.assertEqual(result["imports"][0]["name"], "needed")

    def test_parses_hidden_version_definition(self):
        result = check_symbols.read_library(self.elf_file(make_versioned_elf32(defined=True, hidden=True)))
        exported = result["exports"][0]
        self.assertEqual(exported["version"], "LIBC")
        self.assertTrue(exported["version_hidden"])
        self.assertEqual(exported["version_file"], "")
        self.assertFalse(check_symbols.version_matches(symbol(), exported))
        self.assertTrue(check_symbols.version_matches(symbol(version="LIBC"), exported))

    def test_rejects_missing_version_metadata(self):
        elf = make_versioned_elf32()
        table, = struct.unpack_from("<I", elf, 32)
        versions_offset, = struct.unpack_from("<I", elf, table + 5 * 40 + 16)
        struct.pack_into("<H", elf, versions_offset + 2, 9)
        with self.assertRaisesRegex(ValueError, "undefined version index"):
            check_symbols.read_library(self.elf_file(elf))

    def test_rejects_truncated_version_chain(self):
        elf = make_versioned_elf32()
        table, = struct.unpack_from("<I", elf, 32)
        struct.pack_into("<I", elf, table + 6 * 40 + 28, 2)
        with self.assertRaisesRegex(ValueError, "truncated version chain"):
            check_symbols.read_library(self.elf_file(elf))

    def test_unknown_relocation_and_missing_section_table_fail_closed(self):
        elf = bytearray(make_elf32())
        struct.pack_into("<I", elf, 0x140 + 4, 1 << 8 | 255)
        with self.assertRaisesRegex(ValueError, "unsupported ARM relocation"):
            check_symbols.read_library(self.elf_file(elf))
        struct.pack_into("<H", elf, 48, 0)
        with self.assertRaisesRegex(ValueError, "section headers"):
            check_symbols.read_library(self.elf_file(elf))

    def test_type_compatibility_is_not_name_only(self):
        for imported, exported, jump, matches in [(2, 1, True, False), (1, 2, False, False),
                (1, 0, False, False), (2, 0, True, True), (0, 2, True, True),
                (0, 1, True, False), (0, 1, False, True), (0, 0, False, True), (6, 6, False, False)]:
            with self.subTest(imported=imported, exported=exported, jump=jump):
                self.assertEqual(check_symbols.type_matches(imported, exported, [{"type": 22 if jump else 21}]), matches)

    def test_object_collision_cannot_cover_function_without_typed_bridge(self):
        name = "glBindFramebufferOES"
        guests = [library("libSDL2.so", [symbol(name)]),
                  library("libGameEngine.so", exports=[symbol(name, 1, shndx=1)])]
        report = check_symbols.audit(guests, {}, CONTRACT)
        self.assertEqual(report["summary"]["unresolved_type_rows"], 1)
        report = check_symbols.audit(guests, {name: [provider(name)]}, CONTRACT)
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["imports"][0]["status"], "bridge")
        self.assertEqual(report["rejected_candidates"][0]["reason"], "type")
        self.assertFalse(report["runtime_abi_verified"])

    def test_weak_unresolved_is_zero_but_strong_is_error(self):
        report = check_symbols.audit([library(imports=[symbol(bind=2), symbol("strong")])], {}, CONTRACT)
        self.assertEqual(report["summary"]["weak_zero_rows"], 1)
        self.assertEqual(report["summary"]["unresolved_strong_rows"], 1)

    def test_version_requires_exact_name_and_provider_library(self):
        guests = [library(imports=[symbol(version="LIBC", version_file="libc.so")], needed=["libc.so"])]
        for versions, libraries, succeeds in [(CONTRACT["version_pairs"], ["libc.so"], True),
                ([], ["libc.so"], False), (CONTRACT["version_pairs"], ["libm.so"], False)]:
            with self.subTest(versions=versions, libraries=libraries):
                contract = dict(CONTRACT, version_pairs=versions)
                report = check_symbols.audit(guests, {"needed": [provider(libraries=libraries)]}, contract)
                self.assertEqual(not report["errors"], succeeds)
        guests[0]["imports"][0]["version"] = "LIBC_FUTURE"
        self.assertTrue(check_symbols.audit(guests, {"needed": [provider()]}, CONTRACT)["errors"])

    def test_versioned_guest_export_must_match_requested_library(self):
        request = library(imports=[symbol(version="LIBC", version_file="libc.so")], needed=["libc.so"])
        for module, version, succeeds in [("libc.so", "LIBC", True), ("libc.so", "", False), ("other.so", "LIBC", False)]:
            with self.subTest(module=module, version=version):
                export = library(module, exports=[symbol(shndx=1, version=version)])
                report = check_symbols.audit([export, request], {}, CONTRACT)
                self.assertEqual(not report["errors"], succeeds)

    def test_dependencies_and_initializer_order_are_checked(self):
        guest = library(needed=["missing.so"])
        self.assertIn("unsupported DT_NEEDED", check_symbols.audit([guest], {}, CONTRACT)["errors"][0])
        guest["needed"] = ["dependency.so"]
        dependency = library("dependency.so")
        self.assertIn("must precede requester", check_symbols.audit([guest, dependency], {}, CONTRACT)["errors"][0])
        self.assertEqual(check_symbols.audit([dependency, guest], {}, CONTRACT)["errors"], [])

    def test_provider_scopes_data_policies_and_empty_helpers(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "providers.cpp"
            source.write_text('''
static constexpr const char* kBridgeSystemLibraries[] = {"libc.so", "libm.so"};
static constexpr const char* kBridgeVersionPairs[] = {"libc.so:LIBC"};
void RegisterAllThunks() {
    m_registration_libraries = {"libc.so", "libm.so"};
    RegisterLibcThunks();
}
void RegisterLibcThunks() {
    // RegisterThunk("ignored", []() {});
    const char* url = "https://example.invalid/";
    RegisterThunk("empty", [](Jit&, Host&) { /* empty */ });
    RegisterThunk("null_handler", ThunkHandler{});
    // provider-policy: blocked enosys deliberately unsupported.
    RegisterThunk("blocked", [](Jit& jit, Host&) { errno = ENOSYS; });
    // provider-policy: dns offline network disabled.
    RegisterThunk("dns", [](Jit& jit, Host&) { jit.Regs()[0] = -1; });
    // provider-policy: void_api unsupported no result is fabricated.
    RegisterThunk("void_api", [](Jit& jit, Host&) { log_unsupported(); });
    auto wrapped = [&](const char* name, auto fn) { RegisterThunk(name, fn); };
    wrapped("wrapped_empty", [](Jit&, Host&) {});
    RegisterSubThunks();
}
void RegisterSubThunks() { RegisterThunk("nested", handler); }
void DynamicData() {
    manager.RegisterDataSymbol("_ctype_", address, {"libc.so"});
    manager.RegisterSymbol("__sF", address);
}
uint32_t GetOrCreateThunkAddress(const std::string& name) {
    RegisterThunk(name, [](Jit& jit, Host&) { jit.Regs()[0] = 0; });
}
GetOrCreateThunkAddress("generated_not_provider");
''', encoding="utf-8")
            contract = check_symbols.read_contract(directory)
            self.assertEqual(contract["system_libraries"], ["libc.so", "libm.so"])
            self.assertEqual(contract["version_pairs"], ["libc.so:LIBC"])
            providers = check_symbols.registered_providers(directory)
            self.assertNotIn("ignored", providers)
            self.assertNotIn("generated_not_provider", providers)
            self.assertEqual(providers["nested"][0]["libraries"], ["libc.so", "libm.so"])
            self.assertEqual(providers["_ctype_"][0]["type"], 1)
            self.assertEqual(providers["_ctype_"][0]["libraries"], ["libc.so"])
            self.assertEqual(providers["__sF"][0]["type"], 1)
            for name in ["empty", "null_handler", "wrapped_empty"]:
                self.assertTrue(providers[name][0]["empty"], name)
            self.assertEqual(providers["blocked"][0]["policy"], "enosys")
            self.assertEqual(providers["dns"][0]["policy"], "offline")
            report = check_symbols.audit([library(imports=[symbol("empty"), symbol("blocked"), symbol("void_api")])], providers, contract)
            self.assertEqual(report["summary"]["selected_empty_rows"], 1)
            self.assertEqual(len(report["policies"]), 3)
            self.assertEqual(len(report["functional_policy_blockers"]), 3)
            self.assertTrue(report["coverage_only"])
            self.assertFalse(report["runtime_abi_verified"])


if __name__ == "__main__":
    unittest.main()
