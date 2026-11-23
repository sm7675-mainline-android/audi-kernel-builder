from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from buildsys.btf import audit_btf, base_btf_sha256, stale_split_modules


def write_elf(path: Path, sections: dict[str, bytes]) -> None:
    names = b"\0.shstrtab\0"
    for name in sections:
        names += name.encode() + b"\0"
    payloads = {".shstrtab": names, **sections}
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", header, 16, 1, 183, 1)
    struct.pack_into("<Q", header, 40, 64)
    struct.pack_into("<H", header, 52, 64)
    struct.pack_into("<HHH", header, 58, 64, len(payloads) + 1, 1)
    offset = 64 + 64 * (len(payloads) + 1)
    table, data = bytes(64), b""
    for name, value in payloads.items():
        table += struct.pack("<IIQQQQIIQQ", names.index(name.encode()),
                             3 if name == ".shstrtab" else 1, 0, 0,
                             offset, len(value), 0, 0, 1, 0)
        data += value
        offset += len(value)
    path.write_bytes(header + table + data)


def integer_btf(name_offset: int, strings: bytes) -> bytes:
    record = struct.pack("<IIII", name_offset, 1 << 24, 4, 32)
    return struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(record),
                       len(record), len(strings)) + record + strings


class BtfCacheTests(unittest.TestCase):
    def test_split_string_offsets_checked_against_current_kernel(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base, module = root / "vmlinux", root / "cmd-db.ko"
            write_elf(base, {".BTF": integer_btf(1, b"\0int\0")})
            write_elf(module, {".BTF": integer_btf(6, b"\0local\0")})
            self.assertEqual(audit_btf(base, [module])["failures"], [])
            write_elf(module, {".BTF": integer_btf(1000, b"\0local\0")})
            report = audit_btf(base, [module])
            self.assertEqual(report["invalid_modules"], ["cmd-db.ko"])

    def test_changed_base_invalidates_non_distilled_cache_even_if_parseable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base, module = root / "vmlinux", root / "module.ko"
            write_elf(base, {".BTF": integer_btf(1, b"\0int\0")})
            first = base_btf_sha256(base)
            write_elf(module, {".BTF": integer_btf(6, b"\0local\0")})
            self.assertEqual(stale_split_modules([module], first, first), set())
            write_elf(base, {".BTF": integer_btf(1, b"\0uint\0")})
            self.assertEqual(stale_split_modules([module], first, base_btf_sha256(base)),
                             {"module"})

    def test_distilled_modules_are_validated_by_relocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base, module = root / "vmlinux", root / "module.ko"
            original = integer_btf(1, b"\0int\0")
            write_elf(base, {".BTF": integer_btf(8, b"\0unused\0int\0")})
            write_elf(module, {".BTF": integer_btf(6, b"\0local\0"), ".BTF.base": original})
            self.assertEqual(stale_split_modules([module], "old", "new"), set())
            self.assertEqual(audit_btf(base, [module])["failures"], [])

    def test_module_without_btf_is_explicitly_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base, module = root / "vmlinux", root / "no-btf.ko"
            write_elf(base, {".BTF": integer_btf(1, b"\0int\0")})
            write_elf(module, {})
            report = audit_btf(base, [module])
            self.assertEqual(report["checked"], 0)
            self.assertEqual(report["without_btf"], ["no-btf.ko"])
