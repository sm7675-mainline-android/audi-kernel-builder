from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from buildsys.abi import exported_crcs, import_failures, relocation_failures


class DeliveredAbiTests(unittest.TestCase):
    def test_module_provider_crc_is_checked(self) -> None:
        failures = import_failures("camcc.ko", {"qcom_cc_map": 1}, {},
                                   {"qcom_cc_map": [("clk-qcom.ko", 2)]})
        self.assertEqual(len(failures), 1)
        self.assertIn("CRC mismatch qcom_cc_map", failures[0])
        self.assertIn("clk-qcom.ko=0x00000002", failures[0])

    def test_unshipped_provider_does_not_satisfy_import(self) -> None:
        failures = import_failures("clk-qcom.ko", {"clk_debug_mux_ops": 1}, {}, {})
        self.assertEqual(failures, ["clk-qcom.ko: missing provider clk_debug_mux_ops"])

    def test_kernel_export_takes_precedence_over_module(self) -> None:
        self.assertTrue(import_failures("consumer.ko", {"symbol": 1}, {"symbol": 2},
                                        {"symbol": [("provider.ko", 1)]}))
        self.assertEqual(import_failures("consumer.ko", {"symbol": 1}, {"symbol": 1}, {}), [])

    def test_matching_module_provider_is_accepted(self) -> None:
        self.assertEqual(import_failures("consumer.ko", {"symbol": 7}, {},
                                         {"symbol": [("provider.ko", 7)]}), [])

    def relocation_module(self, path: Path, types: list[int], target_flags: int = 2,
                          relocation_flags: int = 0) -> None:
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<HH", header, 16, 1, 183)
        struct.pack_into("<Q", header, 40, 64)
        struct.pack_into("<HHH", header, 58, 64, 4, 1)
        names = b"\0.shstrtab\0.text\0.rela.text\0"
        names_offset = 64 + 4 * 64
        data_offset = names_offset + len(names)
        relocations = b"".join(struct.pack("<QQq", 0, (1 << 32) | kind, 0) for kind in types)
        sections = bytes(64)
        sections += struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, names_offset,
                                len(names), 0, 0, 1, 0)
        sections += struct.pack("<IIQQQQIIQQ", 11, 1, target_flags, 0, data_offset,
                                0, 0, 0, 4, 0)
        sections += struct.pack("<IIQQQQIIQQ", 17, 4, relocation_flags, 0, data_offset,
                                len(relocations), 0, 2, 8, 24)
        path.write_bytes(header + sections + names + relocations)

    def test_weak_symbol_got_relocations_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oplus_chg_v2.ko"
            self.relocation_module(path, [311, 312, 311, 283])
            self.assertEqual(relocation_failures(path), [
                "oplus_chg_v2.ko: unsupported AArch64 RELA relocation 311 in .text",
                "oplus_chg_v2.ko: unsupported AArch64 RELA relocation 312 in .text",
            ])

    def test_debug_relocations_are_not_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "module.ko"
            self.relocation_module(path, [311, 312], target_flags=0, relocation_flags=2)
            self.assertEqual(relocation_failures(path), [])

    def test_arm64_kernel_relocations_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "module.ko"
            self.relocation_module(path, [0, *range(256, 281), *range(282, 294), 299])
            self.assertEqual(relocation_failures(path), [])

    @patch("buildsys.abi._tool_output")
    def test_crc_reading_handles_relocatable_and_linked_elf(self, output) -> None:
        for address in (0, 0xFFFF800010000000):
            with self.subTest(address=address), tempfile.TemporaryDirectory() as directory:
                header = bytearray(64)
                header[:6] = b"\x7fELF\x02\x01"
                struct.pack_into("<Q", header, 40, 64)
                struct.pack_into("<HHH", header, 58, 64, 3, 1)
                names = b"\0.shstrtab\0__kcrctab\0"
                names_offset = 64 + 3 * 64
                crc_offset = names_offset + len(names)
                sections = bytes(64)
                sections += struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, names_offset,
                                        len(names), 0, 0, 1, 0)
                sections += struct.pack("<IIQQQQIIQQ", 11, 1, 0, address, crc_offset,
                                        8, 0, 0, 4, 0)
                path = Path(directory) / "module"
                path.write_bytes(header + sections + names + struct.pack("<II", 7, 19))
                output.return_value = f"{address + 4:016x} R __crc_qcom_cc_map\n"
                self.assertEqual(exported_crcs(path, Path("llvm-nm")), {"qcom_cc_map": 19})
