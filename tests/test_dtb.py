from __future__ import annotations

import struct
import unittest

from buildsys.common import PipelineError
from buildsys.dtb import _normalize_reservations, _node_body, split_fdt_blob


def fdt_blob(payload: bytes = b"") -> bytes:
    size = 40 + len(payload)
    return struct.pack(">II", 0xD00DFEED, size) + bytes(32) + payload


class DtbTests(unittest.TestCase):
    def test_splits_concatenated_fdt_and_zero_padding(self) -> None:
        first = fdt_blob(b"first")
        second = fdt_blob(b"second")
        self.assertEqual(split_fdt_blob(first + second + bytes(64)), [first, second])

    def test_rejects_invalid_fdt_and_nonzero_tail(self) -> None:
        with self.assertRaises(PipelineError):
            split_fdt_blob(b"not a dtb")
        with self.assertRaises(PipelineError):
            split_fdt_blob(fdt_blob() + b"x")

    def test_reservation_nodes_must_not_overlap(self) -> None:
        config = {
            "splashlog_bb": {"address": "0x1000", "size": "0x1000"},
            "ramoops_window": {"address": "0x1800", "size": "0x1000"},
        }
        with self.assertRaisesRegex(PipelineError, "overlap"):
            _normalize_reservations(config)

    def test_node_body_handles_nested_nodes_and_quoted_braces(self) -> None:
        source = 'reserved-memory { label = "}"; child@0 { reg = <0 1>; }; };'
        self.assertEqual(_node_body(source, "reserved-memory"),
                         ' label = "}"; child@0 { reg = <0 1>; }; ')


if __name__ == "__main__":
    unittest.main()
