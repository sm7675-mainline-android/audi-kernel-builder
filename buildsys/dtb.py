from __future__ import annotations

import re
import struct
import tempfile
from pathlib import Path
from typing import Any

from .common import PipelineError, run


FDT_MAGIC = 0xD00DFEED


def split_fdt_blob(data: bytes) -> list[bytes]:
    blobs: list[bytes] = []
    offset = 0
    while offset < len(data):
        if not any(data[offset:]):
            break
        if offset + 8 > len(data):
            raise PipelineError(f"truncated FDT header at offset {offset:#x}")
        magic, total_size = struct.unpack_from(">II", data, offset)
        if magic != FDT_MAGIC or total_size < 40 or offset + total_size > len(data):
            raise PipelineError(f"invalid concatenated FDT at offset {offset:#x}")
        blobs.append(data[offset:offset + total_size])
        offset += total_size
    if not blobs:
        raise PipelineError("DTB input contains no FDT blobs")
    if any(data[offset:]):
        raise PipelineError("DTB input has non-zero trailing bytes")
    return blobs


def _node_body(source: str, name: str) -> str | None:
    match = re.search(rf"(?m)^\s*{re.escape(name)}\s*\{{", source)
    if not match:
        return None
    start = source.find("{", match.start())
    depth = 0
    quoted = False
    escaped = False
    for index in range(start, len(source)):
        char = source[index]
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
            continue
        if char == '"':
            quoted = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start + 1:index]
    raise PipelineError(f"unterminated DTS node {name}")


def _property_cells(body: str, name: str) -> list[int] | None:
    match = re.search(rf"(?m)^\s*{re.escape(name)}\s*=\s*<([^>]*)>;", body)
    if not match:
        return None
    try:
        return [int(value, 0) for value in match.group(1).split()]
    except ValueError as error:
        raise PipelineError(f"invalid cell value in DTS property {name}") from error


def _normalize_reservations(config: dict[str, Any]) -> list[tuple[str, int, int]]:
    reservations = []
    for name in ("splashlog_bb", "ramoops_window"):
        entry = config.get(name)
        if not isinstance(entry, dict):
            raise PipelineError(f"missing images.dtb_reservations.{name} configuration")
        try:
            address = int(str(entry["address"]), 0)
            size = int(str(entry["size"]), 0)
        except (KeyError, ValueError) as error:
            raise PipelineError(f"invalid reservation configuration for {name}") from error
        if address < 0 or size <= 0 or address + size > 1 << 64:
            raise PipelineError(f"reservation {name} is outside the 64-bit physical range")
        reservations.append((name, address, size))
    for index, (left_name, left_address, left_size) in enumerate(reservations):
        for right_name, right_address, right_size in reservations[index + 1:]:
            if left_address < right_address + right_size and right_address < left_address + left_size:
                raise PipelineError(f"reserved regions overlap: {left_name} and {right_name}")
    return reservations


def _reservation_node(name: str, address: int, size: int) -> str:
    return (
        f"      {name}@{address:x} {{\n"
        f"        reg = <0x{address >> 32:x} 0x{address & 0xffffffff:x} "
        f"0x{size >> 32:x} 0x{size & 0xffffffff:x}>;\n"
        "      };\n"
    )


def validate_reserved_memory(
    data: bytes,
    dtc: Path,
    config: dict[str, Any],
) -> int:
    reservations = _normalize_reservations(config)
    blobs = split_fdt_blob(data)
    with tempfile.TemporaryDirectory(prefix="fdt-verify-") as temporary:
        root = Path(temporary)
        for index, blob in enumerate(blobs):
            binary = root / f"{index}.dtb"
            binary.write_bytes(blob)
            result = run([str(dtc), "-I", "dtb", "-O", "dts", str(binary)], capture=True)
            reserved = _node_body(result.stdout, "reserved-memory")
            if reserved is None:
                raise PipelineError(f"FDT {index} has no /reserved-memory node")
            if _property_cells(reserved, "#address-cells") != [2] or \
                    _property_cells(reserved, "#size-cells") != [2]:
                raise PipelineError(f"FDT {index} /reserved-memory must use 64-bit cells")
            for name, address, size in reservations:
                node = _node_body(reserved, f"{name}@{address:x}")
                if node is None:
                    raise PipelineError(f"FDT {index} lacks {name}@{address:x}")
                cells = _property_cells(node, "reg")
                expected = [address >> 32, address & 0xffffffff,
                            size >> 32, size & 0xffffffff]
                if cells != expected:
                    raise PipelineError(
                        f"FDT {index} {name} reg={cells}, expected {expected}"
                    )
                if re.search(r"(?m)^\s*(?:no-map|compatible)\s*(?:=|;)", node):
                    raise PipelineError(f"FDT {index} {name} must remain a plain reservation")
    return len(blobs)


def validate_reserved_geometry(data: bytes, dtc: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="fdt-geometry-") as temporary:
        root = Path(temporary)
        for index, blob in enumerate(split_fdt_blob(data)):
            binary = root / f"{index}.dtb"
            binary.write_bytes(blob)
            result = run([str(dtc), "-I", "dtb", "-O", "dts", str(binary)], capture=True)
            reserved = _node_body(result.stdout, "reserved-memory")
            if reserved is None:
                raise PipelineError(f"FDT {index} has no /reserved-memory node")
            if _property_cells(reserved, "#address-cells") != [2] or \
                    _property_cells(reserved, "#size-cells") != [2]:
                raise PipelineError(f"FDT {index} /reserved-memory must use 64-bit cells")


def build_reserved_vendor_boot_dtb(
    source: Path,
    destination: Path,
    dtc: Path,
    fdtoverlay: Path,
    config: dict[str, Any],
) -> int:
    if not source.is_file():
        raise PipelineError(f"vendor_boot DTB input does not exist: {source}")
    if not dtc.is_file() or not fdtoverlay.is_file():
        raise PipelineError("kernel build is missing dtc or fdtoverlay")
    reservations = _normalize_reservations(config)
    original = source.read_bytes()
    blobs = split_fdt_blob(original)
    validate_reserved_geometry(original, dtc)
    node_source = "".join(_reservation_node(name, address, size)
                          for name, address, size in reservations)
    overlay_source = (
        "/dts-v1/;\n/plugin/;\n/ {\n"
        "  fragment@0 {\n"
        '    target-path = "/reserved-memory";\n'
        "    __overlay__ {\n"
        "      #address-cells = <2>;\n"
        "      #size-cells = <2>;\n"
        f"{node_source}"
        "    };\n"
        "  };\n"
        "};\n"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fdt-reserve-", dir=destination.parent) as temporary:
        root = Path(temporary)
        source_dts = root / "reservations.dtso"
        overlay = root / "reservations.dtbo"
        source_dts.write_text(overlay_source)
        run([str(dtc), "-@", "-I", "dts", "-O", "dtb", "-o", str(overlay),
             str(source_dts)])
        patched = []
        for index, blob in enumerate(blobs):
            base = root / f"base-{index}.dtb"
            result = root / f"reserved-{index}.dtb"
            base.write_bytes(blob)
            run([str(fdtoverlay), "-i", str(base), "-o", str(result), str(overlay)])
            patched.append(result.read_bytes())
        combined = b"".join(patched)
        validate_reserved_memory(combined, dtc, config)
        temporary_output = root / "vendor_boot.dtb"
        temporary_output.write_bytes(combined)
        temporary_output.replace(destination)
    return len(blobs)
