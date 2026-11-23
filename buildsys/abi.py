from __future__ import annotations

import re
import struct
import subprocess
from pathlib import Path

from .common import PipelineError


def _tool_output(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        raise PipelineError(f"ABI inspection failed: {command!r}\n{result.stderr}")
    return result.stdout


def exported_crcs(path: Path, nm: Path) -> dict[str, int]:
    with path.open("rb") as stream:
        header = stream.read(64)
        if header[:6] != b"\x7fELF\x02\x01":
            raise PipelineError(f"expected a little-endian ELF64 file: {path}")
        section_offset = struct.unpack_from("<Q", header, 40)[0]
        section_size, section_count, names_index = struct.unpack_from("<HHH", header, 58)
        stream.seek(section_offset)
        section_data = stream.read(section_size * section_count)
        sections = [struct.unpack_from("<IIQQQQIIQQ", section_data, index * section_size)
                    for index in range(section_count)]
        names_section = sections[names_index]
        stream.seek(names_section[4])
        names = stream.read(names_section[5])
        crc_section = next((section for section in sections
                            if names[section[0]:].split(b"\0", 1)[0] == b"__kcrctab"), None)
        if crc_section is None:
            return {}
        stream.seek(crc_section[4])
        crc_data = stream.read(crc_section[5])
    exports = {}
    for line in _tool_output([str(nm), str(path)]).splitlines():
        match = re.match(r"^([0-9a-fA-F]+)\s+\w\s+__crc_(\S+)$", line)
        if not match:
            continue
        offset = int(match[1], 16) - crc_section[3]
        if 0 <= offset <= len(crc_data) - 4:
            exports[match[2]] = struct.unpack_from("<I", crc_data, offset)[0]
    return exports


def import_failures(
    module: str,
    imports: dict[str, int],
    kernel: dict[str, int],
    providers: dict[str, list[tuple[str, int]]],
) -> list[str]:
    failures = []
    for symbol, crc in imports.items():
        available = ([("vmlinux", kernel[symbol])] if symbol in kernel
                     else providers.get(symbol, []))
        if not available:
            failures.append(f"{module}: missing provider {symbol}")
        elif any(value != crc for _, value in available):
            detail = ", ".join(f"{name}={value:#010x}" for name, value in available)
            failures.append(f"{module}: CRC mismatch {symbol}: import={crc:#010x}; {detail}")
    return failures


def imported_crcs(path: Path, modprobe: Path) -> dict[str, int]:
    imports = {}
    for line in _tool_output([str(modprobe), "--show-modversions", str(path)]).splitlines():
        crc, symbol = line.split()
        imports[symbol] = int(crc, 16)
    return imports


def relocation_failures(path: Path) -> list[str]:
    supported = {0, *range(256, 281), *range(282, 294), 299}
    failures = []
    with path.open("rb") as stream:
        header = stream.read(64)
        if header[:6] != b"\x7fELF\x02\x01" or len(header) != 64:
            raise PipelineError(f"relocation inspection requires little-endian ELF64: {path}")
        if struct.unpack_from("<HH", header, 16) != (1, 183):
            return [f"{path.name}: expected an AArch64 relocatable module"]
        section_offset = struct.unpack_from("<Q", header, 40)[0]
        section_size, section_count, names_index = struct.unpack_from("<HHH", header, 58)
        stream.seek(section_offset)
        section_data = stream.read(section_size * section_count)
        sections = [struct.unpack_from("<IIQQQQIIQQ", section_data, index * section_size)
                    for index in range(section_count)]
        names_section = sections[names_index]
        stream.seek(names_section[4])
        names = stream.read(names_section[5])
        for section in sections:
            if section[1] != 4 or not sections[section[7]][2] & 2:
                continue
            target = sections[section[7]]
            target_name = names[target[0]:].split(b"\0", 1)[0].decode()
            stream.seek(section[4])
            data = stream.read(section[5])
            for relocation_type in sorted({info & 0xFFFFFFFF
                                           for _, info, _ in struct.iter_unpack("<QQq", data)}
                                          - supported):
                failures.append(f"{path.name}: unsupported AArch64 RELA relocation "
                                f"{relocation_type} in {target_name}")
    return failures


def audit_modules(
    vmlinux: Path, modules: list[Path], release: str, tools: dict[str, Path],
) -> dict:
    kernel = exported_crcs(vmlinux, tools["llvm-nm"])
    if not kernel:
        raise PipelineError("vmlinux has no CRC exports; cannot verify delivered module ABI")
    providers: dict[str, list[tuple[str, int]]] = {}
    for module in modules:
        for symbol, crc in exported_crcs(module, tools["llvm-nm"]).items():
            providers.setdefault(symbol, []).append((module.name, crc))
    failures = []
    imports_count = 0
    for module in modules:
        failures.extend(relocation_failures(module))
        vermagic = _tool_output([str(tools["modinfo"]), "-F", "vermagic", str(module)]).split()
        if not vermagic or vermagic[0] != release:
            failures.append(f"{module.name}: vermagic does not match {release}")
        imports = imported_crcs(module, tools["modprobe"])
        if "module_layout" not in imports:
            failures.append(f"{module.name}: missing module_layout CRC")
        imports_count += len(imports)
        failures.extend(import_failures(module.name, imports, kernel, providers))
    return {"module_count": len(modules), "imports": imports_count,
            "kernelrelease": release, "failures": failures}
