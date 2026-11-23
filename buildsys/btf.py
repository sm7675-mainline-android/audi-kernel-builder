from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import struct
from pathlib import Path

from .common import PipelineError


def btf_sections(path: Path) -> dict[str, bytes]:
    with path.open("rb") as stream:
        header = stream.read(64)
        if header[:6] != b"\x7fELF\x02\x01":
            raise PipelineError(f"BTF inspection requires little-endian ELF64: {path}")
        offset = struct.unpack_from("<Q", header, 40)[0]
        size, count, names_index = struct.unpack_from("<HHH", header, 58)
        stream.seek(offset)
        data = stream.read(size * count)
        sections = [struct.unpack_from("<IIQQQQIIQQ", data, index * size)
                    for index in range(count)]
        names_section = sections[names_index]
        stream.seek(names_section[4])
        names = stream.read(names_section[5])
        result = {}
        for section in sections:
            name = names[section[0]:].split(b"\0", 1)[0].decode()
            if name in (".BTF", ".BTF.base"):
                stream.seek(section[4])
                result[name] = stream.read(section[5])
        return result


def base_btf_sha256(vmlinux: Path) -> str:
    data = btf_sections(vmlinux).get(".BTF")
    if not data:
        raise PipelineError(f"kernel has no base BTF: {vmlinux}")
    return hashlib.sha256(data).hexdigest()


def _libbpf() -> ctypes.CDLL:
    name = ctypes.util.find_library("bpf")
    if not name:
        raise PipelineError("BTF validation requires the host libbpf shared library")
    return ctypes.CDLL(name)


def libbpf_path() -> Path:
    library = _libbpf()
    class DlInfo(ctypes.Structure):
        _fields_ = [("filename", ctypes.c_char_p), ("base", ctypes.c_void_p),
                    ("symbol", ctypes.c_char_p), ("address", ctypes.c_void_p)]
    loader = ctypes.CDLL(None)
    loader.dladdr.argtypes = [ctypes.c_void_p, ctypes.POINTER(DlInfo)]
    loader.dladdr.restype = ctypes.c_int
    info = DlInfo()
    if not loader.dladdr(ctypes.cast(library.btf__parse, ctypes.c_void_p), ctypes.byref(info)):
        raise PipelineError("cannot resolve loaded libbpf for the toolchain receipt")
    return Path(info.filename.decode()).resolve()


class BtfValidator:
    def __init__(self, vmlinux: Path):
        self.library = _libbpf()
        for name, arguments, result in (
            ("btf__parse", [ctypes.c_char_p, ctypes.c_void_p], ctypes.c_void_p),
            ("btf__parse_split", [ctypes.c_char_p, ctypes.c_void_p], ctypes.c_void_p),
            ("libbpf_get_error", [ctypes.c_void_p], ctypes.c_long),
            ("btf__free", [ctypes.c_void_p], None),
        ):
            function = getattr(self.library, name)
            function.argtypes, function.restype = arguments, result
        self.base = self.library.btf__parse(bytes(vmlinux), None)
        error = self.library.libbpf_get_error(self.base)
        if not self.base or error:
            raise PipelineError(f"cannot parse kernel BTF: {vmlinux}, error={error}")

    def __enter__(self) -> BtfValidator:
        return self

    def __exit__(self, *unused) -> None:
        self.library.btf__free(self.base)

    def check(self, module: Path) -> str | None:
        split = self.library.btf__parse_split(bytes(module), self.base)
        error = self.library.libbpf_get_error(split)
        if not split or error:
            return f"{module.name}: split BTF cannot use current vmlinux (libbpf error={error})"
        self.library.btf__free(split)
        return None


def audit_btf(vmlinux: Path, modules: list[Path]) -> dict:
    failures, invalid, skipped = [], [], []
    with BtfValidator(vmlinux) as validator:
        for module in modules:
            if ".BTF" not in btf_sections(module):
                skipped.append(module.name)
                continue
            error = validator.check(module)
            if error:
                failures.append(error)
                invalid.append(module.name)
    return {"base_btf_sha256": base_btf_sha256(vmlinux), "module_count": len(modules),
            "checked": len(modules) - len(skipped), "without_btf": skipped,
            "invalid_modules": invalid, "failures": failures}


def stale_split_modules(modules: list[Path], previous_base: str | None, current_base: str) -> set[str]:
    if previous_base == current_base:
        return set()
    return {module.stem for module in modules
            if ".BTF" in (sections := btf_sections(module)) and ".BTF.base" not in sections}
