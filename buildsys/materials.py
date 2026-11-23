from __future__ import annotations

import tarfile
from pathlib import Path
from typing import Any

from .catalog import load_toml, read_module_list
from .common import PipelineError, sha256_file


VENDOR_BOOT_FILES = ("vendor_ramdisk.tar", "vendor_boot.dtb", "vendor_boot.bootconfig")
DLKM_ETC_FILES = ("NOTICE.xml.gz", "build.prop", "fs_config_dirs", "fs_config_files")
VENDOR_POLICY = ("modules.blocklist", "system_dlkm.modules.blocklist",
                 "vendor_boot.softdep", "vendor_dlkm.softdep")


def target_file(target: Path, relative: str) -> Path:
    path = (target.parent / relative).resolve()
    if not path.is_relative_to(target.parent.resolve()) or not path.is_file():
        raise PipelineError(f"missing or invalid target file: {relative}")
    return path


def system_modules(target: Path, manifest: dict[str, Any]) -> list[str]:
    path = target_file(target, manifest["images"]["system_dlkm"]["modules_list"])
    names = read_module_list(path)
    if not names:
        raise PipelineError(f"empty system_dlkm module list: {path}")
    return names


def check_materials(target: Path, manifest: dict[str, Any], root: Path,
                    partition: str) -> dict[str, str]:
    lock_path = target_file(target, manifest["images"]["materials_lock"])
    lock = load_toml(lock_path)
    if lock.get("schema") != 1:
        raise PipelineError(f"unsupported device material lock: {lock_path}")
    if partition == "vendor_boot":
        names = VENDOR_BOOT_FILES
    elif partition in ("vendor_dlkm", "system_dlkm"):
        names = tuple(f"{partition}/etc/{name}" for name in DLKM_ETC_FILES)
    else:
        raise PipelineError(f"unknown device material partition: {partition}")
    result = {}
    for name in names:
        path = root / name
        if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
            raise PipelineError(f"missing or invalid device material: {path}")
        digest = sha256_file(path)
        if digest != lock.get("files", {}).get(name):
            raise PipelineError(f"device material SHA-256 differs from lock: {path}")
        result[name] = digest
    return result


def unpack_vendor_ramdisk(archive: Path, destination: Path) -> None:
    def ramdisk_filter(member: tarfile.TarInfo, root: str) -> tarfile.TarInfo:
        filtered = tarfile.data_filter(member, root)
        parts = Path(filtered.name).parts
        if (parts[:2] == ("lib", "modules") or ".." in parts
                or filtered.name.endswith((".ko", ".ko.gz", ".ko.xz", ".ko.zst"))):
            raise PipelineError(f"vendor ramdisk material contains a module path: {member.name}")
        return filtered.replace(mode=member.mode & 0o777)

    destination.mkdir(parents=True)
    try:
        with tarfile.open(archive) as stream:
            stream.extractall(destination, filter=ramdisk_filter)
    except (tarfile.TarError, OSError) as error:
        raise PipelineError(f"cannot extract vendor ramdisk material {archive}: {error}") from error
