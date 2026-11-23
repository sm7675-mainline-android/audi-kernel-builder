from __future__ import annotations

import hashlib
import os
import re
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .catalog import kernel_config_path, read_config
from .common import PipelineError, find_tool, run, sha256_file, tree_digest
from .btf import libbpf_path


LLVM_TOOLS = (
    "clang", "ld.lld", "llvm-ar", "llvm-nm", "llvm-strip",
    "llvm-objcopy", "llvm-objdump", "llvm-readelf",
)
HOST_TOOLS = (
    "make", "modinfo", "modprobe", "depmod", "cpio", "lz4", "mkfs.erofs",
    "fsck.erofs", "dump.erofs", "mkbootimg",
    "unpack_bootimg",
    "bc", "bison", "flex", "openssl", "pahole", "patch", "perl", "python3", "rsync",
)


def _git(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )


def _excluded(path: str, patterns: list[str]) -> bool:
    normalized = path.removeprefix("./")
    for pattern in patterns:
        prefix = pattern.rstrip("/*")
        if normalized == prefix or normalized.startswith(prefix + "/"):
            return True
    return False


def source_state(root: Path, excluded_paths: list[str]) -> dict[str, Any]:
    revision = _git(root, "rev-parse", "--show-prefix", "HEAD")
    if revision.returncode or not revision.stdout.startswith("\n"):
        return {
            "revision": None,
            "dirty": True,
            "dirty_paths": ["<non-git-tree>"],
            "dirty_sha256": tree_digest(root),
        }
    paths = _git(root, "diff", "--name-only", "-z", "HEAD", "--").stdout.split("\0")
    untracked = _git(root, "ls-files", "--others", "--exclude-standard", "-z").stdout.split("\0")
    changed = sorted({item for item in paths + untracked if item and not _excluded(item, excluded_paths)})
    digest = hashlib.sha256()
    if changed:
        patch = _git(root, "diff", "--binary", "HEAD", "--", ".",
                     *[f":(exclude){pattern}/**" for pattern in excluded_paths])
        digest.update(patch.stdout.encode())
        for relative in changed:
            path = root / relative
            digest.update(relative.encode() + b"\0")
            if path.is_symlink():
                digest.update(b"L\0" + os.readlink(path).encode())
            elif path.is_file():
                digest.update(b"F\0" + bytes.fromhex(sha256_file(path)))
            elif path.is_dir():
                digest.update(b"D\0")
    return {
        "revision": revision.stdout.strip(),
        "dirty": bool(changed),
        "dirty_paths": changed,
        "dirty_sha256": digest.hexdigest() if changed else None,
    }


def resolve_tools(tools_dir: Path | None, avbtool: str) -> dict[str, Path]:
    search_path = os.environ.get("PATH", "")
    if tools_dir:
        directory = tools_dir.expanduser().resolve()
        if not directory.is_dir():
            raise PipelineError(f"host tools directory does not exist: {directory}")
        search_path = str(directory) + os.pathsep + search_path
    tools = {name: find_tool(name, search_path) for name in HOST_TOOLS}
    tools["libbpf"] = libbpf_path()
    candidate = Path(avbtool).expanduser()
    if candidate.is_absolute() or candidate.parent != Path("."):
        candidate = candidate.resolve()
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            raise PipelineError(f"avbtool is not executable: {candidate}")
        tools["avbtool"] = candidate
    else:
        tools["avbtool"] = find_tool(avbtool, search_path)
    return tools


def toolchain_identity(toolchain: Path, host_tools: dict[str, Path]) -> dict[str, Any]:
    toolchain = toolchain.expanduser().resolve()
    if not toolchain.is_dir():
        raise PipelineError(f"toolchain directory does not exist: {toolchain}")
    search_path = str(toolchain)
    binaries = {}
    for name in LLVM_TOOLS:
        path = find_tool(name, search_path)
        binaries[name] = {"path": str(path), "sha256": sha256_file(path)}
    version = run([str(toolchain / "clang"), "--version"], capture=True).stdout.splitlines()
    if not version:
        raise PipelineError(f"clang returned no version information: {toolchain}")
    host = {
        name: {"path": str(path), "sha256": sha256_file(path)}
        for name, path in sorted(host_tools.items())
    }
    return {
        "path": str(toolchain),
        "clang_version": version[0],
        "binaries": binaries,
        "host_tools": host,
    }


def module_include_dirs(
    manifest: dict[str, Any], roots: dict[str, Path],
) -> list[tuple[str, Path]]:
    build = manifest.get("build", {})
    includes: list[tuple[str, Path]] = []
    for item in build.get("include_dirs", []):
        root = item["root"]
        if root not in roots:
            raise PipelineError(f"unknown include root: {root}")
        base = roots[root] / ("vendor" if root == "vendor" else "")
        include = (base / item["path"]).resolve()
        if not include.is_dir():
            raise PipelineError(f"include directory does not exist: {include}")
        includes.append((root, include))
    for entry in build.get("include_globs", []):
        if isinstance(entry, str):
            root, pattern = "vendor", entry
        elif isinstance(entry, dict):
            root = entry.get("root")
            pattern = entry.get("pattern")
        else:
            raise PipelineError(f"invalid include glob entry: {entry!r}")
        if root not in roots or not isinstance(pattern, str) or not pattern:
            raise PipelineError(f"invalid include glob entry: {entry!r}")
        base = roots[root] / ("vendor" if root == "vendor" else "")
        includes.extend(
            (root, directory.resolve())
            for directory in sorted(base.glob(pattern))
            if directory.is_dir() and directory.resolve().is_relative_to(base.resolve())
        )
    return includes


def module_kcflags(
    manifest: dict[str, Any], roots: dict[str, Path], kernel_flags: str, output: Path,
) -> str:
    include_flags = [f"-I{directory}" for _, directory in module_include_dirs(manifest, roots)]
    flags = [*dict.fromkeys(include_flags), *shlex.split(kernel_flags)]
    response = output / "build-flags/module-kcflags.rsp"
    response.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for argument in flags:
        if any(character.isspace() or character in '\\"' for character in argument):
            argument = '"' + argument.replace("\\", "\\\\").replace('"', '\\"') + '"'
        lines.append(argument)
    content = "\n".join(lines) + "\n"
    if not response.is_file() or response.read_text() != content:
        response.write_text(content)
    return f"@{response}"


def build_environment(
    manifest: dict[str, Any],
    roots: dict[str, Path],
    toolchain: Path,
    tools_dir: Path | None,
    output: Path | None = None,
) -> dict[str, str]:
    build = manifest.get("build", {})
    env = os.environ.copy()
    for name in (
        "KBUILD_EXTRA_SYMBOLS", "KBUILD_OUTPUT", "CROSS_COMPILE", "CLANG_TRIPLE",
        "CC", "LD", "AR", "NM", "STRIP", "OBJCOPY", "OBJDUMP", "READELF",
        "KCFLAGS", "MODULE_KCFLAGS", "KAFLAGS", "KCPPFLAGS", "HOSTCFLAGS", "HOSTLDFLAGS",
        "MAKEFLAGS", "KCONFIG_CONFIG",
    ):
        env.pop(name, None)
    env["PATH"] = ":".join(
        [str(toolchain.resolve())]
        + ([str(tools_dir.resolve())] if tools_dir else [])
        + [env.get("PATH", "")]
    )
    env["ARCH"] = manifest["target"].get("arch", "arm64")
    env["LLVM"] = "1"
    env["CC"] = "clang"
    env["LD"] = "ld.lld"
    env["AR"] = "llvm-ar"
    env["NM"] = "llvm-nm"
    env["STRIP"] = "llvm-strip"
    env["OBJCOPY"] = "llvm-objcopy"
    env["OBJDUMP"] = "llvm-objdump"
    env["READELF"] = "llvm-readelf"
    env["LC_ALL"] = "C"
    env["TZ"] = "UTC"
    env["SOURCE_DATE_EPOCH"] = str(build.get("source_date_epoch", 0))
    env["KBUILD_BUILD_TIMESTAMP"] = build.get(
        "build_timestamp",
        datetime.fromtimestamp(int(build.get("source_date_epoch", 0)), timezone.utc)
        .strftime("%a %b %d %H:%M:%S UTC %Y"),
    )
    env["KBUILD_BUILD_USER"] = build.get("build_user", "reproducible")
    env["KBUILD_BUILD_HOST"] = build.get("build_host", "builder")
    env["KBUILD_BUILD_VERSION"] = str(build.get("build_version", 1))
    env["LOCALVERSION"] = build.get("localversion", "")
    path_maps: list[str] = []
    for name, path in roots.items():
        for option in ("-ffile-prefix-map", "-fdebug-prefix-map", "-fmacro-prefix-map"):
            path_maps.append(f"{option}={path}=/src/{name}")
    if output is not None:
        output = output.expanduser().resolve()
        for option in ("-ffile-prefix-map", "-fdebug-prefix-map", "-fmacro-prefix-map"):
            path_maps.append(f"{option}={output}=/build/out")
    kernel_flags = list(dict.fromkeys(path_maps + build.get("kcflags", [])))
    env["KCFLAGS"] = " ".join(kernel_flags)
    env["KAFLAGS"] = " ".join(path_maps + build.get("kaflags", []))
    return env


def configure_kernel(
    args: Any,
    manifest: dict[str, Any],
    roots: dict[str, Path],
    output: Path,
    env: dict[str, str],
) -> Path:
    kernel_out = output / "kernel-out"
    kernel_out.mkdir(parents=True, exist_ok=True)
    config = kernel_config_path(Path(args.target).resolve(), manifest, roots)
    config_sha = sha256_file(config)
    marker = kernel_out / ".forge-config-sha256"
    changed = marker.exists() and marker.read_text().strip() != config_sha
    make = ["make", "-C", str(roots["kernel"]), f"O={kernel_out}",
            f"ARCH={env['ARCH']}", "LLVM=1"]
    if changed:
        if getattr(args, "reuse_output", False):
            if (kernel_out / ".config").is_file():
                (kernel_out / ".config.previous").write_bytes((kernel_out / ".config").read_bytes())
        elif (output / "modules-receipt.json").exists() or not (
            output / "module-failures.json"
        ).is_file():
            raise PipelineError(
                "kernel OUT belongs to a different config; refusing to replace completed or untracked output"
            )
        else:
            run(make + ["mrproper"], env=env, log=output / "logs/kernel-config-reset.log")
    if not marker.exists():
        if (kernel_out / ".config").exists():
            raise PipelineError("kernel OUT has no forge identity marker; choose a new --out directory")
    if changed or not (kernel_out / ".config").exists():
        (kernel_out / ".forge-config-pending").write_text(config_sha + "\n")
        if manifest["build"].get("kernel_defconfig"):
            run(make + [manifest["build"]["kernel_defconfig"]], env=env,
                log=output / "logs/kernel-defconfig.log")
        else:
            (kernel_out / ".config").write_bytes(config.read_bytes())
    run(make + ["olddefconfig"], env=env,
        log=output / "logs/kernel-olddefconfig.log")
    actual_config = read_config(kernel_out / ".config")
    for symbol in ("CONFIG_MODULES", "CONFIG_MODVERSIONS"):
        if actual_config.get(symbol) != "y":
            raise PipelineError(f"kernel config must enable {symbol}=y")
    if actual_config.get("CONFIG_F2FS_OPLUS_INODE_LAYOUT") in {"y", "m"}:
        raise PipelineError("kernel config must disable CONFIG_F2FS_OPLUS_INODE_LAYOUT")
    marker.write_text(config_sha + "\n")
    return kernel_out


def prepare_kernel(
    args: Any,
    manifest: dict[str, Any],
    roots: dict[str, Path],
    output: Path,
    env: dict[str, str],
    *,
    modpost_warn: bool = True,
) -> tuple[Path, str]:
    kernel_out = configure_kernel(args, manifest, roots, output, env)
    make = ["make", "-C", str(roots["kernel"]), f"O={kernel_out}",
            f"ARCH={env['ARCH']}", "LLVM=1"]
    jobs = str(args.jobs or manifest.get("build", {}).get("jobs", 8))
    kernel_env = env.copy()
    if modpost_warn:
        kernel_env["KBUILD_MODPOST_WARN"] = "1"
    else:
        kernel_env.pop("KBUILD_MODPOST_WARN", None)
    run(make + [f"-j{jobs}", *manifest.get("build", {}).get("kernel_targets", ["Image", "modules"])],
        env=kernel_env, log=output / "logs/kernel-build.log")
    release = run(make + ["-s", "kernelrelease"], env=kernel_env,
                  capture=True).stdout.strip()
    if not release:
        raise PipelineError("kernelrelease command returned an empty value")
    for artifact in (kernel_out / "Module.symvers", kernel_out / "System.map"):
        if not artifact.is_file():
            raise PipelineError(f"kernel build did not produce {artifact.name}")
    (output / "kernelrelease.txt").write_text(release + "\n")
    (kernel_out / ".forge-config-pending").unlink(missing_ok=True)
    return kernel_out, release
