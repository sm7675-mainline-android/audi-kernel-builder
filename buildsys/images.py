from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
from pathlib import Path
from typing import Any

from .common import PipelineError, ensure_output_path, find_tool, run, sha256_file, temporary_directory, write_json
from .dtb import build_reserved_vendor_boot_dtb, validate_reserved_memory
from .materials import DLKM_ETC_FILES, system_modules, unpack_vendor_ramdisk
from .recovery import recovery_dependencies, recovery_module_order, verify_recovery_contents


def _copy_modules(source: Path, destination: Path, names: list[str]) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for name in names:
        source_path = source / f"{name}.ko"
        if not source_path.is_file():
            raise PipelineError(f"missing built module for staging: {source_path}")
        shutil.copy2(source_path, destination / source_path.name)


def _depmod(module_dir: Path, version: str, workspace: Path, depmod: Path) -> None:
    with temporary_directory(workspace, "depmod-") as temp:
        version_dir = temp / "lib/modules" / version
        version_dir.mkdir(parents=True)
        for module in sorted(module_dir.glob("*.ko")):
            shutil.copy2(module, version_dir / module.name)
        run([str(depmod), "-b", str(temp), version])
        for name in ("modules.dep", "modules.alias", "modules.softdep"):
            source = version_dir / name
            if source.is_file():
                shutil.copy2(source, module_dir / name)
    _sanitize_module_aliases(module_dir / "modules.alias")


def _sanitize_module_aliases(path: Path) -> None:
    if not path.is_file():
        return
    lines = []
    for raw in path.read_text(errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            lines.append(raw)
            continue
        parts = line.split()
        if len(parts) == 3 and parts[0] == "alias":
            lines.append(line)
    path.write_text("\n".join(lines) + ("\n" if lines else ""))


def _copy_metadata(source: Path, destination: Path, names: list[str]) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for name in names:
        path = source / name
        if path.is_file():
            shutil.copy2(path, destination / name)


def _merge_softdep(destination: Path, *sources: Path) -> None:
    entries: dict[str, dict[str, list[str]]] = {}
    for source in sources:
        if not source.is_file():
            continue
        for raw in source.read_text(errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2 or parts[0] != "softdep":
                continue
            module = parts[1]
            current = None
            entry = entries.setdefault(module, {"pre": [], "post": []})
            for token in parts[2:]:
                if token in ("pre:", "post:"):
                    current = token[:-1]
                elif token.startswith(("pre:", "post:")):
                    current = token.split(":", 1)[0]
                    dependency = token.split(":", 1)[1]
                    if dependency and dependency not in entry[current]:
                        entry[current].append(dependency)
                elif current and token not in entry[current]:
                    entry[current].append(token)
    lines = []
    for module, parts in entries.items():
        if not parts["pre"] and not parts["post"]:
            continue
        line = f"softdep {module}"
        if parts["pre"]:
            line += " pre: " + " ".join(parts["pre"])
        if parts["post"]:
            line += " post: " + " ".join(parts["post"])
        lines.append(line)
    (destination / "modules.softdep").write_text("\n".join(lines) + ("\n" if lines else ""))


def _has_xattr(output: str) -> bool:
    for line in output.splitlines():
        if "Xattr size:" not in line:
            continue
        values = line.split("Xattr size:", 1)[1].strip().split(maxsplit=1)
        if not values:
            continue
        try:
            if int(values[0]) > 0:
                return True
        except ValueError:
            continue
    return False


def stage_images(
    manifest: dict[str, Any],
    plan: dict[str, Any],
    output: Path,
    materials: Path,
    policy: Path,
    kernelrelease: str,
    tools: dict[str, Path],
    recovery_modules: list[str] | None = None,
) -> dict[str, Path]:
    staging = ensure_output_path(output, output / "staging")
    if staging.exists():
        shutil.rmtree(staging)
    boot_stage = staging / "vendor_boot"
    unpack_vendor_ramdisk(materials / "vendor_ramdisk.tar", boot_stage)
    boot_modules = boot_stage / "lib/modules"
    boot_softdep = policy / "vendor_boot.softdep"
    dlkm_softdep = policy / "vendor_dlkm.softdep"
    recovery = list(plan["vendor_boot"])
    if recovery_modules is not None:
        recovery = recovery_module_order(
            output / "modules-stripped", [*plan["vendor_boot"], *recovery_modules],
            tools["modinfo"], [boot_softdep, dlkm_softdep],
            dependencies=recovery_dependencies(output / "modules-stripped", kernelrelease,
                                               output / "tmp", tools["depmod"]),
        )
    _copy_modules(output / "modules-stripped", boot_modules, recovery)
    _depmod(boot_modules, kernelrelease, output / "tmp", tools["depmod"])
    _copy_metadata(
        policy, boot_modules,
        ["modules.blocklist"],
    )
    (boot_modules / "modules.load").write_text(
        "".join(f"{name}\n" for name in plan["vendor_boot"])
    )
    (boot_modules / "modules.load.recovery").write_text(
        "".join(f"{name}.ko\n" for name in recovery)
    )

    dlkm_stage = staging / "vendor_dlkm"
    _stage_dlkm_etc(materials, "vendor_dlkm", dlkm_stage)
    dlkm_modules = dlkm_stage / "lib/modules"
    _copy_modules(output / "modules-stripped", dlkm_modules, plan["vendor_dlkm"])
    _depmod(dlkm_modules, kernelrelease, output / "tmp", tools["depmod"])
    _copy_metadata(
        policy, dlkm_modules,
        ["modules.blocklist", "system_dlkm.modules.blocklist"],
    )
    _merge_softdep(
        dlkm_modules,
        dlkm_softdep,
        dlkm_modules / "modules.softdep",
    )
    (dlkm_modules / "modules.load").write_text(
        "".join(f"{name}\n" for name in plan["vendor_dlkm"])
    )
    _merge_softdep(
        boot_modules,
        boot_softdep,
        dlkm_softdep,
        boot_modules / "modules.softdep",
    )
    epoch = int(manifest.get("build", {}).get("source_date_epoch", 0))
    _normalize_mtimes(boot_stage, epoch)
    _normalize_mtimes(dlkm_stage, epoch)
    return {"vendor_boot": boot_stage, "vendor_dlkm": dlkm_stage}


def _normalize_mtimes(root: Path, epoch: int) -> None:
    paths = list(root.rglob("*"))
    paths.sort(key=lambda path: len(path.parts), reverse=True)
    for path in paths:
        os.utime(path, (epoch, epoch), follow_symlinks=False)
    os.utime(root, (epoch, epoch), follow_symlinks=False)


def _stage_dlkm_etc(materials: Path, partition: str, staging: Path) -> None:
    etc = staging / "etc"
    etc.mkdir(parents=True)
    for name in DLKM_ETC_FILES:
        destination = etc / name
        shutil.copyfile(materials / partition / "etc" / name, destination)
        destination.chmod(0o644)


def _write_dlkm_tar(stage: Path, archive: Path, config: dict[str, Any], epoch: int) -> None:
    with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as stream:
        for path in [stage, *sorted(stage.rglob("*"))]:
            relative = path.relative_to(stage)
            info = stream.gettarinfo(str(path), arcname=relative.as_posix())
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = epoch
            label = config["selinux_label"]
            if relative.parts[:1] == ("etc",):
                label = config.get("etc_selinux_label", label)
            info.pax_headers["SCHILY.xattr.security.selinux"] = label
            if info.isfile():
                with path.open("rb") as content:
                    stream.addfile(info, content)
            else:
                stream.addfile(info)


def check_erofs_tool(tool: Path) -> None:
    result = run([str(tool), "--help"], capture=True)
    if "--tar=" not in result.stdout + result.stderr:
        raise PipelineError(f"{tool} does not support --tar=f for rootless SELinux labeling")


def _build_dlkm_erofs(stage: Path, image: Path, config: dict[str, Any], tools: dict[str, Path],
                     epoch: int, modules_load: str) -> None:
    check_erofs_tool(tools["mkfs.erofs"])
    temporary = image.with_name(f".{image.name}.tmp")
    temporary.unlink(missing_ok=True)
    with temporary_directory(image.parent.parent, "dlkm-erofs-") as work:
        archive = work / "staging.tar"
        _write_dlkm_tar(stage, archive, config, epoch)
        run([str(tools["mkfs.erofs"]), "-z", config["compression"], "-b", str(config["block_size"]),
             "--mount-point=" + config["mount_point"], "--all-root", "-U", config["uuid"],
             "-T", str(epoch), "--all-time", "--sort=path", "--workers=1", "--tar=f",
             str(temporary), str(archive)])
    run([str(tools["fsck.erofs"]), str(temporary)])
    result = run([str(tools["dump.erofs"]), f"--path={modules_load}", str(temporary)], capture=True)
    if not _has_xattr(result.stdout):
        raise PipelineError(f"{image.stem} modules.load is missing its SELinux xattr")
    limit = int(config.get("partition_size", 0))
    if limit and temporary.stat().st_size > limit:
        raise PipelineError(f"{image.stem} image exceeds partition size: {temporary.stat().st_size} > {limit}")
    os.replace(temporary, image)


def _cpio(stage: Path, output: Path, cpio_tool: Path) -> Path:
    cpio = output / "vendor_boot.ramdisk.cpio"
    names = output / "vendor_boot.ramdisk.names"
    entries = sorted(path.relative_to(stage).as_posix() for path in stage.rglob("*"))
    names.write_text("\0".join(entries) + "\0")
    with cpio.open("wb") as stream, names.open("rb") as name_stream:
        result = subprocess.run(
            [str(cpio_tool), "--null", "--create", "--format=newc", "--owner=0:0", "--reproducible"],
            cwd=stage, stdin=name_stream, stdout=stream, stderr=subprocess.PIPE,
        )
    if result.returncode:
        raise PipelineError("cpio failed: " + result.stderr.decode(errors="replace"))
    return cpio


def _avb_footer(image: Path, config: dict[str, Any], avbtool: Path) -> None:
    run([
        str(avbtool), "add_hash_footer", "--image", str(image),
        "--partition_size", str(config["partition_size"]),
        "--partition_name", "vendor_boot", "--hash_algorithm", "sha256",
        "--salt", config["avb_salt"], "--algorithm", "NONE",
        "--prop", config["avb_property"],
    ])


def _verify_staged_fsck(materials: Path, staged_vendor_boot: Path) -> None:
    fsck_path = Path("system/bin/fsck.f2fs")
    staged_fsck = staged_vendor_boot / fsck_path
    with tarfile.open(materials / "vendor_ramdisk.tar") as archive:
        member = next((item for item in archive if Path(item.name) == fsck_path), None)
        if member is None:
            return
        stock_fsck = archive.extractfile(member)
        if stock_fsck is None:
            raise PipelineError("device materials fsck.f2fs is not a file")
        with stock_fsck:
            matches = staged_fsck.is_file() and staged_fsck.read_bytes() == stock_fsck.read()
    if not matches:
        raise PipelineError("staged fsck.f2fs differs from device materials; run stage again")


def build_images(
    materials: Path,
    manifest: dict[str, Any],
    output: Path,
    staging: dict[str, Path],
    tools: dict[str, Path],
    partition: str = "all",
) -> dict[str, Path]:
    if partition in ("all", "vendor_boot"):
        _verify_staged_fsck(materials, staging["vendor_boot"])

    images = output / "images"
    images.mkdir(parents=True, exist_ok=True)
    build = manifest.get("build", {})
    epoch = int(build.get("source_date_epoch", 0))
    dlkm_config = manifest["images"]["vendor_dlkm"]
    boot_config = manifest["images"]["vendor_boot"]
    output_images: dict[str, Path] = {}
    if partition in ("all", "vendor_dlkm"):
        image = images / "vendor_dlkm.img"
        _build_dlkm_erofs(staging["vendor_dlkm"], image, dlkm_config, tools, epoch,
                         "/lib/modules/modules.load")
        output_images["vendor_dlkm"] = image

    if partition in ("all", "vendor_boot"):
        cpio = _cpio(staging["vendor_boot"], output, tools["cpio"])
        compressed = output / "vendor_boot.ramdisk.cpio.lz4"
        run([str(tools["lz4"]), "-l", "-12", "-f", str(cpio), str(compressed)])
        dtb_source = materials / "vendor_boot.dtb"
        bootconfig = materials / "vendor_boot.bootconfig"
        dtb = output / "vendor_boot.dtb"
        dtc_dir = output / "kernel-out/scripts/dtc"
        fdt_count = build_reserved_vendor_boot_dtb(
            dtb_source, dtb, dtc_dir / "dtc", dtc_dir / "fdtoverlay",
            manifest["images"]["dtb_reservations"],
        )
        expected_fdt_count = manifest["images"]["dtb_reservations"].get("fdt_count")
        if expected_fdt_count is not None and fdt_count != int(expected_fdt_count):
            raise PipelineError(
                f"expected {expected_fdt_count} vendor_boot FDTs, found {fdt_count}"
            )
        reservations = manifest["images"]["dtb_reservations"]
        write_json(output / "vendor_boot-dtb.json", {
            "base_sha256": sha256_file(dtb_source),
            "sha256": sha256_file(dtb),
            "fdt_count": fdt_count,
            "reservations": reservations,
        })
        boot_image = images / "vendor_boot.img"
        temporary = images / ".vendor_boot.img.tmp"
        temporary.unlink(missing_ok=True)
        run([
            str(tools["mkbootimg"]), "--header_version", str(boot_config["header_version"]),
            "--pagesize", str(boot_config["pagesize"]), "--base", boot_config["base"],
            "--kernel_offset", boot_config["kernel_offset"], "--ramdisk_offset", boot_config["ramdisk_offset"],
            "--tags_offset", boot_config["tags_offset"], "--dtb_offset", boot_config["dtb_offset"],
            "--vendor_cmdline", boot_config["vendor_cmdline"], "--board", "", "--dtb", str(dtb),
            "--vendor_bootconfig", str(bootconfig), "--ramdisk_type", "1", "--ramdisk_name", "",
            "--vendor_ramdisk_fragment", str(compressed), "--vendor_boot", str(temporary),
        ])
        _avb_footer(temporary, boot_config, tools["avbtool"])
        partition_size = int(boot_config["partition_size"])
        if temporary.stat().st_size > partition_size:
            raise PipelineError(
                f"vendor_boot image exceeds partition size: {temporary.stat().st_size} > {partition_size}"
            )
        os.replace(temporary, boot_image)
        output_images["vendor_boot"] = boot_image
    for path in sorted(output_images.values()):
        print(f"{sha256_file(path)}  {path}")
    return output_images


def build_boot_image(
    args: Any, manifest: dict[str, Any], output: Path, tools: dict[str, Path]
) -> Path:
    config = manifest["images"]["boot"]
    image = output / "kernel-out/arch/arm64/boot/Image"
    if not image.is_file():
        raise PipelineError("boot packaging requires the built Image")
    with temporary_directory(output, "boot-package-") as work:
        temporary = work / "boot.img"
        command = [
            str(tools["mkbootimg"]), "--header_version", str(config["header_version"]),
            "--os_version", config["os_version"], "--os_patch_level", config["os_patch_level"],
            "--kernel", str(image), "--cmdline",
            args.boot_cmdline or config["cmdline"], "-o", str(temporary),
        ]
        run(command)
        run([
            str(tools["avbtool"]), "add_hash_footer", "--image", str(temporary),
            "--partition_size", str(config["partition_size"]), "--partition_name", "boot",
            "--hash_algorithm", "sha256", "--salt", config["avb_salt"],
            "--algorithm", "NONE", "--rollback_index", str(config["rollback_index"]),
            "--prop", config["avb_os_version"], "--prop", config["avb_fingerprint"],
            "--prop", config["avb_security_patch"],
        ])
        if temporary.stat().st_size > int(config["partition_size"]):
            raise PipelineError("boot image exceeds configured partition size")
        result = output / "images/boot.img"
        result.parent.mkdir(parents=True, exist_ok=True)
        os.replace(temporary, result)
    return result


def build_system_dlkm_image(
    target: Path, materials: Path, manifest: dict[str, Any], output: Path, tools: dict[str, Path],
    llvm_strip: Path,
) -> Path:
    config = manifest["images"]["system_dlkm"]
    kmi = config["kmi"]
    kernel_out = output / "kernel-out"
    names = system_modules(target, manifest)
    built: dict[str, Path] = {}
    for path in kernel_out.rglob("*.ko"):
        built.setdefault(path.stem, path)
    aliases = config.get("module_aliases", {})
    missing = [name for name in names if aliases.get(name, name) not in built]
    if missing:
        raise PipelineError("kernel build is missing system_dlkm modules: " + ", ".join(missing))

    staging = output / "system-dlkm-staging"
    if staging.exists():
        shutil.rmtree(staging)
    _stage_dlkm_etc(materials, "system_dlkm", staging)
    module_dir = staging / "lib/modules" / kmi
    module_dir.mkdir(parents=True, exist_ok=True)
    for name in names:
        destination = module_dir / f"{name}.ko"
        shutil.copy2(built[aliases.get(name, name)], destination)
        run([str(llvm_strip), "--strip-debug", str(destination)])

    version = (output / "kernelrelease.txt").read_text().strip()
    with temporary_directory(output, "system-dlkm-depmod-") as dep_root:
        dep_dir = dep_root / "lib/modules" / version
        dep_dir.mkdir(parents=True)
        for path in module_dir.glob("*.ko"):
            shutil.copy2(path, dep_dir / path.name)
        run([str(tools["depmod"]), "-b", str(dep_root), version])
        prefix = f"/system_dlkm/lib/modules/{kmi}/"
        dep_file = dep_dir / "modules.dep"
        lines = []
        for line in dep_file.read_text(errors="replace").splitlines():
            left, separator, right = line.partition(":")
            left = prefix + Path(left.strip()).name
            deps = [prefix + Path(item).name for item in right.split()]
            lines.append(left + ":" + (" " + " ".join(deps) if deps else ""))
        (module_dir / "modules.dep").write_text("\n".join(lines) + "\n")
        for metadata in ("modules.alias", "modules.softdep"):
            generated = dep_dir / metadata
            if generated.is_file():
                shutil.copy2(generated, module_dir / metadata)
    (module_dir / "modules.load").write_text("".join(f"{name}\n" for name in names))

    images = output / "images"
    images.mkdir(parents=True, exist_ok=True)
    result = images / "system_dlkm.img"
    _build_dlkm_erofs(staging, result, config, tools, int(manifest["build"].get("source_date_epoch", 0)),
                     f"/lib/modules/{kmi}/modules.load")
    return result


def verify_four_images(
    output: Path,
    target: Path,
    manifest: dict[str, Any],
    tools: dict[str, Path],
    materials: Path | None = None,
) -> None:
    receipt_path = output / "images-receipt.json"
    if not receipt_path.is_file():
        raise PipelineError("image receipt is missing")
    import json
    from .common import sha256_file

    receipt = json.loads(receipt_path.read_text())
    required = {"boot", "vendor_boot", "vendor_dlkm", "system_dlkm"}
    if set(receipt) != required:
        raise PipelineError("four-image receipt is incomplete")
    for name in sorted(required):
        entry = receipt[name]
        path = Path(entry["path"])
        if not path.is_file() or sha256_file(path) != entry["sha256"]:
            raise PipelineError(f"{name} image is missing or its SHA-256 differs from receipt")
        limit = int(manifest["images"][name].get("partition_size", 0))
        if limit and path.stat().st_size > limit:
            raise PipelineError(f"{name} image exceeds partition size")
        if name in ("boot", "vendor_boot"):
            expected_partition = name
            with temporary_directory(output, f"verify-{name}-") as verify_dir:
                copied = verify_dir / f"{expected_partition}.img"
                shutil.copy2(path, copied)
                run([str(tools["avbtool"]), "verify_image", "--image", str(copied)])
        elif name in ("vendor_dlkm", "system_dlkm"):
            run([str(tools["fsck.erofs"]), str(path)])
    kernel = output / "kernel-out/arch/arm64/boot/Image"
    if not kernel.is_file():
        raise PipelineError("kernel Image is missing from the recorded build output")
    with temporary_directory(output, "verify-four-images-") as work:
        boot_dir = work / "boot"
        run([str(tools["unpack_bootimg"]), "--boot_img", receipt["boot"]["path"],
             "--out", str(boot_dir)])
        if (boot_dir / "kernel").read_bytes() != kernel.read_bytes():
            raise PipelineError("boot kernel payload differs from the recorded GKI Image")
        ramdisk = boot_dir / "ramdisk"
        if ramdisk.is_file() and ramdisk.stat().st_size:
            raise PipelineError("boot image unexpectedly contains a ramdisk")
        system_root = work / "system_dlkm"
        run([str(tools["fsck.erofs"]), f"--extract={system_root}",
             receipt["system_dlkm"]["path"]])
        kmi = manifest["images"]["system_dlkm"]["kmi"]
        module_dir = system_root / "lib/modules" / kmi
        load_path = module_dir / "modules.load"
        if not load_path.is_file():
            raise PipelineError("system_dlkm image has no modules.load")
        loaded = [line.strip().removesuffix(".ko") for line in load_path.read_text().splitlines()
                  if line.strip()]
        packed = sorted(path.stem for path in module_dir.glob("*.ko"))
        if sorted(loaded) != packed:
            raise PipelineError("system_dlkm modules.load does not match its module files")
        if loaded != system_modules(target, manifest):
            raise PipelineError("system_dlkm modules.load differs from the target's ordered module list")
        xattr = run([str(tools["dump.erofs"]),
                     f"--path=/lib/modules/{kmi}/modules.load",
                     receipt["system_dlkm"]["path"]], capture=True)
        if not _has_xattr(xattr.stdout):
            raise PipelineError("system_dlkm modules.load is missing its SELinux xattr")
        vendor_root = work / "vendor_dlkm"
        run([str(tools["fsck.erofs"]), f"--extract={vendor_root}",
             receipt["vendor_dlkm"]["path"]])
        xattr = run([str(tools["dump.erofs"]), "--path=/lib/modules/modules.load",
                     receipt["vendor_dlkm"]["path"]], capture=True)
        if not _has_xattr(xattr.stdout):
            raise PipelineError("vendor_dlkm modules.load is missing its SELinux xattr")
        vendor_boot_dir = work / "vendor_boot"
        run([str(tools["unpack_bootimg"]), "--boot_img", receipt["vendor_boot"]["path"],
             "--out", str(vendor_boot_dir)])
        embedded_dtb = vendor_boot_dir / "dtb"
        dtb_receipt = receipt["vendor_boot"].get("dtb", {})
        if not embedded_dtb.is_file() or sha256_file(embedded_dtb) != dtb_receipt.get("sha256"):
            raise PipelineError("vendor_boot DTB is missing or differs from its reservation receipt")
        if materials:
            if sha256_file(materials / "vendor_boot.dtb") != dtb_receipt.get("base_sha256"):
                raise PipelineError("vendor_boot reservation receipt references a different base DTB")
            embedded_bootconfig = vendor_boot_dir / "bootconfig"
            if (not embedded_bootconfig.is_file() or
                    sha256_file(embedded_bootconfig) != sha256_file(materials / "vendor_boot.bootconfig")):
                raise PipelineError("vendor_boot bootconfig differs from locked device materials")
            for partition, root in (("system_dlkm", system_root), ("vendor_dlkm", vendor_root)):
                for name in DLKM_ETC_FILES:
                    relative = Path(partition) / "etc" / name
                    delivered = root / "etc" / name
                    if not delivered.is_file() or sha256_file(delivered) != sha256_file(materials / relative):
                        raise PipelineError(f"{relative} differs from locked device materials")
        dtc = output / "kernel-out/scripts/dtc/dtc"
        fdt_count = validate_reserved_memory(
            embedded_dtb.read_bytes(), dtc, manifest["images"]["dtb_reservations"]
        )
        if fdt_count != dtb_receipt.get("fdt_count"):
            raise PipelineError("vendor_boot FDT count differs from its reservation receipt")
        expected_fdt_count = manifest["images"]["dtb_reservations"].get("fdt_count")
        if expected_fdt_count is not None and fdt_count != int(expected_fdt_count):
            raise PipelineError(
                f"expected {expected_fdt_count} vendor_boot FDTs, found {fdt_count}"
            )
        cmdline = _read_boot_cmdline(Path(receipt["boot"]["path"]))
        _verify_boot_memory_args(cmdline, manifest["images"]["dtb_reservations"])
        fragments = sorted(vendor_boot_dir.glob("vendor_ramdisk[0-9][0-9]"))
        if not fragments and (vendor_boot_dir / "vendor_ramdisk").is_file():
            fragments = [vendor_boot_dir / "vendor_ramdisk"]
        if len(fragments) != 1:
            raise PipelineError("ABI verification expects one vendor ramdisk fragment")
        ramdisk = work / "vendor_ramdisk.cpio"
        run([str(tools["lz4"]), "-d", "-f", str(fragments[0]), str(ramdisk)])
        ramdisk_root = work / "ramdisk"
        ramdisk_root.mkdir()
        with ramdisk.open("rb") as stream:
            result = subprocess.run(
                [str(tools["cpio"]), "-id", "--quiet", "--no-absolute-filenames",
                 "--no-preserve-owner", "*.ko", "lib/modules/modules.*"], cwd=ramdisk_root, stdin=stream,
                capture_output=True, text=True,
            )
        if result.returncode:
            raise PipelineError(f"cannot extract vendor_boot modules: {result.stderr}")
        verify_recovery_contents(ramdisk_root / "lib/modules",
                                 output / "staging/vendor_boot/lib/modules")
        from .abi import audit_modules
        from .btf import audit_btf
        recovery_report = audit_modules(
            output / "kernel-out/vmlinux", sorted(ramdisk_root.rglob("*.ko")),
            (output / "kernelrelease.txt").read_text().strip(), tools,
        )
        recovery_path = output / "logs/delivered-recovery-abi-audit.json"
        write_json(recovery_path, recovery_report)
        if recovery_report["failures"]:
            raise PipelineError(f"recovery modules are not self-contained; see {recovery_path}")
        modules = sorted(path for root in (system_root, vendor_root, ramdisk_root)
                         for path in root.rglob("*.ko"))
        report = audit_modules(output / "kernel-out/vmlinux", modules,
                               (output / "kernelrelease.txt").read_text().strip(), tools)
        report_path = output / "logs/delivered-abi-audit.json"
        write_json(report_path, report)
        btf_report = audit_btf(output / "kernel-out/vmlinux", modules)
        btf_path = output / "logs/delivered-btf-audit.json"
        write_json(btf_path, btf_report)
        if btf_report["failures"]:
            raise PipelineError(
                f"delivered module BTF verification failed: {len(btf_report['failures'])} problems; "
                f"see {btf_path}"
            )
        if report["failures"]:
            raise PipelineError(
                f"delivered module ABI verification failed: {len(report['failures'])} problems; "
                f"see {report_path}"
            )


def _read_boot_cmdline(image: Path) -> str:
    with image.open("rb") as stream:
        header = stream.read(44 + 1536)
    if len(header) < 44 or header[:8] != b"ANDROID!":
        raise PipelineError("boot image has an invalid Android header")
    return header[44:44 + 1536].split(b"\0", 1)[0].decode("utf-8", "replace").strip()


def _verify_boot_memory_args(cmdline: str, config: dict[str, Any]) -> None:
    tokens = dict(token.split("=", 1) for token in cmdline.split() if "=" in token)
    expected = {
        "ramoops.mem_address": config["ramoops_window"]["address"],
        "ramoops.mem_size": config["ramoops_window"]["size"],
        "spl.bb": config["splashlog_bb"]["address"],
    }
    for name, value in expected.items():
        if tokens.get(name, "").lower() != str(value).lower():
            raise PipelineError(
                f"boot cmdline {name}={tokens.get(name)!r} does not match reserved DTB value {value}"
            )
