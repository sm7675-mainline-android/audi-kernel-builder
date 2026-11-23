from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import tarfile
import urllib.request

from .common import PipelineError, find_tool, output_lock, run, sha256_file, temporary_directory, write_json


LIBSEPOL_VERSION = "3.8.1"
LIBSEPOL_SHA256 = "0e78705305f955abd4c0654d37a5477ee26349ab74db9e2b03a7868897ae1ddf"
FIRMWARE_LINK = "vendor/firmware_mnt"
FIRMWARE_TARGET = "../firmware"
DISPLAY_WAIT_SCRIPT = "system/bin/recovery-wait-display.sh"


def gate_recovery_display(source: str) -> str:
    original = "service recovery /system/bin/recovery\n"
    if source.count(original) != 1:
        raise PipelineError("expected one TWRP recovery service")
    return source.replace(original, f"service recovery /system/bin/sh /{DISPLAY_WAIT_SCRIPT}\n")


def enable_vibrator_service(source: str) -> str:
    pattern = r"(?m)^service vendor\.oplus\.vibrator [^\n]+\n(?:[ \t]+[^\n]*\n|\n)*"
    services = list(re.finditer(pattern, source))
    if len(services) != 1:
        raise PipelineError("expected one TWRP vendor.oplus.vibrator service")
    service = services[0]
    value = service.group()
    if len(re.findall(r"(?m)^    class \S+$", value)) != 1:
        raise PipelineError("unexpected vibrator service class")
    value = re.sub(r"(?m)^    class \S+$", "    class hal", value)
    value = re.sub(r"(?m)^    disabled\n", "", value)
    interface = "    interface aidl android.hardware.vibrator.IVibrator/default\n"
    if interface not in value:
        value = value.replace("    class hal\n", "    class hal\n" + interface)
    return source[:service.start()] + value + source[service.end():]


def remove_late_firmware_link(source: str) -> str:
    command = "    symlink /firmware /vendor/firmware_mnt\n"
    if source.count(command) != 1:
        raise PipelineError("expected one TWRP firmware symlink command")
    return source.replace(command, "")


def policy_tool(output: Path) -> Path:
    tools = output / "tools"
    directory = tools / "selinux"
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / f"libsepol-{LIBSEPOL_VERSION}.tar.gz"
    if not archive.is_file():
        url = ("https://github.com/SELinuxProject/selinux/releases/download/"
               f"{LIBSEPOL_VERSION}/libsepol-{LIBSEPOL_VERSION}.tar.gz")
        temporary = archive.with_suffix(".download")
        with urllib.request.urlopen(url, timeout=60) as response, temporary.open("wb") as stream:
            shutil.copyfileobj(response, stream)
        temporary.replace(archive)
    if sha256_file(archive) != LIBSEPOL_SHA256:
        raise PipelineError("libsepol source archive checksum mismatch")
    source = directory / f"libsepol-{LIBSEPOL_VERSION}"
    if not source.is_dir():
        with tarfile.open(archive) as compressed:
            compressed.extractall(directory, filter="data")
    run([str(find_tool("make")), "-C", str(source / "src"), "-j", "4"],
        log=output / "logs/recovery-libsepol-build.log")
    binary = tools / "recovery-firmware-policy"
    helper = Path(__file__).resolve().parents[1] / "tools/recovery-firmware-policy.c"
    run([str(find_tool("cc")), "-O2", "-Wall", "-Wextra", "-Werror",
         "-I", str(source / "include"), str(helper), str(source / "src/libsepol.a"),
         "-o", str(binary)])
    return binary


def patch_policy(tool: Path, source: Path, destination: Path) -> None:
    before = run([str(tool), "--cil", str(source)], capture=True).stdout.splitlines()
    run([str(tool), str(source), str(destination)])
    after = run([str(tool), "--cil", str(destination)], capture=True).stdout.splitlines()
    old_class = "(class system (ipc_info syslog_read syslog_mod syslog_console module_request module_load))"
    new_class = old_class[:-2] + " firmware_load))"
    permitted = {
        "(allow kernel rootfs (system (firmware_load)))",
        "(allow kernel vendor_file (system (firmware_load)))",
    }
    normalized_before = sorted(new_class if line == old_class else line for line in before)
    normalized_after = sorted(line for line in after if line not in permitted or line in before)
    if normalized_before != normalized_after or not permitted <= set(after):
        raise PipelineError("recovery policy changes exceed the firmware permission and two rules")


def build_recovery_image(args) -> int:
    output = Path(args.out).resolve()
    base = Path(args.recovery_base).resolve()
    if not base.is_file():
        raise PipelineError("recovery base image is missing")
    magiskboot = Path(args.magiskboot).resolve() if args.magiskboot else find_tool("magiskboot")
    avbtool = find_tool(args.avbtool)
    with output_lock(output), temporary_directory(output / "tmp", "recovery-package-") as work:
        tool = policy_tool(output)
        run([str(magiskboot), "unpack", "-h", str(base)], cwd=work)
        archive = work / "ramdisk.cpio"
        if not archive.is_file():
            raise PipelineError("recovery image does not contain a ramdisk")
        policy = work / "sepolicy.original"
        rc = work / "vibrator.original.rc"
        qcom_rc = work / "qcom.original.rc"
        init_entries = ("system/etc/init/hw/init.rc", "init.recovery.service.rc")
        init_sources = {entry: work / f"init-{index}.rc"
                        for index, entry in enumerate(init_entries)}
        run([str(magiskboot), "cpio", str(archive), f"extract sepolicy {policy}",
             f"extract vendor/etc/init/vibrator-default.rc {rc}",
             f"extract init.recovery.qcom.rc {qcom_rc}",
             *(f"extract {entry} {path}" for entry, path in init_sources.items())], cwd=work)
        patched_policy = work / "sepolicy"
        patched_rc = work / "vibrator.rc"
        patched_qcom_rc = work / "qcom.rc"
        patch_policy(tool, policy, patched_policy)
        patched_rc.write_text(enable_vibrator_service(rc.read_text()))
        patched_qcom_rc.write_text(remove_late_firmware_link(qcom_rc.read_text()))
        for path in init_sources.values():
            path.write_text(gate_recovery_display(path.read_text()))
        display_wait = Path(__file__).resolve().parents[1] / "targets/cliffs/recovery-wait-display.sh"
        ramdisk_files = {"sepolicy": patched_policy,
                         "vendor/etc/init/vibrator-default.rc": patched_rc,
                         "init.recovery.qcom.rc": patched_qcom_rc,
                         **init_sources, DISPLAY_WAIT_SCRIPT: display_wait}
        private_rc_entries = {"init.recovery.qcom.rc", "init.recovery.service.rc"}
        run([str(magiskboot), "cpio", str(archive),
             *(f"add {'0750' if entry in private_rc_entries else '0644'} {entry} {path}"
               for entry, path in ramdisk_files.items()),
             f"ln {FIRMWARE_TARGET} {FIRMWARE_LINK}"], cwd=work)
        images = output / "images"
        images.mkdir(exist_ok=True)
        temporary = work / "recovery.img"
        run([str(magiskboot), "repack", str(base), str(temporary)], cwd=work)
        info = run([str(avbtool), "info_image", "--image", str(temporary)], capture=True)
        if "Footer version:" in info.stdout:
            run([str(avbtool), "erase_footer", "--image", str(temporary)])
        rollback = re.search(r"(?m)^Rollback Index:\s+(\d+)$", info.stdout)
        properties = re.findall(r"(?m)^    Prop: (\S+) -> '([^']*)'$", info.stdout)
        footer = [str(avbtool), "add_hash_footer", "--image", str(temporary),
             "--partition_size", str(base.stat().st_size), "--partition_name", "recovery",
             "--algorithm", "NONE", "--hash_algorithm", "sha256", "--salt", "00"]
        if rollback:
            footer.extend(["--rollback_index", rollback.group(1)])
        for name, value in properties:
            footer.extend(["--prop", f"{name}:{value}"])
        run(footer)
        run([str(avbtool), "verify_image", "--image", str(temporary)])
        delivered = work / "delivered"
        delivered.mkdir()
        run([str(magiskboot), "unpack", str(temporary)], cwd=delivered)
        for entry, expected in ramdisk_files.items():
            extracted = work / "delivered-entry"
            run([str(magiskboot), "cpio", str(delivered / "ramdisk.cpio"),
                 f"extract {entry} {extracted}"])
            if extracted.read_bytes() != expected.read_bytes():
                raise PipelineError(f"recovery image contains unexpected {entry}")
        extracted_link = work / "delivered-firmware-link"
        run([str(magiskboot), "cpio", str(delivered / "ramdisk.cpio"),
             f"extract {FIRMWARE_LINK} {extracted_link}"])
        if not extracted_link.is_symlink() or os.readlink(extracted_link) != FIRMWARE_TARGET:
            raise PipelineError("recovery image is missing the firmware symlink")
        image = images / "recovery.img"
        os.replace(temporary, image)
        receipt = {
            "path": str(image), "sha256": sha256_file(image),
            "base_sha256": sha256_file(base), "sepolicy_sha256": sha256_file(patched_policy),
            "vibrator_rc_sha256": sha256_file(patched_rc),
            "qcom_rc_sha256": sha256_file(patched_qcom_rc),
            "display_wait_sha256": {entry: sha256_file(ramdisk_files[entry])
                                    for entry in (*init_entries, DISPLAY_WAIT_SCRIPT)},
            "firmware_link": {FIRMWARE_LINK: FIRMWARE_TARGET},
            "libsepol_version": LIBSEPOL_VERSION, "libsepol_sha256": LIBSEPOL_SHA256,
            "magiskboot_sha256": sha256_file(magiskboot), "avbtool_sha256": sha256_file(avbtool),
            "policy_tool_sha256": sha256_file(tool),
        }
        write_json(output / "recovery-receipt.json", receipt)
        (output / "SHA256SUMS-recovery.txt").write_text(f"{receipt['sha256']}  {image}\n")
        print(f"recovery={image} sha256={receipt['sha256']}")
    return 0
