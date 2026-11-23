from __future__ import annotations

import io
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from buildsys.catalog import load_toml
from buildsys.common import PipelineError, run, sha256_file
from buildsys.images import (
    _build_dlkm_erofs,
    _verify_staged_fsck,
    build_boot_image,
    check_erofs_tool,
)
from buildsys.materials import VENDOR_BOOT_FILES, check_materials, system_modules, unpack_vendor_ramdisk
from buildsys.pipeline import _verify_staging_receipt, _write_staging_receipt


TARGET = Path(__file__).resolve().parents[1] / "targets/cliffs/sm7675.toml"


class PackagingTests(unittest.TestCase):
    def setUp(self) -> None:
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.root = Path(work.name)

    def test_materials_fail_on_missing_or_modified_inputs(self) -> None:
        target = self.root / "target.toml"
        materials = self.root / "materials"
        materials.mkdir()
        manifest = {"images": {"materials_lock": "materials.lock.toml"}}
        lock = ['schema = 1', '[files]']
        for name in VENDOR_BOOT_FILES:
            path = materials / name
            path.write_text(name)
            lock.append(f'"{name}" = "{sha256_file(path)}"')
        target.with_name("materials.lock.toml").write_text("\n".join(lock))
        result = check_materials(target, manifest, materials, "vendor_boot")
        self.assertEqual(set(result), set(VENDOR_BOOT_FILES))
        (materials / "vendor_boot.dtb").write_bytes(b"changed")
        with self.assertRaisesRegex(PipelineError, "differs from lock"):
            check_materials(target, manifest, materials, "vendor_boot")
        (materials / "vendor_ramdisk.tar").unlink()
        with self.assertRaisesRegex(PipelineError, "missing or invalid"):
            check_materials(target, manifest, materials, "vendor_boot")

    def test_system_module_list_retains_order_and_rejects_duplicates(self) -> None:
        target = self.root / "target.toml"
        manifest = {"images": {"system_dlkm": {"modules_list": "system.list"}}}
        listing = self.root / "system.list"
        listing.write_text("second.ko\nfirst\n")
        self.assertEqual(system_modules(target, manifest), ["second", "first"])
        listing.write_text("second.ko\nfirst\nsecond\n")
        with self.assertRaisesRegex(PipelineError, "duplicate module entries"):
            system_modules(target, manifest)

    def test_changed_material_receipt_invalidates_staging(self) -> None:
        for partition in ("vendor_boot", "vendor_dlkm"):
            (self.root / "staging" / partition).mkdir(parents=True)
        for name in ("plan.json", "modules-receipt.json", "stage-inputs.json"):
            (self.root / name).write_text("{}")
        expected = _write_staging_receipt(self.root)
        self.assertEqual(_verify_staging_receipt(self.root), expected)
        (self.root / "stage-inputs.json").write_text('{"new": "materials"}')
        with self.assertRaisesRegex(PipelineError, "different device materials"):
            _verify_staging_receipt(self.root)

    def test_ramdisk_preserves_permissions_and_symlinks_but_rejects_modules(self) -> None:
        archive = self.root / "vendor_ramdisk.tar"
        with tarfile.open(archive, "w") as stream:
            directory = tarfile.TarInfo("system/bin")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o751
            stream.addfile(directory)
            link = tarfile.TarInfo("system/bin/dump.f2fs")
            link.type = tarfile.SYMTYPE
            link.linkname = "fsck.f2fs"
            stream.addfile(link)
        destination = self.root / "stage"
        unpack_vendor_ramdisk(archive, destination)
        self.assertEqual((destination / "system/bin").stat().st_mode & 0o777, 0o751)
        self.assertEqual((destination / "system/bin/dump.f2fs").readlink(), Path("fsck.f2fs"))
        with tarfile.open(archive, "a") as stream:
            stream.addfile(tarfile.TarInfo("lib/modules/modules.load"))
        with self.assertRaisesRegex(PipelineError, "contains a module path"):
            unpack_vendor_ramdisk(archive, self.root / "old")

    def test_vendor_boot_fsck_must_match_locked_ramdisk(self) -> None:
        archive = self.root / "vendor_ramdisk.tar"
        fsck_data = b"stock fsck binary"
        with tarfile.open(archive, "w") as stream:
            entry = tarfile.TarInfo("./system/bin/fsck.f2fs")
            entry.size = len(fsck_data)
            stream.addfile(entry, io.BytesIO(fsck_data))
        staged = self.root / "staging/vendor_boot/system/bin/fsck.f2fs"
        staged.parent.mkdir(parents=True)
        staged.write_bytes(fsck_data)
        _verify_staged_fsck(self.root, self.root / "staging/vendor_boot")
        staged.write_bytes(b"experimental fsck binary")
        with self.assertRaisesRegex(PipelineError, "differs from device materials"):
            _verify_staged_fsck(self.root, self.root / "staging/vendor_boot")

    @unittest.skipUnless(all(shutil.which(tool) for tool in
                             ("mkbootimg", "unpack_bootimg", "avbtool")), "Android host tools required")
    def test_boot_uses_only_the_built_image_and_target(self) -> None:
        manifest = load_toml(TARGET)
        manifest["images"]["boot"]["partition_size"] = 131072
        kernel = self.root / "kernel-out/arch/arm64/boot/Image"
        kernel.parent.mkdir(parents=True)
        kernel.write_bytes(b"test kernel")
        tools = {name: Path(shutil.which(name)) for name in ("mkbootimg", "unpack_bootimg", "avbtool")}
        image = build_boot_image(SimpleNamespace(boot_cmdline="test=1"), manifest, self.root, tools)
        run([str(tools["avbtool"]), "verify_image", "--image", str(image)])
        unpacked = self.root / "unpacked"
        run([str(tools["unpack_bootimg"]), "--boot_img", str(image), "--out", str(unpacked)])
        self.assertEqual((unpacked / "kernel").read_bytes(), kernel.read_bytes())
        self.assertFalse((unpacked / "ramdisk").exists() and (unpacked / "ramdisk").stat().st_size)

    @unittest.skipUnless(all(shutil.which(tool) for tool in
                             ("mkfs.erofs", "fsck.erofs", "dump.erofs")), "EROFS tools required")
    def test_erofs_contains_both_selinux_labels_without_staging_xattrs(self) -> None:
        tools = {name: Path(shutil.which(name)) for name in ("mkfs.erofs", "fsck.erofs", "dump.erofs")}
        try:
            check_erofs_tool(tools["mkfs.erofs"])
        except PipelineError as error:
            self.skipTest(str(error))
        stage = self.root / "stage"
        (stage / "lib/modules").mkdir(parents=True)
        (stage / "lib/modules/modules.load").write_text("example\n")
        (stage / "etc").mkdir()
        (stage / "etc/build.prop").touch()
        config = load_toml(TARGET)["images"]["vendor_dlkm"]
        images = self.root / "images"
        images.mkdir()
        image = images / "vendor_dlkm.img"
        _build_dlkm_erofs(stage, image, config, tools, 1230768000, "/lib/modules/modules.load")
        contents = image.read_bytes()
        for name in ("selinux_label", "etc_selinux_label"):
            self.assertIn(b"selinux" + config[name].encode(), contents)
        first = sha256_file(image)
        _build_dlkm_erofs(stage, image, config, tools, 1230768000, "/lib/modules/modules.load")
        self.assertEqual(first, sha256_file(image))
