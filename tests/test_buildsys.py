from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from buildsys.catalog import PipelineError, build_plan, kernel_config_path, source_roots
from buildsys.common import find_tool, tree_digest
from buildsys.images import _has_xattr, _merge_softdep, _sanitize_module_aliases
from buildsys.modules import (
    _apply_source_patches,
    _external_command,
    _finalize_kernel_modules,
    _kernel_module,
    _selected_symvers,
    _affected_consumers,
    _local_file_times,
    _restore_local_file_times,
    _prune_module_cache,
    _stale_module_cache,
    _prepare_bazel_source,
    _source_patch_overlay_flags,
    _source_view,
    _write_source_patch_overlay,
)
from buildsys.pipeline import (
    _check_identity,
    _require_packaging_identity,
    _require_kernel_receipt,
    _source_states,
    parser,
)
from buildsys.toolchain import configure_kernel, prepare_kernel, source_state
from buildsys.toolchain import build_environment


class BuildPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.roots = {
            "kernel": self.root / "kernel",
            "msm": self.root / "msm",
            "vendor": self.root / "vendor-repo",
            "compat": self.root / "compat",
        }
        for path in self.roots.values():
            path.mkdir()
        (self.roots["vendor"] / "vendor").mkdir()
        self.target_dir = self.root / "target"
        (self.target_dir / "modules").mkdir(parents=True)
        (self.target_dir / "kernel.config").write_text("CONFIG_TEST=m\n")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_incremental_cache_drops_removed_module_from_both_copies(self) -> None:
        for name in ("modules", "modules-stripped"):
            directory = self.root / name
            directory.mkdir()
            (directory / "qseecom_dlkm.ko").write_bytes(b"old")
            (directory / "smcinvoke_dlkm.ko").write_bytes(b"keep")
        _prune_module_cache(self.root, {"smcinvoke_dlkm"})
        for name in ("modules", "modules-stripped"):
            self.assertFalse((self.root / name / "qseecom_dlkm.ko").exists())
            self.assertEqual((self.root / name / "smcinvoke_dlkm.ko").read_bytes(), b"keep")

    @patch("buildsys.modules.module_vermagic")
    def test_cache_refreshes_release_changes_and_interrupted_builds(self, vermagic) -> None:
        directory = self.root / "modules"
        directory.mkdir()
        hashes = {}
        for name in ("changed", "good", "old", "removed"):
            (directory / f"{name}.ko").write_bytes(b"original")
            hashes[f"{name}.ko"] = hashlib.sha256(b"original").hexdigest()
        (directory / "changed.ko").write_bytes(b"interrupted build")
        vermagic.side_effect = ["6.18-new SMP", "6.18-old SMP"]
        self.assertEqual(
            _stale_module_cache(self.root, {"changed", "good", "old", "missing"},
                                {"module_sha256": hashes}, "6.18-new",
                                Path("modinfo"), Path("readelf")),
            {"changed", "old", "missing"},
        )

    def test_symvers_excludes_unshipped_companion_providers(self) -> None:
        source = self.root / "Module.symvers"
        source.write_text("0x12345678\tclock_api\t/path/clk-qcom\tEXPORT_SYMBOL\t\n"
                          "0xabcdef01\tghost_api\t/path/unshipped\tEXPORT_SYMBOL\t\n")
        result = _selected_symvers(source, {"modules": ["clk_qcom"]}, self.root / "selected")
        self.assertIn("clock_api", result.read_text())
        self.assertNotIn("ghost_api", result.read_text())

    def test_incremental_view_keeps_only_unchanged_file_times(self) -> None:
        same = self.root / "same.c"
        changed = self.root / "changed.c"
        same.write_text("original")
        changed.write_text("original")
        os.utime(same, ns=(1000000000, 1000000000))
        os.utime(changed, ns=(1000000000, 1000000000))
        before = _local_file_times(self.root)
        same.write_text("original")
        changed.write_text("new")
        _restore_local_file_times(self.root, before)
        self.assertEqual(same.stat().st_mtime_ns, 1000000000)
        self.assertNotEqual(changed.stat().st_mtime_ns, 1000000000)

    @patch("buildsys.modules.imported_crcs")
    def test_changed_provider_selects_only_incompatible_consumers(self, imports) -> None:
        source = self.root / "Module.symvers"
        source.write_text("0x12345678\tclock_api\tclk-qcom\tEXPORT_SYMBOL\t\n")
        stale = self.root / "camcc.ko"
        fresh = self.root / "gcc.ko"
        stale.touch()
        fresh.touch()
        imports.side_effect = [{"clock_api": 0x11111111}, {"clock_api": 0x12345678}]
        self.assertEqual(_affected_consumers([source], {"camcc": stale, "gcc": fresh},
                                            Path("modprobe")), {"camcc"})

    @patch("buildsys.common.shutil.which", return_value="/usr/bin/depmod")
    def test_depmod_keeps_argv0_symlink_name(self, _which) -> None:
        self.assertEqual(find_tool("depmod"), Path("/usr/bin/depmod"))

    def test_erofs_xattr_check_accepts_combined_inode_output(self) -> None:
        self.assertTrue(_has_xattr("Path: /lib/modules/modules.load\nInode size: 32   Xattr size: 16\n"))
        self.assertFalse(_has_xattr("Path: /lib/modules/modules.load\nInode size: 32   Xattr size: 0\n"))

    def test_module_alias_sanitizer_drops_non_three_field_aliases(self) -> None:
        aliases = self.root / "modules.alias"
        aliases.write_text(
            "# generated\n"
            "alias i2c:valid module_a\n"
            "alias i2c:tabla top level module_b\n"
            "not-an-alias extra fields\n"
        )

        _sanitize_module_aliases(aliases)

        self.assertEqual(aliases.read_text(), "# generated\nalias i2c:valid module_a\n")

    def test_softdep_merge_accepts_compact_dependency_syntax(self) -> None:
        source = self.root / "modules.softdep"
        destination = self.root / "out"
        source.write_text(
            "softdep oplus_bsp_uff_fp_driver pre:mtk_disp_notify\n"
            "softdep msm_eva pre: msm-mmrm\n"
            "softdep msm_eva pre:synx-driver\n"
            "softdep no_dependencies\n"
        )
        destination.mkdir()

        _merge_softdep(destination, source)

        self.assertEqual(
            (destination / "modules.softdep").read_text(),
            "softdep oplus_bsp_uff_fp_driver pre: mtk_disp_notify\n"
            "softdep msm_eva pre: msm-mmrm synx-driver\n",
        )

    def test_incomplete_module_build_can_reuse_output_for_new_identity(self) -> None:
        output = self.root / 'out'
        output.mkdir()
        (output / 'build-identity.json').write_text('{"version": 1}\n')
        (output / 'module-failures.json').write_text('{"failed_groups": []}\n')

        _check_identity(output, {'version': 2})

        self.assertEqual(
            json.loads((output / 'build-identity.json').read_text()),
            {'version': 2},
        )
        self.assertEqual(
            json.loads((output / 'build-identity.previous.json').read_text()),
            {'version': 1},
        )

    def test_completed_module_build_rejects_output_identity_change(self) -> None:
        output = self.root / 'out'
        output.mkdir()
        (output / 'build-identity.json').write_text('{"version": 1}\n')
        (output / 'modules-receipt.json').write_text('{}\n')

        with self.assertRaisesRegex(PipelineError, 'completed artifacts'):
            _check_identity(output, {'version': 2})

    def test_explicit_output_reuse_preserves_previous_identity(self) -> None:
        output = self.root / 'out'
        output.mkdir()
        (output / 'build-identity.json').write_text('{"version": 1}\n')
        (output / 'modules-receipt.json').write_text('{}\n')

        _check_identity(output, {'version': 2}, allow_reuse=True)

        self.assertEqual(
            json.loads((output / 'build-identity.json').read_text()),
            {'version': 2},
        )
        self.assertEqual(
            json.loads((output / 'build-identity.previous.json').read_text()),
            {'version': 1},
        )

    def manifest(self, boot: list[str], dlkm: list[str], overrides=None):
        (self.target_dir / "boot.list").write_text("\n".join(boot) + "\n")
        (self.target_dir / "dlkm.list").write_text("\n".join(dlkm) + "\n")
        return {
            "target": {"name": "test-target"},
            "build": {"kernel_config": "kernel.config"},
            "modules": {
                "vendor_boot_list": "boot.list",
                "vendor_dlkm_list": "dlkm.list",
            },
            "resolve": {"overrides": overrides or {}},
        }

    def test_make_variables_split_build_groups_and_preserve_output_aliases(self) -> None:
        (self.roots["vendor"] / "vendor/driver").mkdir()
        manifest = self.manifest(
            [], ["wifi-a", "wifi-b"],
            {
                "wifi-a": {
                    "root": "vendor", "path": "driver", "config": "CONFIG_TEST",
                    "output": "qca_a", "make_vars": {"MODNAME": "qca_a"},
                    "kcflags": ["-include compat.h"],
                },
                "wifi-b": {
                    "root": "vendor", "path": "driver", "config": "CONFIG_TEST",
                    "output": "qca_b", "make_vars": {"MODNAME": "qca_b"},
                },
            },
        )

        plan = build_plan(self.target_dir / "target.toml", self.roots, manifest)

        self.assertFalse(plan["unresolved"])
        self.assertFalse(plan["ambiguous"])
        self.assertEqual(len(plan["groups"]), 2)
        self.assertEqual(
            {group["make_vars"]["MODNAME"] for group in plan["groups"]},
            {"qca_a", "qca_b"},
        )
        self.assertEqual(plan["modules"]["wifi-a"]["output"], "qca_a")
        self.assertEqual(
            next(group for group in plan["groups"] if "wifi-a" in group["modules"])["kcflags"],
            ["-include compat.h"],
        )

    def test_different_kbuild_configs_split_build_groups(self) -> None:
        (self.roots["vendor"] / "vendor/driver").mkdir()
        manifest = self.manifest(
            [], ["driver-a", "driver-b"],
            {
                "driver-a": {
                    "root": "vendor", "path": "driver", "config": "CONFIG_DRIVER_A",
                },
                "driver-b": {
                    "root": "vendor", "path": "driver", "config": "CONFIG_DRIVER_B",
                },
            },
        )

        plan = build_plan(self.target_dir / "target.toml", self.roots, manifest)

        self.assertFalse(plan["unresolved"])
        self.assertEqual(len(plan["groups"]), 2)
        self.assertEqual(
            {tuple(group["configs"]) for group in plan["groups"]},
            {("CONFIG_DRIVER_A",), ("CONFIG_DRIVER_B",)},
        )

    def test_same_module_in_two_active_source_dirs_is_ambiguous(self) -> None:
        for directory in ("first", "second"):
            path = self.roots["vendor"] / "vendor" / directory
            path.mkdir()
            (path / "Kbuild").write_text("obj-$(CONFIG_TEST) += duplicate.o\n")
        plan = build_plan(
            self.target_dir / "target.toml",
            self.roots,
            self.manifest([], ["duplicate"]),
        )

        self.assertIn("duplicate", plan["ambiguous"])
        self.assertNotIn("duplicate", plan["modules"])

    def test_cliffs_nxp_nci_uses_vendor_character_device_driver(self) -> None:
        target = Path(__file__).resolve().parents[1] / "targets/cliffs/sm7675.toml"
        override = tomllib.loads(target.read_text())["resolve"]["overrides"]["nxp-nci"]
        kernel_source = self.roots["kernel"] / "drivers/nfc/nxp-nci"
        vendor_source = self.roots["vendor"] / "vendor/nxp/opensource/driver"
        kernel_source.mkdir(parents=True)
        vendor_source.mkdir(parents=True)
        (kernel_source / "Makefile").write_text("obj-$(CONFIG_NFC_NXP_NCI) += nxp-nci.o\n")
        (vendor_source / "Kbuild").write_text("obj-$(CONFIG_NXP_NFC_I2C) += nxp-nci.o\n")
        plan = build_plan(
            self.target_dir / "target.toml", self.roots,
            self.manifest([], ["nxp-nci"], {"nxp-nci": override}),
        )
        self.assertFalse(plan["unresolved"])
        self.assertFalse(plan["ambiguous"])
        self.assertEqual(plan["modules"]["nxp-nci"]["root"], "vendor")
        self.assertEqual(plan["modules"]["nxp-nci"]["path"], "nxp/opensource/driver")
        group = next(group for group in plan["groups"] if "nxp-nci" in group["modules"])
        self.assertEqual(group["configs"], ["CONFIG_NXP_NFC_I2C"])
        self.assertEqual(group["make_vars"]["NFC_ROOT"], "{source}")

    def test_path_override_is_applied_to_selected_module_group(self) -> None:
        source = self.roots["msm"] / "drivers/example"
        source.mkdir(parents=True)
        (source / "Makefile").write_text("obj-$(CONFIG_TEST) += example.o\n")
        manifest = self.manifest([], ["example"])
        manifest["resolve"]["path_overrides"] = {
            "msm:drivers/example": {"kcflags": ["-Wno-unused-variable"]},
        }

        plan = build_plan(self.target_dir / "target.toml", self.roots, manifest)

        self.assertEqual(plan["modules"]["example"]["kcflags"], ("-Wno-unused-variable",))
        self.assertEqual(plan["groups"][0]["kcflags"], ["-Wno-unused-variable"])

    def test_path_override_can_match_source_root_independently(self) -> None:
        source = self.roots["kernel"] / "drivers/example"
        source.mkdir(parents=True)
        (source / "Makefile").write_text("obj-$(CONFIG_TEST) += example.o\n")
        manifest = self.manifest([], ["example"])
        manifest["resolve"]["path_overrides"] = {
            "*:drivers/example": {"kcflags": ["-Wno-unused-variable"]},
        }

        plan = build_plan(self.target_dir / "target.toml", self.roots, manifest)

        self.assertEqual(plan["modules"]["example"]["kcflags"], ("-Wno-unused-variable",))

    def test_path_glob_override_applies_to_nested_module_groups(self) -> None:
        source = self.roots["vendor"] / "vendor/qcom/audio/codecs/wcd"
        source.mkdir(parents=True)
        (source / "Kbuild").write_text("obj-$(CONFIG_TEST) += codec.o\n")
        manifest = self.manifest([], ["codec"])
        manifest["resolve"]["path_overrides"] = {
            "vendor:qcom/audio/**": {"kcflags": ["-include legacy-audio.h"]},
        }

        plan = build_plan(self.target_dir / "target.toml", self.roots, manifest)

        self.assertEqual(
            plan["modules"]["codec"]["kcflags"], ("-include legacy-audio.h",)
        )

    def test_external_kcflags_are_applied_to_each_selected_module(self) -> None:
        source = self.roots["vendor"] / "vendor/driver"
        source.mkdir(parents=True)
        (source / "Kbuild").write_text("obj-$(CONFIG_TEST) += example.o\n")
        manifest = self.manifest([], ["example"])
        manifest["build"]["external_kcflags"] = [
            "-include {root:compat}/android_vendor_backport.h",
        ]

        plan = build_plan(self.target_dir / "target.toml", self.roots, manifest)

        self.assertEqual(
            plan["groups"][0]["kcflags"],
            ["-include {root:compat}/android_vendor_backport.h"],
        )

    def test_include_globs_resolve_from_vendor_repository_subtree(self) -> None:
        include = self.roots["vendor"] / "vendor/qcom/project/include"
        include.mkdir(parents=True)
        manifest = {
            "target": {"arch": "arm64"},
            "build": {"include_globs": ["qcom/**/include"]},
        }

        output = self.root / "out"
        env = build_environment(
            manifest, self.roots, self.root / "llvm/bin", None, output
        )

        response = Path(env["MODULE_KCFLAGS"][1:])
        self.assertEqual(response, output / "build-flags/module-kcflags.rsp")
        self.assertIn(f"-I{include}", response.read_text().splitlines())
        self.assertNotIn(f"-I{include}", env["KCFLAGS"])

    def test_response_file_preserves_multi_token_kcflags(self) -> None:
        manifest = {
            "target": {"arch": "arm64"},
            "build": {"kcflags": ["-include include/legacy.h"]},
        }

        env = build_environment(
            manifest, self.roots, self.root / "llvm/bin", None, self.root / "out"
        )

        arguments = shlex.split(Path(env["MODULE_KCFLAGS"][1:]).read_text())
        self.assertEqual(arguments[-2:], ["-include", "include/legacy.h"])

    def test_control_characters_in_make_values_are_rejected(self) -> None:
        (self.roots["vendor"] / "vendor/driver").mkdir()
        plan_manifest = self.manifest(
            [], ["bad"],
            {"bad": {
                "root": "vendor", "path": "driver", "config": "CONFIG_TEST",
                "make_vars": {"MODNAME": "bad\nvalue"},
            }},
        )

        with self.assertRaisesRegex(PipelineError, "control character"):
            build_plan(self.target_dir / "target.toml", self.roots, plan_manifest)

    def test_source_paths_are_not_restricted_to_workspace_names(self) -> None:
        for legacy in ("common", "crd"):
            with self.subTest(legacy=legacy), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                msm = root / "kernel_platform" / legacy
                msm.mkdir(parents=True)
                vendor = root / "vendor-repo"
                (vendor / "vendor").mkdir(parents=True)
                kernel = root / "kernel"
                compat = root / "compat"
                kernel.mkdir()
                compat.mkdir()
                args = SimpleNamespace(
                    kernel_src=str(kernel), msm_src=str(msm),
                    vendor_src=str(vendor), compat_src=str(compat), extra_src=[],
                )
                self.assertEqual(source_roots(args)["msm"], msm)
                direct = root / "direct" / legacy
                direct.mkdir(parents=True)
                args.msm_src = str(direct)
                self.assertEqual(source_roots(args)["msm"], direct)
                args.compat_src = None
                (direct / "oneplus-6.18-compat").mkdir()
                self.assertEqual(source_roots(args)["compat"], direct / "oneplus-6.18-compat")
                args.kernel_src = str(direct)
                with self.assertRaisesRegex(PipelineError, "separate source roots"):
                    source_roots(args)


class GeneratedModuleTests(unittest.TestCase):
    def test_kernel_module_uses_output_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            kernel_out = Path(temp)
            module_path = kernel_out / "drivers/ufs/host/ufs-qcom.ko"
            module_path.parent.mkdir(parents=True)
            module_path.write_bytes(b"module")

            result = _kernel_module(
                kernel_out,
                {
                    "path": "drivers/ufs/host",
                    "outputs": {"ufs_qcom": "ufs-qcom"},
                },
                "ufs_qcom",
            )

            self.assertEqual(result, module_path)

    def test_source_replacement_overlay_is_scoped_and_count_checked(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            original_root = root / "vendor"
            original = original_root / "vendor/driver/source.c"
            view_root = root / "out/source-view/vendor"
            target = view_root / "vendor/driver/source.c"
            original.parent.mkdir(parents=True)
            target.parent.mkdir(parents=True)
            original.write_text("first(); old_call(); last();\n")
            target.symlink_to(original)
            output = root / "out"
            output.mkdir(exist_ok=True)

            overlay = _apply_source_patches(
                {"vendor": view_root},
                {"vendor": original_root},
                {"build": {"source_replacements": [{
                    "root": "vendor",
                    "path": "vendor/driver/source.c",
                    "search": "old_call()",
                    "replace": "new_call()",
                    "count": 1,
                }]}},
                output / "source-vfs.json",
            )

            self.assertEqual(original.read_text(), "first(); old_call(); last();\n")
            self.assertFalse(target.is_symlink())
            self.assertEqual(target.read_text(), "first(); new_call(); last();\n")
            self.assertEqual(
                json.loads(overlay.read_text())["roots"][0]["name"],
                str(original.resolve()),
            )

    def test_source_replacement_rejects_unexpected_match_count(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            original_root = root / "vendor"
            original = original_root / "vendor/driver/source.c"
            view_root = root / "out/source-view/vendor"
            target = view_root / "vendor/driver/source.c"
            original.parent.mkdir(parents=True)
            target.parent.mkdir(parents=True)
            original.write_text("old_call();\n")
            target.symlink_to(original)

            with self.assertRaisesRegex(PipelineError, "expected 2 matches, found 1"):
                _apply_source_patches(
                    {"vendor": view_root},
                    {"vendor": original_root},
                    {"build": {"source_replacements": [{
                        "root": "vendor",
                        "path": "vendor/driver/source.c",
                        "search": "old_call()",
                        "replace": "new_call()",
                        "count": 2,
                    }]}},
                    root / "out/source-vfs.json",
                )

            self.assertFalse(target.is_symlink())
            self.assertEqual(target.read_text(), "old_call();\n")
            self.assertEqual(original.read_text(), "old_call();\n")

    def test_source_patch_overlay_flag_uses_separate_path_argument(self) -> None:
        overlay = Path('/tmp/source-patches-vfs.json')

        self.assertEqual(
            _source_patch_overlay_flags(overlay),
            ['-ivfsoverlay', str(overlay)],
        )

    def test_source_patch_overlay_redirects_original_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            original = root / 'source/include/trace.h'
            patched = root / 'out/source-view/include/trace.h'
            original.parent.mkdir(parents=True)
            patched.parent.mkdir(parents=True)
            original.write_text('int original;' + chr(10))
            patched.write_text('int patched;' + chr(10))

            overlay = _write_source_patch_overlay(
                [(original, patched)], root / 'out/source-patches-vfs.json'
            )

            self.assertIsNotNone(overlay)
            data = json.loads(overlay.read_text())
            self.assertEqual(data['roots'], [{
                'type': 'file',
                'name': str(original.resolve()),
                'external-contents': str(patched.resolve()),
            }])

    def test_source_view_omits_ignored_build_outputs_without_touching_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            driver = source / "drivers/example"
            driver.mkdir(parents=True)
            (driver / "Kbuild").write_text("obj-m += example.o\n")
            (driver / "example.c").write_text("int example(void) { return 0; }\n")
            (source / ".gitignore").write_text("modules.order\nModule.symvers\n")
            (source / "modules.order").write_text("stale-module.ko\n")
            (source / "Module.symvers").write_text("stale symbol data\n")
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            subprocess.run([
                "git", "-C", str(source), "add", ".gitignore",
                "drivers/example/Kbuild", "drivers/example/example.c",
            ], check=True)

            view = _source_view(source, root / "out/source-view", root / "out")

            self.assertTrue((view / "drivers/example/Kbuild").is_symlink())
            self.assertTrue((view / "drivers/example/example.c").is_symlink())
            self.assertFalse((view / "modules.order").exists())
            self.assertFalse((view / "Module.symvers").exists())
            self.assertEqual((source / "modules.order").read_text(), "stale-module.ko\n")
            self.assertEqual((source / "Module.symvers").read_text(), "stale symbol data\n")

    def test_source_view_maps_active_declared_vendor_links_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            msm = root / "msm"
            active = msm / "drivers/example"
            active.mkdir(parents=True)
            legacy_vendor = root / "workspace/vendor/oplus/example"
            legacy_vendor.mkdir(parents=True)
            (legacy_vendor / "driver.c").write_text("int driver(void) { return 0; }\n")
            docs_target = root / "unlocked/devicetree"
            docs_target.mkdir(parents=True)
            (active / "vendor-source").symlink_to(legacy_vendor, target_is_directory=True)
            (msm / "Documentation").mkdir()
            (msm / "Documentation/devicetree").symlink_to(
                docs_target, target_is_directory=True
            )
            subprocess.run(["git", "init", "-q", str(msm)], check=True)
            subprocess.run([
                "git", "-C", str(msm), "add", "drivers/example/vendor-source",
                "Documentation/devicetree",
            ], check=True)

            vendor_root = root / "vendor-repo"
            vendor_driver = vendor_root / "vendor/oplus/example"
            vendor_driver.mkdir(parents=True)
            (vendor_driver / "driver.c").write_text("int driver(void) { return 1; }\n")
            output = root / "out"
            vendor_view = _source_view(vendor_root, output / "source-view/vendor", output)
            msm_view = _source_view(
                msm,
                output / "source-view/msm",
                output,
                active_paths=["drivers/example"],
                source_link_maps=[{
                    "marker": "vendor", "root": "vendor", "prefix": "vendor",
                }],
                link_roots={"vendor": vendor_view},
            )

            self.assertEqual(
                (msm_view / "drivers/example/vendor-source/driver.c").read_text(),
                "int driver(void) { return 1; }\n",
            )
            self.assertFalse((msm_view / "Documentation/devicetree").exists())
            self.assertEqual(os.readlink(active / "vendor-source"), str(legacy_vendor))

    def test_single_source_matching_output_uses_non_composite_kbuild(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "compat"
            source.mkdir()
            (source / "gh_compat.c").write_text("int compat(void) { return 0; }\n")
            output = root / "out"
            group = {
                "modules": ["gh_compat"],
                "specs": {"gh_compat": {
                    "sources": ["gh_compat.c"], "includes": [], "defines": [],
                }},
            }

            generated = _prepare_bazel_source(group, source, output / "generated", output)

            self.assertEqual(
                (generated / "Kbuild").read_text(),
                f"obj-m += gh_compat.o\nccflags-y += -I{source}\n",
            )

    def test_generated_module_adds_source_and_nested_header_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "vendor/module"
            nested = source / "sensor"
            nested.mkdir(parents=True)
            (nested / "driver.c").write_text('#include "local.h"\n')
            (nested / "local.h").write_text("#pragma once\n")
            output = root / "out"
            group = {
                "modules": ["driver"],
                "specs": {"driver": {
                    "sources": ["sensor/driver.c", "sensor/local.h"],
                    "includes": [], "defines": [],
                }},
            }

            generated = _prepare_bazel_source(
                group, source, output / "generated", output,
                allowed_root=root / "vendor",
            )

            kbuild = (generated / "Kbuild").read_text()
            self.assertIn(f"-I{source}", kbuild)
            self.assertIn(f"-I{nested}", kbuild)

    def test_generated_module_requires_a_compilation_unit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "compat"
            source.mkdir()
            (source / "interface.h").write_text("#pragma once\n")
            output = root / "out"
            group = {
                "modules": ["empty"],
                "specs": {"empty": {
                    "sources": ["interface.h"], "includes": [], "defines": [],
                }},
            }

            with self.assertRaisesRegex(PipelineError, "no C or assembly sources"):
                _prepare_bazel_source(group, source, output / "generated", output)

    def test_generated_sources_may_follow_symlinks_within_the_source_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "vendor/bazel"
            common = root / "vendor/common"
            common.mkdir(parents=True)
            source.mkdir(parents=True)
            (common / "shared.c").write_text("int shared(void) { return 0; }\n")
            (source / "src").symlink_to("../common", target_is_directory=True)
            output = root / "out"
            group = {
                "modules": ["shared"],
                "specs": {"shared": {
                    "sources": ["src/shared.c"], "includes": [], "defines": [],
                }},
            }

            generated = _prepare_bazel_source(
                group, source, output / "generated", output,
                allowed_root=root / "vendor",
            )

            self.assertEqual(
                (generated / "src/shared.c").resolve(), (common / "shared.c").resolve()
            )

            outside = root / "outside.c"
            outside.write_text("int outside(void) { return 0; }\n")
            (source / "outside.c").symlink_to(outside)
            group["specs"]["shared"]["sources"] = ["outside.c"]
            with self.assertRaisesRegex(PipelineError, "escapes its root"):
                _prepare_bazel_source(
                    group, source, output / "outside-generated", output,
                    allowed_root=root / "vendor",
                )

    def test_defconfig_resolves_in_selected_kernel_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "kernel/arch/arm64/configs/gki_defconfig"
            config.parent.mkdir(parents=True)
            config.write_text("CONFIG_MODULES=y\n")
            manifest = {"target": {"arch": "arm64"},
                        "build": {"kernel_defconfig": "gki_defconfig"}}
            self.assertEqual(kernel_config_path(root / "target.toml", manifest,
                                                {"kernel": root / "kernel"}), config)
            manifest["build"]["kernel_config"] = "kernel.config"
            with self.assertRaisesRegex(PipelineError, "exactly one"):
                kernel_config_path(root / "target.toml", manifest,
                                   {"kernel": root / "kernel"})
            del manifest["build"]["kernel_config"]
            manifest["build"]["kernel_defconfig"] = "../../outside_defconfig"
            with self.assertRaisesRegex(PipelineError, "must stay inside"):
                kernel_config_path(root / "target.toml", manifest,
                                   {"kernel": root / "kernel"})

    def test_defconfig_reconfiguration_preserves_objects_and_previous_config(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "kernel/arch/arm64/configs/gki_defconfig"
            config.parent.mkdir(parents=True)
            config.write_text("CONFIG_MODULES=y\nCONFIG_MODVERSIONS=y\n")
            kernel_out = root / "out/kernel-out"
            kernel_out.mkdir(parents=True)
            marker = kernel_out / ".forge-config-sha256"
            marker.write_text("old-input\n")
            (kernel_out / ".config").write_text("old-config\n")
            (kernel_out / "preserved.o").write_bytes(b"object")
            (root / "out/modules-receipt.json").write_text("{}\n")
            args = SimpleNamespace(target=str(root / "target.toml"), reuse_output=True)
            manifest = {"target": {"arch": "arm64"},
                        "build": {"kernel_defconfig": "gki_defconfig"}}
            observed = []

            def fake_run(command, **kwargs):
                observed.append(command[-1])
                if command[-1] == "gki_defconfig":
                    (kernel_out / ".config").write_bytes(config.read_bytes())
                return subprocess.CompletedProcess(command, 0, "", "")

            with patch("buildsys.toolchain.run", side_effect=fake_run):
                configure_kernel(args, manifest, {"kernel": root / "kernel"},
                                 root / "out", {"ARCH": "arm64"})
            self.assertEqual(observed, ["gki_defconfig", "olddefconfig"])
            self.assertEqual((kernel_out / ".config.previous").read_text(), "old-config\n")
            self.assertEqual((kernel_out / "preserved.o").read_bytes(), b"object")
            self.assertEqual(marker.read_text().strip(), hashlib.sha256(config.read_bytes()).hexdigest())
            with self.assertRaisesRegex(PipelineError, "run the kernel stage before packaging"):
                _require_kernel_receipt(root / "out")

    def test_config_rejects_oplus_f2fs_inode_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "kernel.config").write_text(
                "CONFIG_MODULES=y\nCONFIG_MODVERSIONS=y\nCONFIG_F2FS_OPLUS_INODE_LAYOUT=y\n"
            )
            args = SimpleNamespace(target=str(root / "target.toml"), reuse_output=False)
            manifest = {"target": {"arch": "arm64"}, "build": {"kernel_config": "kernel.config"}}
            with patch("buildsys.toolchain.run"), self.assertRaisesRegex(
                PipelineError, "must disable CONFIG_F2FS_OPLUS_INODE_LAYOUT"
            ):
                configure_kernel(args, manifest, {"kernel": root / "kernel"},
                                 root / "out", {"ARCH": "arm64"})

    def test_failed_reconfiguration_does_not_advance_config_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "kernel.config"
            config.write_text("CONFIG_MODULES=y\nCONFIG_MODVERSIONS=y\n")
            kernel_out = root / "out/kernel-out"
            kernel_out.mkdir(parents=True)
            marker = kernel_out / ".forge-config-sha256"
            marker.write_text("old-input\n")
            (kernel_out / ".config").write_text("old-config\n")
            args = SimpleNamespace(target=str(root / "target.toml"), reuse_output=True)
            with patch("buildsys.toolchain.run", side_effect=PipelineError("failed")):
                with self.assertRaisesRegex(PipelineError, "failed"):
                    configure_kernel(args, {"build": {"kernel_config": "kernel.config"}},
                                     {"kernel": root}, root / "out", {"ARCH": "arm64"})
            self.assertEqual(marker.read_text(), "old-input\n")

    def test_kernel_bootstrap_allows_external_symbols_until_final_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            kernel = root / "kernel"
            kernel.mkdir()
            target_dir = root / "target"
            target_dir.mkdir()
            (target_dir / "kernel.config").write_text(
                "CONFIG_MODULES=y\nCONFIG_MODVERSIONS=y\n"
            )
            output = root / "out"
            args = SimpleNamespace(target=str(target_dir / "target.toml"), jobs=2)
            manifest = {
                "build": {"kernel_config": "kernel.config", "jobs": 2,
                          "kernel_targets": ["Image", "modules"]},
            }
            observed = []

            def fake_run(command, *, env=None, log=None, capture=False, **kwargs):
                observed.append((command, env))
                if "Image" in command:
                    kernel_out = Path(next(item[2:] for item in command if item.startswith("O=")))
                    (kernel_out / "Module.symvers").write_text("\n")
                    (kernel_out / "System.map").write_text("\n")
                output_text = "test-release\n" if command[-1] == "kernelrelease" else ""
                return subprocess.CompletedProcess(command, 0, output_text, "")

            with patch("buildsys.toolchain.run", side_effect=fake_run):
                kernel_out, release = prepare_kernel(
                    args, manifest, {"kernel": kernel}, output, {"ARCH": "arm64"}
                )

            self.assertEqual(release, "test-release")
            self.assertEqual(kernel_out, output / "kernel-out")
            self.assertFalse((kernel_out / ".forge-config-pending").exists())
            build_env = next(env for command, env in observed if "Image" in command)
            self.assertEqual(build_env["KBUILD_MODPOST_WARN"], "1")

    def test_kernel_config_is_restored_when_marked_output_lost_config(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            kernel = root / "kernel"
            kernel.mkdir()
            target_dir = root / "target"
            target_dir.mkdir()
            config = target_dir / "kernel.config"
            config.write_text("CONFIG_MODULES=y\nCONFIG_MODVERSIONS=y\n")
            output = root / "out"
            kernel_out = output / "kernel-out"
            kernel_out.mkdir(parents=True)
            (kernel_out / ".forge-config-sha256").write_text(
                hashlib.sha256(config.read_bytes()).hexdigest() + "\n"
            )
            args = SimpleNamespace(target=str(target_dir / "target.toml"), jobs=2)
            manifest = {
                "build": {"kernel_config": "kernel.config", "jobs": 2,
                          "kernel_targets": ["Image", "modules"]},
            }
            restored_config = []

            def fake_run(command, *, env=None, log=None, capture=False, **kwargs):
                if command[-1] == "olddefconfig":
                    restored_config.append((kernel_out / ".config").read_text())
                if "Image" in command:
                    (kernel_out / "Module.symvers").write_text("\n")
                    (kernel_out / "System.map").write_text("\n")
                output_text = "test-release\n" if command[-1] == "kernelrelease" else ""
                return subprocess.CompletedProcess(command, 0, output_text, "")

            with patch("buildsys.toolchain.run", side_effect=fake_run):
                prepare_kernel(args, manifest, {"kernel": kernel}, output,
                               {"ARCH": "arm64"})

            self.assertEqual(restored_config, [config.read_text()])

    def test_incomplete_output_resets_kernel_out_when_config_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            kernel = root / "kernel"
            kernel.mkdir()
            target_dir = root / "target"
            target_dir.mkdir()
            config = target_dir / "kernel.config"
            config.write_text("CONFIG_MODULES=y\nCONFIG_MODVERSIONS=y\n")
            output = root / "out"
            kernel_out = output / "kernel-out"
            kernel_out.mkdir(parents=True)
            (kernel_out / ".forge-config-sha256").write_text("old-config\n")
            (kernel_out / ".config").write_text("old config\n")
            (output / "module-failures.json").write_text("{}\n")
            args = SimpleNamespace(target=str(target_dir / "target.toml"), jobs=2)
            manifest = {
                "build": {"kernel_config": "kernel.config", "jobs": 2,
                          "kernel_targets": ["Image", "modules"]},
            }
            observed = []

            def fake_run(command, *, env=None, log=None, capture=False, **kwargs):
                observed.append(command)
                if command[-1] == "mrproper":
                    (kernel_out / ".config").unlink()
                if command[-1] == "olddefconfig":
                    (kernel_out / ".config").write_text(config.read_text())
                    self.assertEqual((kernel_out / ".config").read_text(), config.read_text())
                if "Image" in command:
                    (kernel_out / "Module.symvers").write_text("\n")
                    (kernel_out / "System.map").write_text("\n")
                output_text = "test-release\n" if command[-1] == "kernelrelease" else ""
                return subprocess.CompletedProcess(command, 0, output_text, "")

            with patch("buildsys.toolchain.run", side_effect=fake_run):
                prepare_kernel(args, manifest, {"kernel": kernel}, output,
                               {"ARCH": "arm64"})

            self.assertEqual(observed[0][-1], "mrproper")
            self.assertEqual(
                (kernel_out / ".forge-config-sha256").read_text(),
                hashlib.sha256(config.read_bytes()).hexdigest() + "\n",
            )

    def test_completed_output_rejects_kernel_config_change(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            kernel = root / "kernel"
            kernel.mkdir()
            target_dir = root / "target"
            target_dir.mkdir()
            config = target_dir / "kernel.config"
            config.write_text("CONFIG_MODULES=y\nCONFIG_MODVERSIONS=y\n")
            output = root / "out"
            kernel_out = output / "kernel-out"
            kernel_out.mkdir(parents=True)
            (kernel_out / ".forge-config-sha256").write_text("old-config\n")
            (output / "modules-receipt.json").write_text("{}\n")
            args = SimpleNamespace(target=str(target_dir / "target.toml"), jobs=2)
            manifest = {"build": {"kernel_config": "kernel.config"}}

            with patch("buildsys.toolchain.run") as run_mock:
                with self.assertRaisesRegex(PipelineError, "refusing to replace completed"):
                    prepare_kernel(args, manifest, {"kernel": kernel}, output,
                                   {"ARCH": "arm64"})
            run_mock.assert_not_called()

    def test_final_kernel_modpost_filters_conflicting_external_symvers(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            external_symvers = root / "external/Module.symvers"
            external_symvers.parent.mkdir()
            external_symvers.write_text(
                "0x11111111 kernel_owned vendor_a EXPORT_SYMBOL\n"
                "0x22222222 common_external vendor_a EXPORT_SYMBOL\n"
                "0x33333333 crc_conflict vendor_a EXPORT_SYMBOL\n"
            )
            second_symvers = root / "external2/Module.symvers"
            second_symvers.parent.mkdir()
            second_symvers.write_text(
                "0x11111111 kernel_owned vendor_b EXPORT_SYMBOL\n"
                "0x22222222 common_external vendor_b EXPORT_SYMBOL_GPL\n"
                "0x44444444 crc_conflict vendor_b EXPORT_SYMBOL\n"
            )
            kernel_out = root / "out"
            kernel_out.mkdir()
            (kernel_out / "Module.symvers").write_text(
                "0xaaaaaaaa kernel_owned vmlinux EXPORT_SYMBOL\n"
            )
            observed = {}

            def fake_run(command, *, env=None, log=None, **kwargs):
                observed.update(command=command, env=env, log=log)
                return subprocess.CompletedProcess(command, 0, "", "")

            with patch("buildsys.modules.run", side_effect=fake_run):
                _finalize_kernel_modules(
                    root / "kernel", kernel_out, {
                        "ARCH": "arm64", "KBUILD_MODPOST_WARN": "1",
                    }, 4, [external_symvers, second_symvers], root / "logs/final.log",
                )

            filtered_symvers = root / "kernel-extra.symvers"
            self.assertEqual(
                observed["env"]["KBUILD_EXTRA_SYMBOLS"], str(filtered_symvers)
            )
            self.assertEqual(
                filtered_symvers.read_text(),
                "0x22222222 common_external vendor_a EXPORT_SYMBOL\n",
            )
            self.assertNotIn("KBUILD_MODPOST_WARN", observed["env"])
            self.assertEqual(observed["command"][-1], "modules")


class PipelineTests(unittest.TestCase):
    @patch("buildsys.pipeline.build_plan", return_value={})
    def test_packaging_allows_python_upgrade_but_rejects_kernel_change(self, _plan) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name)
        plan = output / "plan.json"
        plan.write_text("{}")
        receipt = {"plan_sha256": hashlib.sha256(plan.read_bytes()).hexdigest()}
        (output / "modules-receipt.json").write_text(json.dumps(receipt))
        previous = {
            "source_states": {"kernel": "locked"},
            "python": {"version": "old", "executable_sha256": "old"},
            "toolchain": {"host_tools": {"python3": {"sha256": "old"}}},
        }
        (output / "build-identity.json").write_text(json.dumps(previous))
        current = {
            "source_states": {"kernel": "locked"},
            "python": {"version": "new", "executable_sha256": "new"},
            "toolchain": {"host_tools": {"python3": {"sha256": "new"}}},
        }
        _require_packaging_identity(output, current, output / "target.toml", {}, {})
        self.assertEqual(current["toolchain"]["host_tools"]["python3"]["sha256"], "new")
        self.assertEqual(json.loads((output / "build-identity.json").read_text()), current)
        changed = dict(current, source_states={"kernel": "different"})
        with self.assertRaisesRegex(PipelineError, "kernel build inputs changed"):
            _require_packaging_identity(output, changed, output / "target.toml", {}, {})

    def test_packaging_accepts_kernel_and_all_stage_receipts(self) -> None:
        for receipt_name in ("kernel-receipt.json", "build-receipt.json"):
            with self.subTest(receipt=receipt_name), tempfile.TemporaryDirectory() as temp:
                output = Path(temp)
                image = output / "kernel-out/arch/arm64/boot/Image"
                image.parent.mkdir(parents=True)
                image.write_bytes(b"fresh kernel")
                (output / "kernelrelease.txt").write_text("6.18-test\n")
                (output / receipt_name).write_text(json.dumps({"kernelrelease": "6.18-test"}))
                self.assertEqual(_require_kernel_receipt(output), (image, "6.18-test"))
                (output / "kernelrelease.txt").write_text("6.18-other\n")
                with self.assertRaisesRegex(PipelineError, "kernel release differs"):
                    _require_kernel_receipt(output)

    def test_packaging_rejects_unreceipted_kernel(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            image = output / "kernel-out/arch/arm64/boot/Image"
            image.parent.mkdir(parents=True)
            image.write_bytes(b"incomplete build")
            (output / "kernelrelease.txt").write_text("6.18-test\n")
            with self.assertRaisesRegex(PipelineError, "kernel receipt is missing"):
                _require_kernel_receipt(output)

    def test_external_build_disables_unrequested_local_modules(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "msm/drivers/char"
            source.mkdir(parents=True)
            (source / "Makefile").write_text(
                "obj-$(CONFIG_MSM_RDBG) += rdbg.o\n"
                "obj-$(CONFIG_VIRTIO_CONSOLE) += virtio_console.o\n"
            )
            command, _ = _external_command(
                {"kernel": root / "kernel", "msm": root / "msm",
                 "vendor": root / "vendor"},
                root / "kernel-out", source, root / "module-out",
                {"configs": ["CONFIG_MSM_RDBG"], "make_vars": {}},
                {"ARCH": "arm64"}, 2, [], False,
            )

        self.assertIn("CONFIG_VIRTIO_CONSOLE=", command)
        self.assertIn("CONFIG_MSM_RDBG=m", command)

    def test_external_build_preserves_modules_support(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "msm/kernel"
            source.mkdir(parents=True)
            (source / "Makefile").write_text(
                "obj-$(CONFIG_MODULES) += module.o\n"
                "obj-$(CONFIG_MSM_SYSSTATS) += msm_sysstats.o\n"
            )
            command, _ = _external_command(
                {"kernel": root / "kernel", "msm": root / "msm",
                 "vendor": root / "vendor"},
                root / "kernel-out", source, root / "module-out",
                {"configs": ["CONFIG_MSM_SYSSTATS"], "make_vars": {}},
                {"ARCH": "arm64"}, 2, [], False,
            )

        self.assertNotIn("CONFIG_MODULES=", command)
        self.assertIn("CONFIG_MSM_SYSSTATS=m", command)

    def test_external_build_preserves_enabled_composite_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "msm/drivers/iommu"
            source.mkdir(parents=True)
            (source / "Makefile").write_text(
                "obj-$(CONFIG_TARGET) += target.o\n"
                "obj-$(CONFIG_COMPOSITE_DEP) += composite_dep.o\n"
                "target-$(CONFIG_COMPOSITE_DEP) += dep.o\n"
            )
            kernel_out = root / "kernel-out"
            kernel_out.mkdir()
            (kernel_out / ".config").write_text(
                "CONFIG_MODULES=y\n"
                "CONFIG_TARGET=m\n"
                "CONFIG_COMPOSITE_DEP=y\n"
            )
            command, _ = _external_command(
                {"kernel": root / "kernel", "msm": root / "msm",
                 "vendor": root / "vendor"},
                kernel_out, source, root / "module-out",
                {"configs": ["CONFIG_TARGET"], "make_vars": {}},
                {"ARCH": "arm64"}, 2, [], False,
            )

        self.assertNotIn("CONFIG_COMPOSITE_DEP=", command)
        self.assertIn("CONFIG_TARGET=m", command)

    def test_external_make_values_expand_explicit_source_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "vendor/vendor/driver"
            source.mkdir(parents=True)
            roots = {
                "kernel": root / "kernel",
                "msm": root / "msm",
                "vendor": root / "vendor",
                "compat": root / "compat",
            }
            command, env = _external_command(
                roots, root / "kernel-out", source, root / "module-out",
                {
                    "configs": ["CONFIG_TEST"],
                    "kcflags": ["-include {root:compat}/compat_header.h"],
                    "make_vars": {
                        "DATA_ROOT": "{root:vendor}/vendor-data",
                        "MODNAME": "test_module",
                        "WLAN_ROOT": "{source}",
                    },
                },
                {"ARCH": "arm64", "KCFLAGS": "-DLOCAL=1"}, 2, [], False,
            )

        self.assertIn(f"DATA_ROOT={roots['vendor'] / 'vendor/vendor-data'}", command)
        self.assertIn(f"WLAN_ROOT={source}", command)
        self.assertIn("MODNAME=test_module", command)
        self.assertIn("-DLOCAL=1", env["KCFLAGS"])
        self.assertIn("-DCONFIG_TEST_MODULE", env["KCFLAGS"])
        self.assertIn(f"-include {roots['compat'] / 'compat_header.h'}", env["KCFLAGS"])

    def test_external_camera_roots_expand_to_declared_vendor_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            vendor = root / "vendor"
            (vendor / "vendor/qcom/opensource/camera-kernel").mkdir(parents=True)
            source = vendor / "vendor/qcom/opensource/camera-kernel"
            command, _ = _external_command(
                {"kernel": root / "kernel", "msm": root / "msm", "vendor": vendor},
                root / "kernel-out", source, root / "module-out",
                {"configs": ["CONFIG_CAMERA"], "make_vars": {
                    "CAMERA_KERNEL_ROOT": "{root:vendor}/qcom/opensource/camera-kernel",
                    "DISPLAY_ROOT": "{root:vendor}/qcom/opensource/display-drivers",
                }},
                {"ARCH": "arm64"}, 1, [], False,
            )
        self.assertIn(
            f"CAMERA_KERNEL_ROOT={vendor / 'vendor/qcom/opensource/camera-kernel'}",
            command,
        )
        self.assertIn(
            f"DISPLAY_ROOT={vendor / 'vendor/qcom/opensource/display-drivers'}",
            command,
        )

    def test_external_index_uses_kernel_output_symvers_without_duplicate_input(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "vendor/vendor/driver"
            source.mkdir(parents=True)
            command, env = _external_command(
                {"kernel": root / "kernel", "msm": root / "msm",
                 "vendor": root / "vendor"},
                root / "kernel-out", source, root / "module-out",
                {"configs": ["CONFIG_TEST"], "make_vars": {}},
                {"ARCH": "arm64", "KBUILD_EXTRA_SYMBOLS": "/stale/Module.symvers"},
                2, [], False,
            )

        self.assertIn(f"O={root / 'kernel-out'}", command)
        self.assertNotIn("KBUILD_EXTRA_SYMBOLS", env)

    def test_common_arguments_work_before_and_after_subcommand(self) -> None:
        args = parser().parse_args([
            "--kernel-src", "/src/kernel", "--out", "/tmp/out", "plan",
            "--vendor-src", "/src/vendor", "--module-jobs", "3", "--allow-unresolved",
        ])

        self.assertEqual(args.command, "plan")
        self.assertEqual(args.kernel_src, "/src/kernel")
        self.assertEqual(args.vendor_src, "/src/vendor")
        self.assertEqual(args.module_jobs, 3)
        self.assertTrue(args.allow_unresolved)

    def test_doctor_is_a_first_class_pipeline_stage(self) -> None:
        args = parser().parse_args([
            "doctor", "--kernel-src", "/src/kernel", "--out", "/tmp/out",
        ])

        self.assertEqual(args.command, "doctor")
        self.assertEqual(args.kernel_src, "/src/kernel")

    def test_independent_boot_and_system_dlkm_packaging_stages(self) -> None:
        boot = parser().parse_args(["boot"])
        system = parser().parse_args([
            "system-dlkm", "--materials", "/inputs/device-materials",
        ])

        self.assertEqual(boot.command, "boot")
        self.assertIsNone(boot.materials)
        self.assertEqual(system.command, "system-dlkm")
        self.assertEqual(system.materials, "/inputs/device-materials")

    def test_packaging_accepts_legacy_identity_without_a_source_lock_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            previous = {"source_states": {"kernel": {"revision": "any-revision"}},
                        "source_lock_sha256": "obsolete-lock-digest"}
            (output / "build-identity.json").write_text(json.dumps(previous))
            current = {"source_states": previous["source_states"]}
            _require_packaging_identity(output, current, output / "target.toml", {}, {},
                                        gki_only=True)
            self.assertEqual(json.loads((output / "build-identity.json").read_text()), previous)
            changed = {"source_states": {"kernel": {"revision": "changed"}}}
            with self.assertRaisesRegex(PipelineError, "kernel build inputs changed"):
                _require_packaging_identity(output, changed, output / "target.toml", {}, {},
                                            gki_only=True)

    def test_check_group_is_a_diagnostic_stage(self) -> None:
        args = parser().parse_args([
            "check-group", "--group-id", "msm_drivers_spi_33ed1fc1",
        ])

        self.assertEqual(args.command, "check-group")
        self.assertEqual(args.group_id, "msm_drivers_spi_33ed1fc1")

    def test_prebuilt_module_import_is_not_a_pipeline_stage(self) -> None:
        with self.assertRaises(SystemExit):
            parser().parse_args(["import-modules", "--prebuilt-modules", "/tmp/modules",
                                 "--reuse-kernel-out", "/tmp/kernel-out"])

    def test_tree_digest_does_not_depend_on_mtime(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "file"
            path.write_text("same contents")
            before = tree_digest(Path(temp))
            os.utime(path, (1, 1))

            self.assertEqual(before, tree_digest(Path(temp)))

    def test_tree_digest_can_exclude_packaging_selinux_xattr(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "file"
            path.write_text("same contents")
            try:
                os.setxattr(path, "user.pipeline-test", b"label")
            except OSError as error:
                self.skipTest(f"user xattrs unavailable: {error}")

            all_xattrs = tree_digest(Path(temp))
            ignored = tree_digest(
                Path(temp), ignored_xattrs=frozenset({"user.pipeline-test"})
            )
            self.assertNotEqual(all_xattrs, ignored)

    def test_compat_source_is_recorded_without_a_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            compat = root / "compat"
            compat.mkdir()
            source = compat / "shim.c"
            source.write_text("int shim(void) { return 0; }\n")
            state = _source_states({"compat": compat})
            self.assertEqual(state["compat"]["tree_sha256"], tree_digest(compat))
            source.write_text("int shim(void) { return 1; }\n")
            self.assertNotEqual(_source_states({"compat": compat}), state)

    def test_dirty_git_source_is_accepted_and_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            root.mkdir()
            (root / "source.c").write_text("int value(void) { return 1; }\n")
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", "source.c"], check=True)
            subprocess.run([
                "git", "-C", str(root), "-c", "user.name=Test",
                "-c", "user.email=test@example.invalid", "commit", "-qm", "base",
            ], check=True)
            (root / "source.c").write_text("int value(void) { return 2; }\n")
            state = source_state(root, [])
            verified = _source_states({"test": root})
            self.assertEqual(verified["test"]["dirty_sha256"], state["dirty_sha256"])
            (root / "source.c").write_text("int value(void) { return 3; }\n")
            self.assertNotEqual(_source_states({"test": root}), verified)

            extracted = root / "extracted"
            extracted.mkdir()
            (extracted / "source.c").write_text("int value(void) { return 4; }\n")
            extracted_state = _source_states({"test": extracted})["test"]
            self.assertIsNone(extracted_state["revision"])
            self.assertEqual(extracted_state["dirty_sha256"], tree_digest(extracted))


if __name__ == "__main__":
    unittest.main()
