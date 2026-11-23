from pathlib import Path
import shutil
import tarfile
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from buildsys.common import PipelineError
from buildsys.images import stage_images
from buildsys.recovery import recovery_inputs, recovery_module_order, verify_recovery_contents
from buildsys.recovery_image import (
    enable_vibrator_service, gate_recovery_display, patch_policy, remove_late_firmware_link,
)


class RecoveryTests(unittest.TestCase):
    def test_display_wait_only_changes_recovery_service_command(self):
        options = ("    socket recovery stream 422 system system\n"
                   "    seclabel u:r:recovery:s0\n"
                   "\nservice fastbootd /system/bin/fastbootd\n    disabled\n")
        source = "service recovery /system/bin/recovery\n" + options
        self.assertEqual(gate_recovery_display(source),
                         "service recovery /system/bin/sh /system/bin/recovery-wait-display.sh\n"
                         + options)
        for invalid in ("service recovery /sbin/recovery\n", source + source):
            with self.assertRaises(PipelineError):
                gate_recovery_display(invalid)

    def test_firmware_link_patch_preserves_read_only_mount_and_service_start(self):
        source = ("on property:twrp.modules.loaded=true\n"
                  "    mount vfat /dev/block/by-name/modem${ro.boot.slot_suffix} /firmware ro\n"
                  "    start vendor.secure_element\n")
        self.assertEqual(remove_late_firmware_link(
            source + "    symlink /firmware /vendor/firmware_mnt\n"), source)
        with self.assertRaises(PipelineError):
            remove_late_firmware_link(source)

    def test_vibrator_service_autostarts_and_declares_aidl_without_changing_permissions(self):
        source = ("on boot\n    chmod 0666 /dev/awinic_haptic\n\n"
                  "service vendor.oplus.vibrator /vendor/bin/hw/vendor.oplus.hardware.vibrator-service\n"
                  "    class late_start\n    user root\n    group root\n    disabled\n"
                  "    seclabel u:r:recovery:s0\n    setenv RICHTAP_DEVICE_PATH /dev/awinic_haptic\n\n"
                  "service other /bin/other\n    disabled\n")
        result = enable_vibrator_service(source)
        self.assertIn("    class hal\n    interface aidl android.hardware.vibrator.IVibrator/default\n", result)
        self.assertIn("on boot\n    chmod 0666 /dev/awinic_haptic\n", result)
        self.assertIn("    user root\n    group root\n    seclabel u:r:recovery:s0\n", result)
        self.assertIn("service other /bin/other\n    disabled\n", result)
        self.assertEqual(enable_vibrator_service(result), result)
        with self.assertRaises(PipelineError):
            enable_vibrator_service("service other /bin/other\n")
        with self.assertRaises(PipelineError):
            enable_vibrator_service(source + source)

    @patch("buildsys.recovery_image.run")
    def test_policy_semantics_allow_only_two_firmware_rules_and_class_permission(self, run):
        old = "(class system (ipc_info syslog_read syslog_mod syslog_console module_request module_load))"
        new = old[:-2] + " firmware_load))"
        rules = "(allow kernel rootfs (system (firmware_load)))\n(allow kernel vendor_file (system (firmware_load)))"
        run.side_effect = [subprocess.CompletedProcess([], 0, old, ""), None,
                           subprocess.CompletedProcess([], 0, new + "\n" + rules, "")]
        patch_policy(Path("tool"), Path("original"), Path("patched"))
        run.side_effect = [subprocess.CompletedProcess([], 0, old, ""), None,
                           subprocess.CompletedProcess([], 0, new + "\n" + rules + "\n(allow bad rule)", "")]
        with self.assertRaisesRegex(PipelineError, "exceed"):
            patch_policy(Path("tool"), Path("original"), Path("patched"))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.modules = self.root / "modules-stripped"
        self.modules.mkdir()
        for name in ["early", "display", "touch", "pwm-driver", "late"]:
            (self.modules / f"{name}.ko").write_bytes(name.encode())

    @patch("buildsys.recovery.subprocess.run")
    def test_order_includes_dependencies_aliases_and_softdeps(self, run):
        metadata = {"early": "depends:\n", "display": "depends: pwm_driver\nsoftdep: post: late\n",
                    "touch": "depends:\n", "pwm-driver": "depends:\n", "late": "depends:\n"}
        run.side_effect = lambda command, **kwargs: subprocess.CompletedProcess(
            command, 0, metadata[Path(command[-1]).stem], "")
        softdep = self.root / "modules.softdep"
        softdep.write_text("softdep display pre:touch unavailable_optional\n")
        self.assertEqual(recovery_module_order(self.modules, ["early", "display", "touch"],
                                              Path("modinfo"), [softdep]),
                         ["early", "pwm-driver", "touch", "display", "late"])

    @patch("buildsys.recovery.subprocess.run")
    def test_missing_required_dependency_and_cycles_fail(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, "depends: absent\n", "")
        with self.assertRaisesRegex(PipelineError, "not built: absent"):
            recovery_module_order(self.modules, ["display"], Path("modinfo"), [])
        run.return_value = subprocess.CompletedProcess([], 0, "depends: display\n", "")
        with self.assertRaisesRegex(PipelineError, "cycle"):
            recovery_module_order(self.modules, ["display"], Path("modinfo"), [])

    def test_recovery_list_is_an_explicit_packaging_input(self):
        self.assertEqual(recovery_inputs(self.root / "target.toml", {}), {})
        manifest = {"images": {"vendor_boot": {"recovery_modules_list": "recovery.list"}}}
        (self.root / "recovery.list").write_text("display.ko\ntouch\n")
        self.assertEqual(recovery_inputs(self.root / "target.toml", manifest),
                         {"recovery_modules": ["display", "touch"]})

    @patch("buildsys.images._depmod")
    @patch("buildsys.images.recovery_dependencies", return_value={})
    @patch("buildsys.images.recovery_module_order", return_value=["early", "display", "touch"])
    def test_staging_keeps_normal_lists_and_dlkm_ownership(self, order, dependencies, depmod):
        from buildsys.materials import DLKM_ETC_FILES

        materials = self.root / "materials"
        etc = materials / "vendor_dlkm/etc"
        etc.mkdir(parents=True)
        for name in DLKM_ETC_FILES:
            (etc / name).touch()
        (materials / "vendor_dlkm/lib").mkdir()
        (materials / "vendor_dlkm/lib/legacy.ko").touch()
        with tarfile.open(materials / "vendor_ramdisk.tar", "w"):
            pass
        policy = self.root / "policy"
        policy.mkdir()
        (policy / "modules.blocklist").write_text("blocklist test\n")
        (policy / "vendor_dlkm.softdep").write_text("softdep display pre: early\n")
        plan = {"vendor_boot": ["early"], "vendor_dlkm": ["display", "touch"]}
        staging = stage_images({}, plan, self.root, materials, policy, "6.18", {"modinfo": Path("modinfo"),
                               "depmod": Path("depmod")}, ["display", "touch"])
        boot = staging["vendor_boot"] / "lib/modules"
        self.assertEqual((boot / "modules.load").read_text(), "early\n")
        self.assertEqual((boot / "modules.load.recovery").read_text(), "early.ko\ndisplay.ko\ntouch.ko\n")
        self.assertEqual((staging["vendor_dlkm"] / "lib/modules/modules.load").read_text(), "display\ntouch\n")
        self.assertTrue((boot / "touch.ko").is_file())
        self.assertTrue((staging["vendor_dlkm"] / "lib/modules/touch.ko").is_file())
        self.assertFalse((staging["vendor_dlkm"] / "lib/legacy.ko").exists())
        self.assertEqual((boot / "modules.blocklist").read_text(), "blocklist test\n")
        self.assertEqual((boot / "modules.softdep").read_text(), "softdep display pre: early\n")

    def test_delivered_recovery_requires_local_dependencies_and_identical_bytes(self):
        stage = self.root / "stage"
        stage.mkdir()
        (stage / "modules.load").write_text("early\n")
        (stage / "modules.load.recovery").write_text("early.ko\ndisplay.ko\n")
        for name in ["early", "display"]:
            shutil.copy2(self.modules / f"{name}.ko", stage)
        (stage / "modules.dep").write_text("early.ko:\ndisplay.ko: early.ko\n")
        delivered = self.root / "delivered"
        shutil.copytree(stage, delivered)
        verify_recovery_contents(delivered, stage)
        (delivered / "modules.dep").write_text("display.ko: absent.ko\n")
        with self.assertRaisesRegex(PipelineError, "dependency is missing"):
            verify_recovery_contents(delivered, stage)
        (delivered / "display.ko").write_bytes(b"stale")
        with self.assertRaisesRegex(PipelineError, "differs from staging"):
            verify_recovery_contents(delivered, stage)
