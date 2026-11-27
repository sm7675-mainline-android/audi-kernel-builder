from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from .catalog import PipelineError, build_plan, kernel_config_path, load_toml, source_roots, write_plan
from .common import find_tool, output_lock, reject_whitespace, run, sha256_file, tree_digest, write_json
from .images import (
    build_boot_image, build_images, build_system_dlkm_image, stage_images,
    check_erofs_tool, verify_four_images,
)
from .materials import VENDOR_POLICY, check_materials, system_modules, target_file
from .dtb import validate_reserved_memory
from .modules import build_modules, module_vermagic, _group_id, _kernel_module
from .toolchain import build_environment, configure_kernel, prepare_kernel, resolve_tools, source_state, toolchain_identity


HERE = Path(__file__).resolve().parents[1]
DEFAULT_KERNEL = HERE / "src/kernel"
DEFAULT_MSM = HERE / "src/msm"
DEFAULT_VENDOR = HERE / "src/vendor"
DEFAULT_TOOLCHAIN = HERE / "src/llvm/bin"


def _normalize_args(args: argparse.Namespace) -> None:
    args.target = str(Path(args.target).expanduser().resolve())
    args.out = str(Path(args.out).expanduser().resolve())
    for name in ("kernel_src", "msm_src", "vendor_src", "compat_src", "toolchain", "tools_dir",
                 "materials"):
        value = getattr(args, name, None)
        if value:
            setattr(args, name, str(Path(value).expanduser().resolve()))
    normalized_extras = []
    for entry in getattr(args, "extra_src", []) or []:
        if "=" not in entry:
            normalized_extras.append(entry)
            continue
        name, path = entry.split("=", 1)
        normalized_extras.append(f"{name}={Path(path).expanduser().resolve()}")
    args.extra_src = normalized_extras


def load_context(args: argparse.Namespace) -> tuple[Path, dict[str, Any], dict[str, Path], Path]:
    target = Path(args.target)
    manifest = load_toml(target)
    roots = source_roots(args)
    output = Path(args.out)
    output.mkdir(parents=True, exist_ok=True)
    paths = [*roots.values(), output, Path(args.toolchain)]
    paths.extend(Path(entry.split("=", 1)[1]) for entry in args.extra_src)
    reject_whitespace(paths)
    return target, manifest, roots, output


def _source_states(roots: dict[str, Path]) -> dict[str, Any]:
    return {
        name: ({"revision": None, "dirty": False, "tree_sha256": tree_digest(root)}
               if name == "compat" else source_state(root, ["out"] if name == "kernel" else []))
        for name, root in roots.items()
    }


def _plan(args: argparse.Namespace, target: Path, manifest: dict[str, Any],
          roots: dict[str, Path], output: Path, *, require_complete: bool) -> dict[str, Any]:
    plan = build_plan(target, roots, manifest)
    write_plan(plan, output / "plan.json")
    if require_complete and plan["unresolved"]:
        raise PipelineError("unresolved modules: " + ", ".join(plan["unresolved"]))
    if require_complete and plan["ambiguous"]:
        raise PipelineError("module source conflicts: " + ", ".join(sorted(plan["ambiguous"])))
    if not require_complete and plan["unresolved"] and not args.allow_unresolved:
        raise PipelineError(
            "unresolved modules: " + ", ".join(plan["unresolved"])
            + "; use --allow-unresolved for inventory-only planning"
        )
    if not require_complete and plan["ambiguous"] and args.strict_ambiguity:
        raise PipelineError("ambiguous modules: " + ", ".join(sorted(plan["ambiguous"])))
    return plan


def _toolchain_and_env(args: argparse.Namespace, manifest: dict[str, Any],
                       roots: dict[str, Path], output: Path
                       ) -> tuple[dict[str, Any], dict[str, str], dict[str, Path]]:
    host_tools = resolve_tools(
        Path(args.tools_dir) if args.tools_dir else None,
        args.avbtool,
    )
    identity = toolchain_identity(Path(args.toolchain), host_tools)
    env = build_environment(
        manifest, roots, Path(args.toolchain),
        Path(args.tools_dir) if args.tools_dir else None,
        output,
    )
    return identity, env, host_tools


def _build_identity(target: Path, manifest: dict[str, Any], states: dict[str, Any],
                    toolchain: dict[str, Any], roots: dict[str, Path]) -> dict[str, Any]:
    config = kernel_config_path(target, manifest, roots)
    pipeline_files = [HERE / "forge.py", *sorted((HERE / "buildsys").rglob("*.py"))]
    pipeline_digest = hashlib.sha256()
    for path in pipeline_files:
        if "__pycache__" in path.parts:
            continue
        pipeline_digest.update(path.relative_to(HERE).as_posix().encode() + b"\0")
        pipeline_digest.update(bytes.fromhex(sha256_file(path)))
    source_patches = []
    for item in manifest.get("build", {}).get("source_patches", []):
        patch_path = (HERE / item["file"]).resolve()
        source_patches.append({
            "root": item["root"],
            "file": item["file"],
            "sha256": sha256_file(patch_path),
        })
    return {
        "schema": 1,
        "target_sha256": sha256_file(target),
        "config_sha256": sha256_file(config),
        "pipeline_sha256": pipeline_digest.hexdigest(),
        "source_patches": source_patches,
        "source_states": states,
        "python": {
            "version": sys.version.splitlines()[0],
            "executable_sha256": sha256_file(Path(sys.executable).resolve()),
        },
        "toolchain": toolchain,
    }


def _check_identity(
    output: Path, identity: dict[str, Any], *, allow_reuse: bool = False
) -> None:
    path = output / "build-identity.json"
    if path.exists():
        try:
            current = json.loads(path.read_text())
        except json.JSONDecodeError as error:
            raise PipelineError(f"invalid build identity receipt: {path}") from error
        if current != identity:
            failure_path = output / "module-failures.json"
            modules_receipt = output / "modules-receipt.json"
            if not allow_reuse and (not failure_path.is_file() or modules_receipt.exists()):
                raise PipelineError(
                    "--out contains completed artifacts from different inputs; "
                    "use --reuse-output for an intentional development rebuild"
                )
            previous = output / "build-identity.previous.json"
            shutil.copy2(path, previous)
            write_json(path, identity)
            reason = "explicitly requested" if allow_reuse else "incomplete module build"
            print(f"Reusing output ({reason}); previous identity saved to {previous}")
    else:
        write_json(path, identity)


def _require_identity(output: Path, identity: dict[str, Any]) -> None:
    path = output / "build-identity.json"
    if not path.is_file():
        raise PipelineError("build identity is missing; run build-modules first")
    try:
        current = json.loads(path.read_text())
    except json.JSONDecodeError as error:
        raise PipelineError(f"invalid build identity receipt: {path}") from error
    if current != identity:
        raise PipelineError("build inputs changed since module compilation; choose a new --out")


def _require_packaging_identity(
    output: Path, identity: dict[str, Any], target: Path,
    roots: dict[str, Path], manifest: dict[str, Any], *, gki_only: bool = False,
    ignore_kernel_source_state: bool = False,
) -> None:
    path = output / "build-identity.json"
    if not path.is_file():
        raise PipelineError("build identity is missing; run the kernel stage first")
    try:
        current = json.loads(path.read_text())
    except json.JSONDecodeError as error:
        raise PipelineError(f"invalid build identity receipt: {path}") from error
    expected = dict(identity)
    actual = dict(current)
    actual.pop("source_lock_sha256", None)
    expected.pop("pipeline_sha256", None)
    actual.pop("pipeline_sha256", None)
    expected.pop("target_sha256", None)
    actual.pop("target_sha256", None)
    expected.pop("python", None)
    actual.pop("python", None)
    expected_tools = dict(expected.pop("toolchain", {}))
    actual_tools = dict(actual.pop("toolchain", {}))
    expected_hosts = dict(expected_tools.pop("host_tools", {}))
    actual_hosts = dict(actual_tools.pop("host_tools", {}))
    expected_hosts.pop("python3", None)
    actual_hosts.pop("python3", None)
    if ignore_kernel_source_state:
        expected_sources = expected.get("source_states")
        actual_sources = actual.get("source_states")
        if isinstance(expected_sources, dict) and isinstance(actual_sources, dict):
            expected_sources = dict(expected_sources)
            actual_sources = dict(actual_sources)
            expected_sources.pop("kernel", None)
            actual_sources.pop("kernel", None)
            expected["source_states"] = expected_sources
            actual["source_states"] = actual_sources
    hosts_match = all(expected_hosts.get(name) == value
                      for name, value in actual_hosts.items())
    if actual != expected or actual_tools != expected_tools or not hosts_match:
        raise PipelineError("kernel build inputs changed; cannot package existing kernel artifacts")
    if gki_only:
        return
    stored_plan = output / "plan.json"
    module_receipt_path = output / "modules-receipt.json"
    if not stored_plan.is_file() or not module_receipt_path.is_file():
        raise PipelineError("completed module plan and receipt are required for image packaging")
    try:
        receipt = json.loads(module_receipt_path.read_text())
        previous_plan = json.loads(stored_plan.read_text())
    except json.JSONDecodeError as error:
        raise PipelineError("invalid module plan or receipt") from error
    current_plan = build_plan(target, roots, manifest)
    plan_keys = ("groups", "vendor_boot", "vendor_dlkm", "excluded", "unresolved", "ambiguous")
    if any(previous_plan.get(key) != current_plan.get(key) for key in plan_keys):
        raise PipelineError("module target changed; existing vendor modules cannot be reused")
    if receipt.get("plan_sha256") != sha256_file(stored_plan):
        raise PipelineError("module receipt does not match the stored module plan")
    # Image-only target edits and packaging-code updates must not force the
    # expensive external vendor module build to run again.
    new_identity_path = output / "build-identity.json"
    if current != identity:
        write_json(new_identity_path, identity)
        receipt["build_identity_sha256"] = sha256_file(new_identity_path)
        write_json(module_receipt_path, receipt)
        stage_receipt_path = output / "staging-receipt.json"
        if stage_receipt_path.is_file():
            stage_receipt = json.loads(stage_receipt_path.read_text())
            stage_receipt["modules_receipt_sha256"] = sha256_file(module_receipt_path)
            write_json(stage_receipt_path, stage_receipt)


def _verify_modules_receipt(output: Path, plan: dict[str, Any]) -> dict[str, Any]:
    from .btf import base_btf_sha256
    path = output / "modules-receipt.json"
    if not path.is_file():
        raise PipelineError("modules receipt is missing; run build-modules first")
    try:
        receipt = json.loads(path.read_text())
    except json.JSONDecodeError as error:
        raise PipelineError(f"invalid modules receipt: {path}") from error
    if receipt.get("plan_sha256") != sha256_file(output / "plan.json"):
        raise PipelineError("module plan changed since compilation; choose a new --out")
    if receipt.get("module_count") != len(plan["modules"]):
        raise PipelineError("module receipt does not match the current plan")
    release_path = output / "kernelrelease.txt"
    if not release_path.is_file() or receipt.get("kernelrelease") != release_path.read_text().strip():
        raise PipelineError("kernel release does not match the module receipt")
    identity_path = output / "build-identity.json"
    if receipt.get("build_identity_sha256") != sha256_file(identity_path):
        raise PipelineError("module receipt belongs to a different build identity")
    if receipt.get("base_btf_sha256") != base_btf_sha256(output / "kernel-out/vmlinux"):
        raise PipelineError("module BTF cache belongs to another vmlinux; run incremental build-modules")
    return receipt


def _write_staging_receipt(output: Path) -> dict[str, Any]:
    staging = output / "staging"
    receipt = {
        "schema": 1,
        "plan_sha256": sha256_file(output / "plan.json"),
        "modules_receipt_sha256": sha256_file(output / "modules-receipt.json"),
        "stage_inputs_sha256": sha256_file(output / "stage-inputs.json"),
        "trees": {
            name: tree_digest(
                staging / name,
                ignored_xattrs=frozenset({"security.selinux"}),
            )
            for name in ("vendor_boot", "vendor_dlkm")
        },
    }
    write_json(output / "staging-receipt.json", receipt)
    return receipt


def _verify_staging_receipt(output: Path) -> dict[str, Any]:
    path = output / "staging-receipt.json"
    if not path.is_file():
        raise PipelineError("staging receipt is missing; run stage first")
    try:
        receipt = json.loads(path.read_text())
    except json.JSONDecodeError as error:
        raise PipelineError(f"invalid staging receipt: {path}") from error
    if receipt.get("plan_sha256") != sha256_file(output / "plan.json"):
        raise PipelineError("staging was produced from a different module plan")
    if receipt.get("stage_inputs_sha256") != sha256_file(output / "stage-inputs.json"):
        raise PipelineError("staging was produced from different device materials; run stage again")
    modules_path = output / "modules-receipt.json"
    if receipt.get("modules_receipt_sha256") != sha256_file(modules_path):
        raise PipelineError("module receipt changed after staging")
    staging = output / "staging"
    expected_trees = receipt.get("trees", {})
    for name, expected in expected_trees.items():
        actual = tree_digest(
            staging / name,
            ignored_xattrs=frozenset({"security.selinux"}),
        )
        if actual != expected:
            raise PipelineError(f"staged {name} tree changed after stage; run stage again")
    if set(expected_trees) != {"vendor_boot", "vendor_dlkm"}:
        raise PipelineError("staging receipt is incomplete")
    return receipt


def _stage_identity(target: Path, manifest: dict[str, Any], materials: Path) -> dict[str, Any]:
    from .recovery import recovery_inputs
    return {
        **recovery_inputs(target, manifest),
        "vendor_boot": check_materials(target, manifest, materials, "vendor_boot"),
        "vendor_dlkm": check_materials(target, manifest, materials, "vendor_dlkm"),
        "module_policy": {name: sha256_file(target_file(target, f"modules/{name}"))
                          for name in VENDOR_POLICY},
    }


def _materials(args: argparse.Namespace) -> Path:
    if not args.materials or not Path(args.materials).is_dir():
        raise PipelineError("--materials must point to the locked device materials directory")
    return Path(args.materials)


def _system_dlkm_inputs(target: Path, manifest: dict[str, Any], materials: Path) -> dict[str, Any]:
    names = system_modules(target, manifest)
    path = target_file(target, manifest["images"]["system_dlkm"]["modules_list"])
    return {
        "materials": check_materials(target, manifest, materials, "system_dlkm"),
        "modules_list_sha256": sha256_file(path),
        "module_count": len(names),
    }


def _check_stage_identity(output: Path, identity: dict[str, Any], *, allow_reuse: bool = False) -> None:
    path = output / "stage-inputs.json"
    if path.exists() and json.loads(path.read_text()) != identity:
        if not allow_reuse:
            raise PipelineError("stage inputs changed; run stage with --reuse-output")
        shutil.copy2(path, output / "stage-inputs.previous.json")
    if not path.exists():
        write_json(path, identity)
    elif allow_reuse:
        write_json(path, identity)


def plan_command(args: argparse.Namespace) -> int:
    target, manifest, roots, output = load_context(args)
    with output_lock(output):
        plan = _plan(args, target, manifest, roots, output, require_complete=False)
    print(json.dumps({
        "target": plan["target"],
        "vendor_boot": len(plan["vendor_boot"]),
        "vendor_dlkm": len(plan["vendor_dlkm"]),
        "groups": len(plan["groups"]),
        "unresolved": len(plan["unresolved"]),
        "ambiguous": len(plan["ambiguous"]),
        "plan": str(output / "plan.json"),
    }, indent=2))
    return 0


def doctor_command(args: argparse.Namespace) -> int:
    """Validate all explicit inputs without compiling or mutating source trees."""
    target, manifest, roots, output = load_context(args)
    with output_lock(output):
        states = _source_states(roots)
        toolchain, _, host_tools = _toolchain_and_env(args, manifest, roots, output)
        plan = _plan(args, target, manifest, roots, output, require_complete=True)
        check_erofs_tool(host_tools["mkfs.erofs"])
        materials = _materials(args)
        stage_inputs = _stage_identity(target, manifest, materials)
        system_inputs = _system_dlkm_inputs(target, manifest, materials)
    result = {
        "target": plan["target"],
        "sources": states,
        "toolchain": toolchain,
        "host_tools": {name: str(path) for name, path in sorted(host_tools.items())},
        "vendor_boot": len(plan["vendor_boot"]),
        "vendor_dlkm": len(plan["vendor_dlkm"]),
        "groups": len(plan["groups"]),
        "stage_inputs": stage_inputs,
        "system_dlkm_inputs": system_inputs,
        "plan": str(output / "plan.json"),
        "status": "ready",
    }
    write_json(output / "doctor.json", result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def config_command(args: argparse.Namespace) -> int:
    target, manifest, roots, output = load_context(args)
    with output_lock(output):
        states = _source_states(roots)
        toolchain, env, _ = _toolchain_and_env(args, manifest, roots, output)
        _check_identity(output, _build_identity(target, manifest, states, toolchain, roots),
                        allow_reuse=args.reuse_output)
        kernel_out = configure_kernel(args, manifest, roots, output, env)
        run(["make", "-C", str(roots["kernel"]), f"O={kernel_out}",
             f"ARCH={env['ARCH']}", "LLVM=1", "savedefconfig"],
            env=env, log=output / "logs/kernel-savedefconfig.log")
        print(f"config={kernel_out / '.config'}")
        print(f"defconfig={kernel_out / 'defconfig'}")
    return 0


def kernel_command(args: argparse.Namespace) -> int:
    from .btf import base_btf_sha256
    target, manifest, roots, output = load_context(args)
    with output_lock(output):
        states = _source_states(roots)
        toolchain, env, _ = _toolchain_and_env(args, manifest, roots, output)
        _check_identity(output, _build_identity(target, manifest, states, toolchain, roots),
                        allow_reuse=args.reuse_output)
        kernel_out, release = prepare_kernel(args, manifest, roots, output, env)
        write_json(output / "kernel-receipt.json", {
            "kernelrelease": release,
            "kernel_out": str(kernel_out),
            "module_symvers_sha256": sha256_file(kernel_out / "Module.symvers"),
            "base_btf_sha256": base_btf_sha256(kernel_out / "vmlinux"),
        })
        print(f"kernelrelease={release}")
    return 0


def modules_command(args: argparse.Namespace) -> int:
    target, manifest, roots, output = load_context(args)
    with output_lock(output):
        states = _source_states(roots)
        toolchain, env, _ = _toolchain_and_env(args, manifest, roots, output)
        _check_identity(output, _build_identity(target, manifest, states, toolchain, roots),
                        allow_reuse=args.reuse_output)
        plan = _plan(args, target, manifest, roots, output, require_complete=True)
        selected = set(args.module) if args.module else None
        if selected is not None:
            _, release = _require_kernel_receipt(output)
            kernel_out = output / "kernel-out"
        else:
            kernel_out, release = prepare_kernel(args, manifest, roots, output, env)
        receipt = build_modules(args, manifest, roots, plan, output, kernel_out, release, env,
                                selected_modules=selected, incremental=args.incremental)
        receipt["plan_sha256"] = sha256_file(output / "plan.json")
        receipt["build_identity_sha256"] = sha256_file(output / "build-identity.json")
        write_json(output / "modules-receipt.json", receipt)
        (output / "module-failures.json").unlink(missing_ok=True)
        print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


def reuse_staged_modules_command(args: argparse.Namespace) -> int:
    """Reuse verified staged vendor modules when only kernel-owned modules change."""
    from .btf import audit_btf, stale_split_modules
    target, manifest, roots, output = load_context(args)
    with output_lock(output):
        states = _source_states(roots)
        toolchain, _, _ = _toolchain_and_env(args, manifest, roots, output)
        identity = _build_identity(target, manifest, states, toolchain, roots)
        _check_identity(output, identity, allow_reuse=True)
        plan = _plan(args, target, manifest, roots, output, require_complete=True)
        _, release = _require_kernel_receipt(output)
        kernel_out = output / "kernel-out"

        old_receipt_path = output / "modules-receipt.json"
        stage_receipt_path = output / "staging-receipt.json"
        if not old_receipt_path.is_file() or not stage_receipt_path.is_file():
            raise PipelineError("staged module artifacts and receipts are required")
        old_receipt = json.loads(old_receipt_path.read_text())
        stage_receipt = json.loads(stage_receipt_path.read_text())
        if old_receipt.get("kernelrelease") != release:
            raise PipelineError("staged modules were built for a different kernel release")
        current_external_groups = [
            _group_id(group) for group in plan["groups"] if group["root"] != "kernel"
        ]
        if old_receipt.get("external_groups") != current_external_groups:
            raise PipelineError("external module plan changed; reuse is limited to kernel modules")

        staging = output / "staging"
        expected_trees = stage_receipt.get("trees", {})
        for name in ("vendor_boot", "vendor_dlkm"):
            tree = staging / name
            expected_digest = expected_trees.get(name)
            if not tree.is_dir() or not expected_digest or tree_digest(
                tree, ignored_xattrs=frozenset({"security.selinux"})
            ) != expected_digest:
                raise PipelineError(f"existing staged {name} tree does not match its receipt")

        available: dict[str, Path] = {}
        for name in ("vendor_boot", "vendor_dlkm"):
            module_dir = staging / name / "lib/modules"
            for path in module_dir.glob("*.ko"):
                previous = available.get(path.stem)
                if previous and sha256_file(previous) != sha256_file(path):
                    raise PipelineError(f"conflicting staged copies of {path.stem}.ko")
                available[path.stem] = path

        expected = set(plan["modules"])
        extras = set(available) - expected
        if extras:
            raise PipelineError("staging contains modules outside the current plan: "
                                + ", ".join(sorted(extras)))
        missing = expected - set(available)
        non_kernel = [name for name in missing if plan["modules"][name]["root"] != "kernel"]
        if non_kernel:
            raise PipelineError("cannot reuse staging; missing external modules: "
                                + ", ".join(sorted(non_kernel)))
        candidates = [available[name] if name in available
                      else _kernel_module(kernel_out, plan["modules"][name], name)
                      for name in sorted(expected)]
        btf_report = audit_btf(kernel_out / "vmlinux", candidates)
        stale = stale_split_modules(candidates, old_receipt.get("base_btf_sha256"),
                                    btf_report["base_btf_sha256"])
        if stale or btf_report["failures"]:
            raise PipelineError("staged BTF cannot be reused; run incremental build-modules")

        modules_dir = output / "modules"
        stripped_dir = output / "modules-stripped"
        for directory in (modules_dir, stripped_dir):
            if directory.exists():
                shutil.rmtree(directory)
            directory.mkdir(parents=True)
        modinfo = find_tool("modinfo")
        readelf = find_tool("llvm-readelf", str(Path(args.toolchain).resolve()))
        strip = find_tool("llvm-strip", str(Path(args.toolchain).resolve()))
        reused = {}
        for name in sorted(expected):
            source = available.get(name)
            source_kind = "staging"
            if source is None:
                source = _kernel_module(kernel_out, plan["modules"][name], name)
                source_kind = "kernel-out"
            vermagic = module_vermagic(source, modinfo, readelf)
            if not vermagic.startswith(release):
                raise PipelineError(f"{source.name} vermagic differs from {release}: {vermagic}")
            full = modules_dir / f"{name}.ko"
            stripped = stripped_dir / full.name
            shutil.copy2(source, full)
            shutil.copy2(source, stripped)
            run([str(strip), "--strip-debug", str(stripped)])
            reused[name] = {"source": source_kind, "sha256": sha256_file(source)}

        receipt = {
            "schema": 2,
            "kernelrelease": release,
            "module_count": len(expected),
            "vendor_boot_count": len(plan["vendor_boot"]),
            "vendor_dlkm_count": len(plan["vendor_dlkm"]),
            "external_groups": current_external_groups,
            "plan_sha256": sha256_file(output / "plan.json"),
            "build_identity_sha256": sha256_file(output / "build-identity.json"),
            "reused_artifacts": reused,
            "base_btf_sha256": btf_report["base_btf_sha256"],
            "module_sha256": {name + ".ko": item["sha256"] for name, item in reused.items()},
        }
        write_json(old_receipt_path, receipt)
        print(json.dumps({
            "module_count": len(expected),
            "reused_staged": len(available),
            "added_from_kernel": sorted(missing),
            "status": "ready-to-stage",
        }, indent=2))
    return 0


def check_group_command(args: argparse.Namespace) -> int:
    target, manifest, roots, output = load_context(args)
    with output_lock(output):
        states = _source_states(roots)
        toolchain, env, _ = _toolchain_and_env(args, manifest, roots, output)
        _check_identity(output, _build_identity(target, manifest, states, toolchain, roots),
                        allow_reuse=args.reuse_output)
        plan = _plan(args, target, manifest, roots, output, require_complete=True)
        kernel_out, release = prepare_kernel(args, manifest, roots, output, env)
        result = build_modules(
            args, manifest, roots, plan, output, kernel_out, release, env,
            check_group=args.group_id,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def stage_command(args: argparse.Namespace) -> int:
    target, manifest, roots, output = load_context(args)
    with output_lock(output):
        states = _source_states(roots)
        toolchain, _, host_tools = _toolchain_and_env(args, manifest, roots, output)
        _require_packaging_identity(
            output, _build_identity(target, manifest, states, toolchain, roots), target, roots, manifest,
        )
        plan = _plan(args, target, manifest, roots, output, require_complete=True)
        _verify_modules_receipt(output, plan)
        release_file = output / "kernelrelease.txt"
        if not (output / "modules-stripped").is_dir():
            raise PipelineError("modules-stripped is missing; run build-modules first")
        materials = _materials(args)
        stage_identity = _stage_identity(target, manifest, materials)
        _check_stage_identity(output, stage_identity, allow_reuse=args.reuse_output)
        stage_images(
            manifest, plan, output, materials, target.parent / "modules", release_file.read_text().strip(),
            host_tools,
            recovery_modules=stage_identity.get("recovery_modules"),
        )
        _write_staging_receipt(output)
        print(f"staging={output / 'staging'}")
    return 0


def image_command(args: argparse.Namespace) -> int:
    target, manifest, roots, output = load_context(args)
    with output_lock(output):
        states = _source_states(roots)
        toolchain, _, host_tools = _toolchain_and_env(args, manifest, roots, output)
        _require_packaging_identity(
            output, _build_identity(target, manifest, states, toolchain, roots), target, roots, manifest,
        )
        plan = _plan(args, target, manifest, roots, output, require_complete=True)
        _verify_modules_receipt(output, plan)
        staging = output / "staging"
        if not (staging / "vendor_boot").is_dir() or not (staging / "vendor_dlkm").is_dir():
            raise PipelineError("staging directories are missing; run stage first")
        stage_identity_path = output / "stage-inputs.json"
        if not stage_identity_path.is_file():
            raise PipelineError("stage input receipt is missing; run stage first")
        materials = _materials(args)
        current_stage_identity = _stage_identity(target, manifest, materials)
        try:
            stored_stage_identity = json.loads(stage_identity_path.read_text())
        except json.JSONDecodeError as error:
            raise PipelineError(f"invalid stage input receipt: {stage_identity_path}") from error
        if stored_stage_identity != current_stage_identity:
            raise PipelineError("stage inputs changed; run stage with --reuse-output")
        _verify_staging_receipt(output)
        images = build_images(materials, manifest, output, {
            "vendor_boot": staging / "vendor_boot",
            "vendor_dlkm": staging / "vendor_dlkm",
        }, host_tools, args.partition)
        for name, path in images.items():
            extra = _vendor_boot_receipt(output) if name == "vendor_boot" else {}
            _record_images(output, name, path, {**extra, "stage_inputs": current_stage_identity})
        receipt = json.loads((output / "images-receipt.json").read_text())
        print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


def _record_images(output: Path, name: str, path: Path, extra: dict[str, Any]) -> None:
    receipt_path = output / "images-receipt.json"
    receipt = json.loads(receipt_path.read_text()) if receipt_path.is_file() else {}
    from .common import sha256_file

    receipt[name] = {"path": str(path), "sha256": sha256_file(path), **extra}
    write_json(receipt_path, receipt)
    build_receipt_path = output / "build-receipt.json"
    if build_receipt_path.is_file():
        build_receipt = json.loads(build_receipt_path.read_text())
        build_receipt.setdefault("images", {})[name] = receipt[name]
        write_json(build_receipt_path, build_receipt)
    (output / "SHA256SUMS.txt").write_text("".join(
        f"{item['sha256']}  {item['path']}\n" for _, item in sorted(receipt.items())
    ))


def _vendor_boot_receipt(output: Path) -> dict[str, Any]:
    path = output / "vendor_boot-dtb.json"
    if not path.is_file():
        raise PipelineError("vendor_boot DTB reservation receipt is missing")
    try:
        dtb = json.loads(path.read_text())
    except json.JSONDecodeError as error:
        raise PipelineError("invalid vendor_boot DTB reservation receipt") from error
    return {"dtb": dtb}


def _require_kernel_receipt(output: Path) -> tuple[Path, str]:
    if (output / "kernel-out/.forge-config-pending").exists():
        raise PipelineError("kernel config changed; run the kernel stage before packaging")
    receipt_path = output / "kernel-receipt.json"
    if not receipt_path.is_file():
        receipt_path = output / "build-receipt.json"
    if not receipt_path.is_file():
        raise PipelineError("kernel receipt is missing; run the kernel stage first")
    receipt = json.loads(receipt_path.read_text())
    kernel_out = output / "kernel-out"
    image = kernel_out / "arch/arm64/boot/Image"
    release_file = output / "kernelrelease.txt"
    if not image.is_file() or not release_file.is_file():
        raise PipelineError("kernel output is incomplete; run the kernel stage first")
    release = release_file.read_text().strip()
    if release != receipt.get("kernelrelease"):
        raise PipelineError("kernel release differs from its receipt")
    return image, release


def boot_image_command(args: argparse.Namespace) -> int:
    target, manifest, roots, output = load_context(args)
    with output_lock(output):
        states = _source_states(roots)
        toolchain, _, host_tools = _toolchain_and_env(args, manifest, roots, output)
        _require_packaging_identity(
            output, _build_identity(target, manifest, states, toolchain, roots), target, roots, manifest,
            gki_only=True,
        )
        kernel, release = _require_kernel_receipt(output)
        image = build_boot_image(args, manifest, output, host_tools)
        _record_images(output, "boot", image, _boot_receipt(args, manifest, kernel, release))
        print(f"boot={image} sha256={sha256_file(image)}")
    return 0


def system_dlkm_command(args: argparse.Namespace) -> int:
    target, manifest, roots, output = load_context(args)
    with output_lock(output):
        states = _source_states(roots)
        toolchain, _, host_tools = _toolchain_and_env(args, manifest, roots, output)
        _require_packaging_identity(
            output, _build_identity(target, manifest, states, toolchain, roots), target, roots, manifest,
            gki_only=True,
        )
        _, release = _require_kernel_receipt(output)
        materials = _materials(args)
        inputs = _system_dlkm_inputs(target, manifest, materials)
        image = build_system_dlkm_image(
            target, materials, manifest, output, host_tools, Path(args.toolchain) / "llvm-strip"
        )
        _record_images(output, "system_dlkm", image, {
            **inputs, "kernelrelease": release,
        })
        print(f"system_dlkm={image} sha256={sha256_file(image)}")
    return 0


def _boot_receipt(args: argparse.Namespace, manifest: dict[str, Any],
                  kernel: Path, release: str) -> dict[str, Any]:
    return {
        "kernel_sha256": sha256_file(kernel),
        "kernelrelease": release,
        "cmdline": args.boot_cmdline or manifest["images"]["boot"]["cmdline"],
    }


def verify_command(args: argparse.Namespace) -> int:
    target, manifest, roots, output = load_context(args)
    with output_lock(output):
        _, _, host_tools = _toolchain_and_env(args, manifest, roots, output)
        host_tools["llvm-nm"] = Path(args.toolchain).resolve() / "llvm-nm"
        materials = None
        if args.materials:
            materials = _materials(args)
            for partition in ("vendor_boot", "vendor_dlkm", "system_dlkm"):
                check_materials(target, manifest, materials, partition)
        verify_four_images(output, target, manifest, host_tools, materials)
        print("four-image verification passed")
    return 0


def all_command(args: argparse.Namespace) -> int:
    target, manifest, roots, output = load_context(args)
    with output_lock(output):
        states = _source_states(roots)
        toolchain, env, host_tools = _toolchain_and_env(args, manifest, roots, output)
        check_erofs_tool(host_tools["mkfs.erofs"])
        materials = _materials(args)
        stage_identity = _stage_identity(target, manifest, materials)
        system_inputs = _system_dlkm_inputs(target, manifest, materials)
        _check_stage_identity(output, stage_identity, allow_reuse=args.reuse_output)
        _check_identity(output, _build_identity(target, manifest, states, toolchain, roots),
                        allow_reuse=args.reuse_output)
        plan = _plan(args, target, manifest, roots, output, require_complete=True)
        kernel_out, release = prepare_kernel(args, manifest, roots, output, env)
        modules = build_modules(args, manifest, roots, plan, output, kernel_out, release, env,
                                incremental=args.incremental)
        modules["plan_sha256"] = sha256_file(output / "plan.json")
        modules["build_identity_sha256"] = sha256_file(output / "build-identity.json")
        write_json(output / "modules-receipt.json", modules)
        write_json(output / "kernel-receipt.json", {
            "kernelrelease": release,
            "kernel_out": str(kernel_out),
            "module_symvers_sha256": sha256_file(kernel_out / "Module.symvers"),
            "base_btf_sha256": modules["base_btf_sha256"],
        })
        staging = stage_images(
            manifest, plan, output, materials, target.parent / "modules", release, host_tools,
            recovery_modules=stage_identity.get("recovery_modules"),
        )
        staging_receipt = _write_staging_receipt(output)
        images = build_images(materials, manifest, output, staging, host_tools, "all")
        images["boot"] = build_boot_image(args, manifest, output, host_tools)
        images["system_dlkm"] = build_system_dlkm_image(
            target, materials, manifest, output, host_tools, Path(args.toolchain) / "llvm-strip"
        )
        extras = {
            "vendor_boot": {**_vendor_boot_receipt(output), "stage_inputs": stage_identity},
            "vendor_dlkm": {"stage_inputs": stage_identity},
            "boot": _boot_receipt(args, manifest, kernel_out / "arch/arm64/boot/Image", release),
            "system_dlkm": {**system_inputs, "kernelrelease": release},
        }
        for name, path in images.items():
            _record_images(output, name, path, extras[name])
        host_tools["llvm-nm"] = Path(args.toolchain) / "llvm-nm"
        verify_four_images(output, target, manifest, host_tools, materials)
        receipt = {
            "schema": 4,
            "target": manifest["target"]["name"],
            "kernelrelease": release,
            "source_states": states,
            "toolchain": toolchain,
            "target_sha256": sha256_file(target),
            "config_sha256": sha256_file(kernel_config_path(target, manifest, roots)),
            "plan_sha256": sha256_file(output / "plan.json"),
            "stage_inputs": stage_identity,
            "staging": staging_receipt,
            "modules": modules,
            "images": json.loads((output / "images-receipt.json").read_text()),
        }
        write_json(output / "build-receipt.json", receipt)
        print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


def add_common(parser: argparse.ArgumentParser, *, inherited: bool = False) -> None:
    default = argparse.SUPPRESS if inherited else None
    parser.add_argument("--target", default=default or str(HERE / "targets/cliffs/sm7675.toml"))
    parser.add_argument("--kernel-src", default=default or str(DEFAULT_KERNEL))
    parser.add_argument("--msm-src", default=default or str(DEFAULT_MSM))
    parser.add_argument("--vendor-src", default=default or str(DEFAULT_VENDOR))
    parser.add_argument("--compat-src", default=default, help="defaults to oneplus-6.18-compat in the selected MSM tree")
    parser.add_argument("--toolchain", default=default or str(DEFAULT_TOOLCHAIN))
    parser.add_argument("--tools-dir", default=default)
    parser.add_argument(
        "--extra-src", action="append", default=[] if not inherited else argparse.SUPPRESS,
        metavar="NAME=PATH", help="additional source root referenced by the target manifest",
    )
    parser.add_argument("--out", default=default or str(HERE / "out/current"))
    parser.add_argument("--materials", default=default,
                        help="device material directory checked against the target's SHA-256 lock")
    parser.add_argument("--jobs", type=int, default=default)
    parser.add_argument("--module-jobs", type=int, default=default,
                        help="maximum concurrent external module groups")
    parser.add_argument(
        "--reuse-output", action="store_true", default=default,
        help="reuse an existing output directory after input changes; stale receipts remain invalid",
    )
    parser.add_argument("--avbtool", default=default or "avbtool")


def parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="forge.py")
    add_common(parser)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("doctor", "plan", "config", "kernel", "build-modules", "reuse-staged-modules", "check-group",
                 "stage", "image", "boot", "system-dlkm", "recovery", "kernelsu", "verify", "all"):
        child = sub.add_parser(name)
        add_common(child, inherited=True)
    sub.choices["plan"].add_argument("--allow-unresolved", action="store_true")
    sub.choices["plan"].add_argument("--strict-ambiguity", action="store_true")
    sub.choices["image"].add_argument(
        "--partition", choices=("vendor_boot", "vendor_dlkm", "all"), default="all"
    )
    sub.choices["boot"].add_argument("--boot-cmdline", default=None)
    sub.choices["all"].add_argument("--boot-cmdline", default=None)
    sub.choices["all"].add_argument("--incremental", action="store_true",
        help="preserve external Kbuild object directories instead of starting clean")
    sub.choices["recovery"].add_argument("--recovery-base", required=True)
    sub.choices["recovery"].add_argument("--magiskboot")
    sub.choices["kernelsu"].add_argument("--kernelsu-src", required=True)
    sub.choices["kernelsu"].add_argument(
        "--allow-kernel-source-mismatch", action="store_true",
        help="build against existing kernel-out artifacts when only kernel source identity differs",
    )
    sub.choices["kernelsu"].add_argument("--output-subdir")
    sub.choices["kernelsu"].add_argument("--artifact-name")
    sub.choices["kernelsu"].add_argument(
        "--profile", choices=("bakasu", "generic"), default="bakasu",
    )
    sub.choices["kernelsu"].add_argument("--make-variable", action="append", default=[])
    sub.choices["check-group"].add_argument("--group-id", required=True)
    sub.choices["build-modules"].add_argument("--module", action="append", default=[],
        help="rebuild the source group owning this module; repeat for multiple modules")
    sub.choices["build-modules"].add_argument("--incremental", action="store_true",
        help="preserve external Kbuild object directories instead of starting clean")
    return parser


def main(argv: list[str] | None = None) -> int:
    os.umask(0o022)
    args = parser().parse_args(argv)
    _normalize_args(args)
    try:
        from .recovery_image import build_recovery_image
        from .kernelsu import build_kernelsu
        commands = {
            "doctor": doctor_command,
            "plan": plan_command,
            "config": config_command,
            "kernel": kernel_command,
            "build-modules": modules_command,
            "reuse-staged-modules": reuse_staged_modules_command,
            "check-group": check_group_command,
            "stage": stage_command,
            "image": image_command,
            "boot": boot_image_command,
            "system-dlkm": system_dlkm_command,
            "recovery": build_recovery_image,
            "kernelsu": build_kernelsu,
            "verify": verify_command,
            "all": all_command,
        }
        return commands[args.command](args)
    except PipelineError as error:
        print(f"forge: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
