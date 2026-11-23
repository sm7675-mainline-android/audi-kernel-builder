from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from .abi import audit_modules
from .btf import audit_btf
from .common import PipelineError, output_lock, reject_whitespace, run, sha256_file, write_json
from .toolchain import source_state


def build_kernelsu(args: Any) -> int:
    from .pipeline import (
        _build_identity, _require_kernel_receipt,
        _require_packaging_identity, _source_states, _toolchain_and_env, load_context,
    )

    target, manifest, roots, output = load_context(args)
    source = Path(args.kernelsu_src).expanduser().resolve()
    reject_whitespace([source])
    if not (source / "kernel/Kbuild").is_file():
        raise PipelineError("--kernelsu-src must point to a KernelSU repository")
    with output_lock(output):
        states = _source_states(roots)
        toolchain, env, tools = _toolchain_and_env(args, manifest, roots, output)
        _require_packaging_identity(
            output, _build_identity(target, manifest, states, toolchain, roots), target, roots, manifest,
            gki_only=True,
        )
        image, release = _require_kernel_receipt(output)
        kernel_out = output / "kernel-out"
        kernel_receipt = json.loads((output / "kernel-receipt.json").read_text())
        if sha256_file(kernel_out / "Module.symvers") != kernel_receipt["module_symvers_sha256"]:
            raise PipelineError("kernel Module.symvers differs from its build receipt")
        kernel_inputs = {
            name: sha256_file(kernel_out / name)
            for name in (".config", "Module.symvers", "vmlinux", "include/generated/utsrelease.h")
        }
        kernel_inputs["arch/arm64/boot/Image"] = sha256_file(image)
        source_before = source_state(source, [])
        destination = output / "kernelsu"
        objects = destination / "build"
        objects.mkdir(parents=True, exist_ok=True)
        (destination / "receipt.json").unlink(missing_ok=True)
        variables = {
            "CONFIG_KSU": "m",
            "CONFIG_KSU_TRACEPOINT_HOOK": "y",
            "CONFIG_KSU_MULTI_MANAGER_SUPPORT": "y",
            "CONFIG_KSU_DEBUG": "n",
        }
        env["KBUILD_MODPOST_WARN"] = "1"
        command = [
            "make", "-C", str(kernel_out), f"M={source / 'kernel'}", f"MO={objects}",
            f"-j{args.jobs or manifest['build'].get('jobs', 8)}",
            *(f"{name}={value}" for name, value in variables.items()), "modules",
        ]
        run(command, env=env, log=output / "logs/kernelsu-build.log")
        module = destination / "android17-6.18_kernelsu.ko"
        shutil.copy2(objects / "kernelsu.ko", module)
        llvm = Path(args.toolchain)
        run([str(llvm / "llvm-strip"), "--strip-debug", str(module)])
        report = audit_modules(kernel_out / "vmlinux", [module], release, {
            **tools, "llvm-nm": llvm / "llvm-nm",
        })
        undefined = run([str(llvm / "llvm-nm"), "--undefined-only", "--format=posix", str(module)],
                        capture=True).stdout
        symbols = run([str(llvm / "llvm-nm"), "--defined-only", "--format=posix",
                       str(kernel_out / "vmlinux")], capture=True).stdout
        available = {line.split()[0] for line in symbols.splitlines() if line.split()}
        required = {line.split()[0] for line in undefined.splitlines() if line.split()}
        missing = sorted(required - available)
        report["runtime_symbols"] = len(required)
        report["missing_runtime_symbols"] = missing
        report["failures"].extend(f"KernelSU runtime symbol missing: {name}" for name in missing)
        report["btf"] = audit_btf(kernel_out / "vmlinux", [module])
        report["failures"].extend(report["btf"]["failures"])
        for name, digest in kernel_inputs.items():
            if sha256_file(kernel_out / name) != digest:
                report["failures"].append(f"KernelSU build changed kernel input: {name}")
        if source_state(source, []) != source_before:
            report["failures"].append("KernelSU source changed during the build")
        write_json(destination / "validation.json", report)
        if report["failures"]:
            raise PipelineError("KernelSU validation failed: " + "; ".join(report["failures"]))
        write_json(destination / "receipt.json", {
            "source": str(source), "source_state": source_before,
            "kernelrelease": release, "kernel_inputs": kernel_inputs,
            "toolchain": toolchain, "make_variables": variables,
            "module": str(module), "sha256": sha256_file(module),
            "validation_sha256": sha256_file(destination / "validation.json"),
        })
        (destination / "SHA256SUMS.txt").write_text(f"{sha256_file(module)}  {module.name}\n")
        print(f"kernelsu={module} sha256={sha256_file(module)}")
    return 0
