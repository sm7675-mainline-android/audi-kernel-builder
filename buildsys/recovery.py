from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from .catalog import read_module_list
from .common import PipelineError, run, temporary_directory


def recovery_dependencies(source: Path, version: str, workspace: Path, depmod: Path) -> dict[str, list[str]]:
    with temporary_directory(workspace, "recovery-depmod-") as temp:
        modules = temp / "lib/modules" / version
        modules.mkdir(parents=True)
        for path in source.glob("*.ko"):
            (modules / path.name).symlink_to(path.resolve())
        run([str(depmod), "-b", str(temp), version])
        dependencies = {}
        for line in (modules / "modules.dep").read_text().splitlines():
            module, _, names = line.partition(":")
            dependencies[Path(module).stem] = [Path(name).stem for name in names.split()]
        return dependencies


def recovery_inputs(target: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    value = manifest.get("images", {}).get("vendor_boot", {}).get("recovery_modules_list")
    if not value:
        return {}
    path = (target.parent / value).resolve()
    return {"recovery_modules": read_module_list(path)}


def recovery_module_order(
    source: Path, seeds: list[str], modinfo: Path, softdep_sources: list[Path],
    dependencies: dict[str, list[str]] | None = None,
) -> list[str]:
    available = {path.stem.replace("-", "_"): path.stem for path in source.glob("*.ko")}
    pre: dict[str, list[str]] = {}
    post: dict[str, list[str]] = {}

    def add_softdep(module: str, value: str) -> None:
        destination = None
        for token in value.split():
            if token.startswith(("pre:", "post:")):
                destination = pre if token.startswith("pre:") else post
                token = token.split(":", 1)[1]
            if token and destination is not None:
                dependency = available.get(token.replace("-", "_"))
                if dependency:
                    destination.setdefault(module, []).append(dependency)

    for path in softdep_sources:
        if not path.is_file():
            continue
        for raw in path.read_text().splitlines():
            parts = raw.split("#", 1)[0].split(maxsplit=2)
            if len(parts) == 3 and parts[0] == "softdep":
                module = available.get(parts[1].replace("-", "_"))
                if module:
                    add_softdep(module, parts[2])

    ordered: list[str] = []
    complete: set[str] = set()
    visiting: set[str] = set()
    pending = list(seeds)

    def visit(name: str) -> None:
        module = available.get(name.replace("-", "_"))
        if module is None:
            raise PipelineError(f"recovery module is not built: {name}")
        if module in complete:
            return
        if module in visiting:
            raise PipelineError(f"recovery module dependency cycle at {module}")
        visiting.add(module)
        result = subprocess.run([str(modinfo), str(source / f"{module}.ko")],
                                capture_output=True, text=True)
        if result.returncode:
            raise PipelineError(f"cannot read recovery module metadata: {module}: {result.stderr}")
        required: list[str] = []
        for line in result.stdout.splitlines():
            field, separator, value = line.partition(":")
            if separator and field == "depends" and dependencies is None:
                required.extend(name.strip() for name in value.split(",") if name.strip())
            elif separator and field == "softdep":
                add_softdep(module, value)
        if dependencies is not None:
            required = dependencies[module]
        for dependency in [*required, *pre.get(module, [])]:
            visit(dependency)
        visiting.remove(module)
        complete.add(module)
        ordered.append(module)
        pending.extend(post.get(module, []))

    index = 0
    while index < len(pending):
        visit(pending[index])
        index += 1
    return ordered


def verify_recovery_contents(module_dir: Path, staging: Path) -> None:
    from .common import sha256_file

    for name in ("modules.load", "modules.load.recovery"):
        path = module_dir / name
        if not path.is_file() or path.read_bytes() != (staging / name).read_bytes():
            raise PipelineError(f"vendor_boot {name} differs from staging")
    recovery = read_module_list(module_dir / "modules.load.recovery")
    early = read_module_list(module_dir / "modules.load")
    if not set(early) <= set(recovery):
        raise PipelineError("recovery list omits early boot modules")
    present = {path.stem for path in module_dir.glob("*.ko")}
    if present != set(recovery):
        raise PipelineError("vendor_boot module files differ from the recovery list")
    for name in recovery:
        if sha256_file(module_dir / f"{name}.ko") != sha256_file(staging / f"{name}.ko"):
            raise PipelineError(f"vendor_boot module differs from staging: {name}")
    for line in (module_dir / "modules.dep").read_text().splitlines():
        module, separator, dependencies = line.partition(":")
        if not separator or not (module_dir / module).is_file():
            raise PipelineError(f"invalid recovery modules.dep entry: {line}")
        for dependency in dependencies.split():
            if not (module_dir / dependency).is_file():
                raise PipelineError(f"recovery dependency is missing: {dependency}")
