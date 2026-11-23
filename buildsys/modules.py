from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .common import PipelineError, ensure_output_path, find_tool, run, sha256_file, write_json
from .abi import imported_crcs
from .btf import audit_btf, stale_split_modules


def _group_id(group: dict[str, Any]) -> str:
    identity = f"{group['root']}:{group['path']}:{group['kind']}:{','.join(group['modules'])}"
    suffix = hashlib.sha256(identity.encode()).hexdigest()[:8]
    path = group["path"].replace("/", "_") or "root"
    return f"{group['root']}_{path[:48]}_{suffix}"


def _reset(path: Path, output: Path) -> None:
    path = ensure_output_path(output, path)
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)


def _local_file_times(root: Path) -> dict[str, tuple[str, int]]:
    result = {}
    for directory, _, names in os.walk(root):
        for name in names:
            path = Path(directory) / name
            if not path.is_symlink() and path.is_file():
                result[str(path.relative_to(root))] = (sha256_file(path), path.stat().st_mtime_ns)
    return result


def _prune_module_cache(output: Path, names: set[str]) -> None:
    for directory in ("modules", "modules-stripped"):
        root = ensure_output_path(output, output / directory)
        for module in root.glob("*.ko"):
            if module.stem not in names:
                module.unlink()


def _stale_module_cache(
    output: Path, names: set[str], receipt: dict[str, Any], release: str,
    modinfo: Path, readelf: Path,
) -> set[str]:
    stale = set()
    hashes = receipt.get("module_sha256", {})
    for name in sorted(names):
        path = output / "modules" / f"{name}.ko"
        if not path.is_file() or sha256_file(path) != hashes.get(path.name):
            stale.add(name)
            continue
        try:
            version = module_vermagic(path, modinfo, readelf).split()[0]
        except (PipelineError, IndexError):
            stale.add(name)
            continue
        if version != release:
            stale.add(name)
    return stale


def _restore_local_file_times(root: Path, previous: dict[str, tuple[str, int]]) -> None:
    for relative, (digest, timestamp) in previous.items():
        path = root / relative
        if path.is_file() and not path.is_symlink() and sha256_file(path) == digest:
            os.utime(path, ns=(path.stat().st_atime_ns, timestamp))


def _source_directory(group: dict[str, Any], roots: dict[str, Path]) -> Path:
    base = roots[group["root"]] / ("vendor" if group["root"] == "vendor" else "")
    source = (base / group["path"]).resolve()
    try:
        source.relative_to(base.resolve())
    except ValueError as error:
        raise PipelineError(f"module source escapes root: {source}") from error
    if not source.is_dir():
        raise PipelineError(f"module source directory is missing: {source}")
    return source


def _write_source_patch_overlay(
    replacements: list[tuple[Path, Path]], overlay_path: Path,
) -> Path | None:
    if not replacements:
        return None
    overlay_path.parent.mkdir(parents=True, exist_ok=True)
    overlay = {
        "version": 0,
        "case-sensitive": True,
        "roots": [
            {
                "type": "file",
                "name": str(original.resolve()),
                "external-contents": str(patched.resolve()),
            }
            for original, patched in replacements
        ],
    }
    overlay_path.write_text(json.dumps(overlay, indent=2) + chr(10))
    return overlay_path


def _source_patch_overlay_flags(overlay: Path) -> list[str]:
    return ["-ivfsoverlay", str(overlay)]


def _apply_source_patches(
    source_views: dict[str, Path],
    roots: dict[str, Path],
    manifest: dict[str, Any],
    overlay_path: Path,
) -> Path | None:
    build_system = Path(__file__).resolve().parents[1]
    replacements: list[tuple[Path, Path]] = []
    for item in manifest.get("build", {}).get("source_patches", []):
        if not isinstance(item, dict) or set(item) != {"root", "file", "sha256"}:
            raise PipelineError("source patches require root, file, and sha256")
        root = item["root"]
        if root not in source_views:
            if root not in roots:
                raise PipelineError(f"source patch names unknown root: {root}")
            continue
        patch_path = (build_system / item["file"]).resolve()
        try:
            patch_path.relative_to(build_system)
        except ValueError as error:
            raise PipelineError(f"source patch escapes build system: {patch_path}") from error
        if not patch_path.is_file():
            raise PipelineError(f"source patch is missing: {patch_path}")
        if hashlib.sha256(patch_path.read_bytes()).hexdigest() != item["sha256"]:
            raise PipelineError(f"source patch digest mismatch: {patch_path}")
        patch_targets = []
        for line in patch_path.read_text().splitlines():
            if line.startswith("+++ b/"):
                relative = Path(line[6:])
                if relative.is_absolute() or ".." in relative.parts:
                    raise PipelineError(f"source patch target escapes view: {relative}")
                patch_targets.append((roots[root] / relative, source_views[root] / relative))
        for original, target in patch_targets:
            if target.is_symlink():
                resolved = target.resolve(strict=True)
                if not resolved.is_file():
                    raise PipelineError(f"source patch target is not a file: {target}")
                local_copy = target.with_name(f".{target.name}.patch-copy")
                shutil.copy2(resolved, local_copy)
                target.unlink()
                local_copy.replace(target)
        result = subprocess.run(
            ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(patch_path)],
            cwd=source_views[root], text=True, capture_output=True,
        )
        if result.returncode:
            raise PipelineError(
                f"source patch failed ({root}:{item['file']}): "
                f"{(result.stdout + result.stderr).strip()}"
            )
        for original, target in patch_targets:
            if not original.is_file() or not target.is_file():
                raise PipelineError(f"source patch overlay target is missing: {target}")
            replacements.append((original, target))

    for item in manifest.get("build", {}).get("source_replacements", []):
        required = {"root", "path", "search", "replace", "count"}
        if not isinstance(item, dict) or set(item) != required:
            raise PipelineError(
                "source replacements require root, path, search, replace, and count"
            )
        root = item["root"]
        relative = Path(item["path"])
        if root not in source_views or relative.is_absolute() or ".." in relative.parts:
            raise PipelineError(f"invalid source replacement target: {item!r}")
        if not item["search"] or not isinstance(item["count"], int) or item["count"] < 1:
            raise PipelineError(f"invalid source replacement match count: {item!r}")
        original = roots[root] / relative
        target = source_views[root] / relative
        if not original.is_file() or not target.is_file():
            raise PipelineError(f"source replacement target is missing: {target}")
        if target.is_symlink():
            resolved = target.resolve(strict=True)
            if not resolved.is_file():
                raise PipelineError(f"source replacement target is not a file: {target}")
            local_copy = target.with_name(f".{target.name}.replacement-copy")
            shutil.copy2(resolved, local_copy)
            target.unlink()
            local_copy.replace(target)
        text = target.read_text(errors="surrogateescape")
        found = text.count(item["search"])
        if found != item["count"]:
            raise PipelineError(
                f"source replacement expected {item['count']} matches, found {found}: "
                f"{root}:{relative}"
            )
        target.write_text(
            text.replace(item["search"], item["replace"]),
            errors="surrogateescape",
        )
        pair = (original, target)
        if pair not in replacements:
            replacements.append(pair)
    return _write_source_patch_overlay(replacements, overlay_path)


def _declared_module_configs(source: Path) -> set[str]:
    configs: set[str] = set()
    assignment = re.compile(r"^\s*obj-\$\((CONFIG_[A-Za-z0-9_]+)\)\s*(?:\+|:)?=", re.M)
    for name in ("Kbuild", "Makefile"):
        path = source / name
        if path.is_file():
            configs.update(assignment.findall(path.read_text(errors="ignore")))
    return configs


def _enabled_kernel_configs(kernel_out: Path) -> set[str]:
    config = kernel_out / ".config"
    if not config.is_file():
        return set()
    enabled: set[str] = set()
    for line in config.read_text(errors="ignore").splitlines():
        match = re.match(r"^(CONFIG_[A-Za-z0-9_]+)=(?:y|m)$", line)
        if match:
            enabled.add(match.group(1))
    return enabled


def _composite_dependency_configs(
    source: Path, output_names: set[str],
) -> set[str]:
    configs: set[str] = set()
    assignment = re.compile(
        r"^\s*([A-Za-z0-9_.+-]+)-\$\((CONFIG_[A-Za-z0-9_]+)\)\s*(?:\+|:)?=",
        re.M,
    )
    for name in ("Kbuild", "Makefile"):
        path = source / name
        if not path.is_file():
            continue
        for module, config in assignment.findall(path.read_text(errors="ignore")):
            if module in output_names:
                configs.add(config)
    return configs


def _source_view(
    root: Path,
    destination: Path,
    output: Path,
    *,
    active_paths: list[str] | None = None,
    source_link_maps: list[dict[str, str]] | None = None,
    generated_links: list[dict[str, str]] | None = None,
    link_roots: dict[str, Path] | None = None,
) -> Path:
    root = root.resolve()
    destination = ensure_output_path(output, destination)
    destination.mkdir(parents=True)
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others",
         "--exclude-standard"],
        check=False, capture_output=True,
    )
    if result.returncode:
        entries: list[str] = []
        for current, directories, files in os.walk(root, followlinks=False):
            current_path = Path(current)
            kept = []
            for name in directories:
                path = current_path / name
                if name in {".git", ".repo", ".tmp_versions", "__pycache__"}:
                    continue
                if path.is_symlink():
                    entries.append(path.relative_to(root).as_posix())
                else:
                    kept.append(name)
            directories[:] = kept
            entries.extend((current_path / name).relative_to(root).as_posix()
                           for name in files)
    else:
        entries = [os.fsdecode(item) for item in result.stdout.split(b"\0") if item]

    active = [Path(item) for item in active_paths or []]
    source_link_maps = source_link_maps or []
    link_roots = link_roots or {}
    for relative in sorted(set(entries)):
        path = Path(relative)
        if any(part in {".git", ".repo", ".tmp_versions", "__pycache__"}
               for part in path.parts):
            continue
        if path.name in {"modules.order", "Module.symvers"}:
            continue
        source = root / path
        if not source.exists() and not source.is_symlink():
            continue
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            link = os.readlink(source)
            resolved = (source.parent / link).resolve()
            try:
                resolved.relative_to(root)
            except ValueError as error:
                if active_paths is not None and not any(
                    path == item or item in path.parents for item in active
                ):
                    continue
                matches: list[Path] = []
                for mapping in source_link_maps:
                    mapped_root = mapping["root"]
                    marker = mapping["marker"]
                    marker_positions = [
                        index for index, part in enumerate(resolved.parts) if part == marker
                    ]
                    if mapped_root not in link_roots or not marker_positions:
                        continue
                    suffix = Path(*resolved.parts[marker_positions[-1] + 1:])
                    mapped_base = link_roots[mapped_root].resolve()
                    candidate = Path(os.path.abspath(
                        mapped_base / mapping.get("prefix", "") / suffix
                    ))
                    try:
                        candidate.relative_to(mapped_base)
                    except ValueError:
                        continue
                    if candidate.exists():
                        matches.append(candidate)
                if len(matches) != 1:
                    raise PipelineError(
                        f"active source symlink has no unique declared mapping: "
                        f"{source} -> {link}"
                    ) from error
                mapped = matches[0]
                link = os.path.relpath(mapped, target.parent)
                target.symlink_to(link, target_is_directory=mapped.is_dir())
            else:
                if os.path.isabs(link):
                    link = os.path.relpath(destination / resolved.relative_to(root), target.parent)
                target.symlink_to(link, target_is_directory=source.is_dir())
        elif source.is_file():
            if source.name in {"Makefile", "Kbuild"}:
                text = source.read_text(errors="ignore")
                legacy_include = "$(srctree)/$(src)/Makefile.json-build"
                if legacy_include in text:
                    target.write_text(text.replace(legacy_include, "$(src)/Makefile.json-build"))
                    continue
            target.symlink_to(source.resolve())
    for specification in generated_links or []:
        relative = Path(specification["path"])
        target = specification["target"]
        if relative.is_absolute() or ".." in relative.parts or not target:
            raise PipelineError(f"invalid generated source link: {specification!r}")
        link_path = destination / relative
        resolved_link = ensure_output_path(output, link_path)
        if resolved_link.exists() or resolved_link.is_symlink():
            raise PipelineError(f"generated source link collides with input: {relative}")
        if Path(target).is_absolute():
            raise PipelineError(f"generated source link target must be relative: {target}")
        resolved_target = (link_path.parent / target).resolve()
        try:
            resolved_target.relative_to(destination.resolve())
        except ValueError as error:
            raise PipelineError(f"generated source link escapes source view: {relative}") from error
        if not resolved_target.exists():
            raise PipelineError(f"generated source link target is missing: {relative} -> {target}")
        link_path.parent.mkdir(parents=True, exist_ok=True)
        link_path.symlink_to(target, target_is_directory=resolved_target.is_dir())
    return destination


def _prepare_bazel_source(
    group: dict[str, Any],
    source: Path,
    generated_root: Path,
    output: Path,
    allowed_root: Path | None = None,
    allowed_root_alias: Path | None = None,
) -> Path:
    if len(group["modules"]) != 1:
        raise PipelineError("generated DDK groups must contain exactly one module")
    module = group["modules"][0]
    spec = group["specs"][module]
    allowed = [(allowed_root or source).resolve()]
    if allowed_root_alias is not None:
        allowed.append(allowed_root_alias.resolve())
    directory = ensure_output_path(output, generated_root)
    directory.mkdir(parents=True)
    object_files: list[str] = []
    include_dirs = {source.resolve()}
    for relative in spec["sources"]:
        path = (source / relative).resolve()
        if not any(path.is_relative_to(root) for root in allowed):
            raise PipelineError(f"generated module source escapes its root: {relative}")
        if not path.is_file():
            raise PipelineError(f"generated module source is missing: {path}")
        link = directory / relative
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(path)
        include_dirs.add(path.parent)
        if Path(relative).suffix in {".c", ".S", ".s"}:
            object_files.append(Path(relative).with_suffix(".o").as_posix())

    if not object_files:
        raise PipelineError(f"generated module {module} has no C or assembly sources")

    output_name = group.get("outputs", {}).get(module, module)
    lines = [f"obj-m += {output_name}.o"]
    if object_files != [f"{output_name}.o"]:
        lines.append(f"{output_name}-y := \\")
        lines.extend(f"\t{object_file} \\" for object_file in object_files)
        lines[-1] = lines[-1].removesuffix(" \\")
    explicit_include_dirs = set()
    for include in spec["includes"]:
        include_path = (source / include).resolve()
        if not any(include_path.is_relative_to(root) for root in allowed):
            raise PipelineError(f"generated module include escapes its root: {include}")
        if not include_path.is_dir():
            raise PipelineError(f"generated module include directory is missing: {include_path}")
        explicit_include_dirs.add(include_path)
    for include_path in sorted(include_dirs | explicit_include_dirs):
        lines.append(f"ccflags-y += -I{include_path}")
    for define in spec["defines"]:
        if not define or any(character.isspace() for character in define):
            raise PipelineError(f"invalid generated module define: {define!r}")
        lines.append(f"ccflags-y += -D{define}")
    for undefine in spec.get("undefines", []):
        if not re.fullmatch(r"CONFIG_[A-Za-z0-9_]+", undefine):
            raise PipelineError(f"invalid generated module undefine: {undefine!r}")
        lines.append(f"ccflags-y += -U{undefine}")
    (directory / "Kbuild").write_text("\n".join(lines) + "\n")
    return directory


def _prepare_generated_vendor_files(source_views: dict[str, Path]) -> None:
    """Generate vendor files that the original Bazel prebuild creates."""
    vendor_view = source_views.get("vendor")
    if vendor_view is None:
        return
    charger = vendor_view / "vendor/oplus/kernel/charger/v2"
    script = charger / "scripts/ic_cfg_parse.py"
    config = charger / "config/oplus_chg_ic.json"
    if not script.is_file() or not config.is_file():
        return
    outputs = {
        "-hd": charger / "oplus_chg_ic_cfg.h",
        "-s": charger / "oplus_chg_ic_cfg_str.h",
        "-df": charger / "oplus_chg_ic_auto_debug.h",
        "-m": charger / "oplus_chg_ic_cfg.json",
    }
    command = ["python3", str(script)]
    for option, path in outputs.items():
        command.extend((option, str(path)))
    command.append(str(config))
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode:
        raise PipelineError(
            "Oplus charger configuration generation failed: "
            + (result.stdout + result.stderr).strip()
        )


def _generate_declared_source_files(
    source_views: dict[str, Path], manifest: dict[str, Any], output: Path,
) -> None:
    for item in manifest.get("build", {}).get("generated_files", []):
        if not isinstance(item, dict) or set(item) != {"root", "path", "content"}:
            raise PipelineError("generated files require root, path, and content")
        root = item["root"]
        relative = Path(item["path"])
        if root not in source_views or relative.is_absolute() or ".." in relative.parts:
            raise PipelineError(f"invalid generated source file: {item!r}")
        if not isinstance(item["content"], str):
            raise PipelineError(f"generated source file content is not text: {item!r}")
        target = ensure_output_path(output, source_views[root] / relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink() or target.exists():
            target.unlink()
        target.write_text(item["content"])


def _apply_generated_compat_headers(generated_root: Path, group: dict[str, Any]) -> None:
    for name, generated in group.get("generated_headers", {}).items():
        if not re.fullmatch(r"[A-Za-z0-9_./+-]+", name):
            raise PipelineError(f"invalid generated header path: {name!r}")
        source = generated_root / generated
        if not source.is_file():
            raise PipelineError(f"generated compatibility header is missing: {source}")
        destination = Path(group["path"]) / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def _kernel_module(kernel_out: Path, group: dict[str, Any], module: str) -> Path:
    output_name = group.get("outputs", {}).get(module, module)
    expected = kernel_out / group["path"] / f"{output_name}.ko"
    if expected.is_file():
        return expected
    matches = list(kernel_out.rglob(f"{output_name}.ko"))
    if len(matches) != 1:
        raise PipelineError(f"expected one kernel-built {module}.ko, found {matches}")
    return matches[0]


def _external_command(
    roots: dict[str, Path],
    kernel_out: Path,
    source: Path,
    module_out: Path,
    group: dict[str, Any],
    env: dict[str, str],
    jobs: int,
    extra_symvers: list[Path],
    warning_only: bool,
) -> tuple[list[str], dict[str, str]]:
    group_env = env.copy()
    group_env.pop("KBUILD_MODPOST_WARN", None)
    if warning_only:
        group_env["KBUILD_MODPOST_WARN"] = "1"
    if extra_symvers:
        group_env["KBUILD_EXTRA_SYMBOLS"] = " ".join(str(path) for path in extra_symvers)
    else:
        group_env.pop("KBUILD_EXTRA_SYMBOLS", None)
    group_env["KCFLAGS"] = env.get("MODULE_KCFLAGS", env.get("KCFLAGS", ""))
    command = [
        "make", "-C", str(roots["kernel"]), f"O={kernel_out}",
        f"M={source}", f"MO={module_out}", f"ARCH={env['ARCH']}", "LLVM=1",
        f"-j{jobs}",
    ]
    requested_configs = set(group["configs"])
    declared_configs = _declared_module_configs(source) - requested_configs
    declared_configs.discard("CONFIG_MODULES")
    output_names = {
        _output_name(group, module) for module in group.get("modules", [])
    }
    if not output_names:
        output_names = {
            config.removeprefix("CONFIG_").lower()
            for config in requested_configs
        }
    composite_configs = _composite_dependency_configs(source, output_names)
    enabled_configs = _enabled_kernel_configs(kernel_out)
    command.extend(
        f"{config}="
        for config in sorted(
            declared_configs - enabled_configs.intersection(composite_configs)
        )
    )
    command.extend(f"{config}=m" for config in group["configs"])
    substitutions = {
        "source": str(source),
        **{f"root:{name}": str(path / "vendor" if name == "vendor" else path)
           for name, path in roots.items()},
    }

    def render(value: str) -> str:
        def replace(match: re.Match[str]) -> str:
            key = match.group(1)
            if key not in substitutions:
                raise PipelineError(f"unknown make variable placeholder: {{{key}}}")
            return substitutions[key]

        return re.sub(r"\{([^{}]+)\}", replace, value)

    for name, value in sorted(group.get("make_vars", {}).items()):
        command.append(f"{name}={render(value)}")
    extra_kcflags = [f"-D{config}_MODULE" for config in group.get("configs", [])]
    extra_kcflags.extend(render(value) for value in group.get("kcflags", []))
    if extra_kcflags:
        group_env["KCFLAGS"] = " ".join(
            value for value in [group_env.get("KCFLAGS", ""), *extra_kcflags] if value
        )
    command.append("modules")
    return command, group_env


def _output_name(group: dict[str, Any], module: str) -> str:
    return group.get("outputs", {}).get(module, module)


def _selected_symvers(source: Path, group: dict[str, Any], destination: Path) -> Path:
    selected = {_output_name(group, name).replace("-", "_") for name in group["modules"]}
    lines = []
    for line in source.read_text().splitlines():
        fields = line.split()
        if len(fields) >= 4 and Path(fields[2]).name.replace("-", "_") in selected:
            lines.append(line)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("".join(line + "\n" for line in lines))
    return destination


def _affected_consumers(
    symvers: list[Path], modules: dict[str, Path], modprobe: Path,
) -> set[str]:
    exports = {}
    for path in symvers:
        for line in path.read_text().splitlines():
            fields = line.split()
            if len(fields) >= 4:
                exports.setdefault(fields[1], set()).add(int(fields[0], 16))
    affected = set()
    for name, path in modules.items():
        if path.is_file() and any(
            symbol in exports and exports[symbol] != {crc}
            for symbol, crc in imported_crcs(path, modprobe).items()
        ):
            affected.add(name)
    return affected


def module_vermagic(module: Path, modinfo: Path, readelf: Path) -> str:
    try:
        result = run([str(modinfo), "-F", "vermagic", str(module)], capture=True)
        value = result.stdout.strip()
        if value:
            return value
    except PipelineError:
        pass
    result = run([str(readelf), "-p", ".modinfo", str(module)], capture=True)
    for line in result.stdout.splitlines():
        match = re.search(r"vermagic=(.*)$", line)
        if match:
            return match.group(1).strip()
    raise PipelineError(f"module has no vermagic metadata: {module}")


def _kernel_external_symvers(
    kernel_symvers: Path,
    external_symvers: list[Path],
    destination: Path,
) -> Path:
    kernel_symbols: set[str] = set()
    for line in kernel_symvers.read_text().splitlines():
        fields = line.split()
        if len(fields) >= 2:
            kernel_symbols.add(fields[1])

    candidates: dict[str, tuple[str, str]] = {}
    ambiguous: set[str] = set()
    for path in sorted(external_symvers):
        for line in path.read_text().splitlines():
            fields = line.split()
            if len(fields) < 4:
                continue
            crc, symbol = fields[:2]
            if symbol in kernel_symbols:
                continue
            previous = candidates.get(symbol)
            if previous is None:
                candidates[symbol] = (crc, line)
            elif previous[0] != crc:
                ambiguous.add(symbol)

    lines = [
        record
        for symbol, (_, record) in sorted(candidates.items())
        if symbol not in ambiguous
    ]
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("".join(f"{line}\n" for line in lines))
    return destination


def _finalize_kernel_modules(
    kernel_root: Path,
    kernel_out: Path,
    env: dict[str, str],
    jobs: int,
    extra_symvers: list[Path],
    log: Path,
) -> None:
    kernel_env = env.copy()
    if extra_symvers:
        filtered_symvers = _kernel_external_symvers(
            kernel_out / "Module.symvers",
            extra_symvers,
            kernel_out.parent / "kernel-extra.symvers",
        )
        kernel_env["KBUILD_EXTRA_SYMBOLS"] = str(filtered_symvers)
    else:
        kernel_env.pop("KBUILD_EXTRA_SYMBOLS", None)
    kernel_env.pop("KBUILD_MODPOST_WARN", None)
    command = [
        "make", "-C", str(kernel_root), f"O={kernel_out}",
        f"ARCH={env['ARCH']}", "LLVM=1", f"-j{jobs}", "modules",
    ]
    run(command, env=kernel_env, log=log)


def build_modules(
    args: Any,
    manifest: dict[str, Any],
    roots: dict[str, Path],
    plan: dict[str, Any],
    output: Path,
    kernel_out: Path,
    kernelrelease: str,
    env: dict[str, str],
    *,
    check_group: str | None = None,
    selected_modules: set[str] | None = None,
    incremental: bool = False,
) -> dict[str, Any]:
    if plan["unresolved"]:
        raise PipelineError("unresolved modules: " + ", ".join(plan["unresolved"]))
    if plan["ambiguous"]:
        raise PipelineError(
            "module source conflicts need [resolve.overrides]: "
            + ", ".join(sorted(plan["ambiguous"]))
        )
    if check_group is not None:
        matches = [group for group in plan["groups"] if _group_id(group) == check_group]
        if len(matches) != 1 or matches[0]["root"] == "kernel":
            raise PipelineError(f"unknown external module group: {check_group}")
    build_root = output / "kbuild"
    source_times = {}
    previous_receipt = {}
    receipt_path = output / "modules-receipt.json"
    if incremental or selected_modules is not None:
        if receipt_path.is_file():
            previous_receipt = json.loads(receipt_path.read_text())
    if selected_modules is not None:
        unknown = selected_modules - set(plan["modules"])
        if unknown:
            raise PipelineError("unknown modules: " + ", ".join(sorted(unknown)))
        incremental = True
        if not (output / "modules-receipt.json").is_file():
            raise PipelineError("targeted rebuild requires an existing module receipt")
    btf_refresh = set()
    if incremental:
        stale = _stale_module_cache(
            output, set(plan["modules"]), previous_receipt, kernelrelease,
            find_tool("modinfo", env.get("PATH")),
            find_tool("llvm-readelf", str(Path(args.toolchain).expanduser().resolve())),
        )
        if selected_modules is not None:
            selected_modules.update(stale)
        if stale:
            print("Module cache rebuild: " + ", ".join(sorted(stale)), flush=True)
        _prune_module_cache(output, set(plan["modules"]))
        cached_modules = sorted((output / "modules").glob("*.ko"))
        btf_report = audit_btf(kernel_out / "vmlinux", cached_modules)
        write_json(output / "logs/cached-btf-audit.json", btf_report)
        btf_refresh = stale_split_modules(
            cached_modules, previous_receipt.get("base_btf_sha256"), btf_report["base_btf_sha256"],
        ) | {Path(name).stem for name in btf_report["invalid_modules"]}
        if selected_modules is not None:
            selected_modules.update(btf_refresh)
        if btf_refresh:
            print("BTF cache refresh: " + ", ".join(sorted(btf_refresh)), flush=True)
    if not incremental:
        _reset(build_root, output)
    else:
        build_root.mkdir(parents=True, exist_ok=True)
        for name in ("source-view", "generated"):
            path = build_root / name
            if path.exists():
                source_times[name] = _local_file_times(path)
                shutil.rmtree(path)
    index_root = build_root / "index"
    final_root = build_root / "final"
    index_root.mkdir(exist_ok=True)
    final_root.mkdir(exist_ok=True)
    modules_dir = output / "modules"
    stripped_dir = output / "modules-stripped"
    if check_group is None and not incremental:
        _reset(modules_dir, output)
        _reset(stripped_dir, output)
    else:
        modules_dir.mkdir(parents=True, exist_ok=True)
        stripped_dir.mkdir(parents=True, exist_ok=True)
    external: list[dict[str, Any]] = []
    source_views: dict[str, Path] = {}
    build_roots = roots.copy()
    jobs = int(args.jobs or manifest.get("build", {}).get("jobs", 8))
    parallelism = int(
        getattr(args, "module_jobs", None)
        or manifest.get("build", {}).get("module_parallelism", 1)
    )
    if jobs < 1 or parallelism < 1:
        raise PipelineError("kernel jobs and module parallelism must be positive integers")
    parallelism = min(jobs, parallelism)
    group_jobs = max(1, jobs // parallelism)
    groups_by_root: dict[str, list[dict[str, Any]]] = {}
    # The kernel and compat roots are complete, immutable build inputs. They
    # must stay real paths: making a filtered source view of the kernel drops
    # top-level generated/configuration context and can make external Kbuild
    # report CONFIG_MODULES as disabled. Only vendor/MSM trees need views for
    # link remapping and source isolation.
    direct_roots = {"kernel", "compat"}

    for group in plan["groups"]:
        if group["root"] != "kernel":
            groups_by_root.setdefault(group["root"], []).append(group)
    source_link_maps = manifest.get("build", {}).get("source_link_maps", {})
    generated_source_links = manifest.get("build", {}).get("source_links", {})

    def active_paths(root_name: str) -> list[str]:
        paths = [group["path"] for group in groups_by_root[root_name]]
        if root_name == "vendor":
            return [str(Path("vendor") / path) for path in paths]
        return paths

    for group in plan["groups"]:
        if group["root"] != "kernel":
            for value in [*group.get("make_vars", {}).values(), *group.get("kcflags", [])]:
                for referenced_root in re.findall(r"\{root:([^}]+)\}", value):
                    groups_by_root.setdefault(referenced_root, [])

    required_link_roots = {
        mapping["root"]
        for root_name in groups_by_root
        for mapping in source_link_maps.get(root_name, [])
    }
    pending = set(required_link_roots)
    while pending:
        ready = sorted(
            root_name for root_name in pending
            if all(mapping["root"] in source_views
                   for mapping in source_link_maps.get(root_name, []))
        )
        if not ready:
            raise PipelineError("source link mappings contain a cycle or unknown root")
        for root_name in ready:
            if root_name not in roots:
                raise PipelineError(f"source link mapping names unknown root: {root_name}")
            source_views[root_name] = _source_view(
                roots[root_name], build_root / "source-view" / root_name, output,
                active_paths=active_paths(root_name),
                source_link_maps=source_link_maps.get(root_name, []),
                generated_links=generated_source_links.get(root_name, []),
                link_roots=source_views,
            )
            build_roots[root_name] = source_views[root_name]
            pending.remove(root_name)

    patch_roots = {
        item["root"] for item in manifest.get("build", {}).get("source_patches", [])
        if isinstance(item, dict) and item.get("root") in groups_by_root
    }
    patch_roots.update(
        item["root"] for item in manifest.get("build", {}).get("source_replacements", [])
        if isinstance(item, dict) and item.get("root") in groups_by_root
    )
    for root_name in sorted(patch_roots):
        if root_name in source_views:
            continue
        source_views[root_name] = _source_view(
            roots[root_name], build_root / "source-view" / root_name, output,
            active_paths=active_paths(root_name),
            source_link_maps=source_link_maps.get(root_name, []),
            generated_links=generated_source_links.get(root_name, []),
            link_roots=source_views,
        )
        build_roots[root_name] = source_views[root_name]

    source_patch_overlay = _apply_source_patches(
        source_views, roots, manifest, build_root / "source-patches-vfs.json",
    )
    _generate_declared_source_files(source_views, manifest, output)
    _prepare_generated_vendor_files(source_views)
    if source_patch_overlay:
        env = env.copy()
        env["MODULE_KCFLAGS"] = " ".join(
            value for value in (
                env.get("MODULE_KCFLAGS", env.get("KCFLAGS", "")),
                *_source_patch_overlay_flags(source_patch_overlay),
            ) if value
        )

    compile_groups = plan["groups"]
    if check_group is not None:
        compile_groups = [group for group in compile_groups if _group_id(group) == check_group]

    for group in compile_groups:
        if group["root"] == "kernel":
            continue
        identifier = _group_id(group)
        source = _source_directory(group, roots)
        if group["kind"] == "bazel":
            original_root = roots[group["root"]] / (
                "vendor" if group["root"] == "vendor" else ""
            )
            allowed_root = original_root
            if group["root"] in source_views:
                view_prefix = "vendor" if group["root"] == "vendor" else ""
                allowed_root = source_views[group["root"]] / view_prefix
                source = allowed_root / group["path"]
            source = _prepare_bazel_source(
                group, source, build_root / "generated" / identifier, output,
                allowed_root=allowed_root, allowed_root_alias=original_root,
            )
        else:
            root_name = group["root"]
            if root_name not in source_views:
                source_views[root_name] = _source_view(
                    roots[root_name], build_root / "source-view" / root_name, output,
                    active_paths=active_paths(root_name),
                    source_link_maps=source_link_maps.get(root_name, []),
                    generated_links=generated_source_links.get(root_name, []),
                    link_roots=source_views,
                )
                build_roots[root_name] = source_views[root_name]
            source = source_views[root_name] / source.relative_to(roots[root_name])
        for value in [*group.get("make_vars", {}).values(), *group.get("kcflags", [])]:
            for referenced_root in re.findall(r"\{root:([^}]+)\}", value):
                if referenced_root not in roots:
                    raise PipelineError(f"unknown source root in make variable: {referenced_root}")
                if referenced_root in direct_roots:
                    continue
                if referenced_root not in source_views:
                    source_views[referenced_root] = _source_view(
                        roots[referenced_root],
                        build_root / "source-view" / referenced_root,
                        output,
                        active_paths=active_paths(referenced_root),
                        source_link_maps=source_link_maps.get(referenced_root, []),
                        generated_links=generated_source_links.get(referenced_root, []),
                        link_roots=source_views,
                    )
                    build_roots[referenced_root] = source_views[referenced_root]
        index_out = index_root / identifier
        final_out = final_root / identifier
        index_out.mkdir(parents=True, exist_ok=True)
        final_out.mkdir(parents=True, exist_ok=True)
        external.append({
            "id": identifier,
            "source": source,
            "index_out": index_out,
            "final_out": final_out,
            "group": group,
        })

    for name, previous in source_times.items():
        _restore_local_file_times(build_root / name, previous)
    logs = output / "logs"
    kernel_symvers = kernel_out / "Module.symvers"
    check_log = logs / f"group-check-{check_group}.log" if check_group else None
    active_external = [item for item in external
                       if selected_modules is None
                       or selected_modules.intersection(item["group"]["modules"])]
    def build_index(item: dict[str, Any]) -> str | None:
        command, group_env = _external_command(
            build_roots, kernel_out, item["source"], item["index_out"], item["group"],
            env, group_jobs, [], True,
        )
        try:
            run(
                command, cwd=item["source"], env=group_env,
                log=check_log or logs / f"modules-index-{item['id']}.log",
                display=f"make module-index[{item['id']}] -j{group_jobs}",
            )
        except PipelineError as error:
            return f"{item['id']}: {error}"
        symvers = item["index_out"] / "Module.symvers"
        if not symvers.is_file():
            return f"{item['id']}: module index pass produced no Module.symvers"
        missing_modules = []
        for module in item["group"]["modules"]:
            matches = list(item["index_out"].rglob(f"{_output_name(item['group'], module)}.ko"))
            if len(matches) != 1:
                missing_modules.append(
                    f"{module}: expected one {_output_name(item['group'], module)}.ko, found {len(matches)}"
                )
        if missing_modules:
            return f"{item['id']}: " + "; ".join(missing_modules)
        return None

    index_failures: list[str] = []
    with ThreadPoolExecutor(max_workers=parallelism) as executor:
        index_failures = [
            failure for failure in executor.map(build_index, active_external) if failure
        ]

    if index_failures:
        failure_path = (output / "group-checks" / f"{check_group}.json"
                        if check_group else output / "module-failures.json")
        write_json(failure_path, {
            "schema": 1,
            "stage": "index",
            "failed_groups": index_failures,
            "logs": [str(check_log.relative_to(output))] if check_log else sorted(
                str(path.relative_to(output)) for path in logs.glob("modules-index-*.log")
            ),
        })
        raise PipelineError(
            f"module index pass failed for {len(index_failures)} group(s):\n  "
            + "\n  ".join(index_failures)
        )

    if check_group is not None:
        result = {
            "group": check_group,
            "status": "index-pass",
            "log": str(check_log.relative_to(output)),
        }
        write_json(output / "group-checks" / f"{check_group}.json", result)
        return result

    symvers_by_id = {}
    for item in external:
        source_symvers = item["index_out"] / "Module.symvers"
        if not source_symvers.is_file():
            raise PipelineError(f"missing cached index for {item['id']}; include its modules in --module")
        symvers_by_id[item["id"]] = _selected_symvers(
            source_symvers, item["group"], build_root / "selected-symvers" / f"{item['id']}.symvers"
        )
    if selected_modules is not None:
        modprobe = find_tool("modprobe", env.get("PATH"))
        while True:
            active_ids = {item["id"] for item in active_external}
            affected = _affected_consumers(
                list(symvers_by_id.values()),
                {name: modules_dir / f"{name}.ko" for name in plan["modules"]},
                modprobe,
            )
            additions = [item for item in external if item["id"] not in active_ids
                         and affected.intersection(item["group"]["modules"])]
            selected_modules.update(affected)
            if not additions:
                break
            for item in additions:
                print(f"ABI consumer rebuild: {', '.join(item['group']['modules'])}", flush=True)
                failure = build_index(item)
                if failure:
                    raise PipelineError(failure)
                symvers_by_id[item["id"]] = _selected_symvers(
                    item["index_out"] / "Module.symvers", item["group"],
                    build_root / "selected-symvers" / f"{item['id']}.symvers",
                )
            active_external.extend(additions)
    def build_final(item: dict[str, Any]) -> list[str]:
        failures: list[str] = []
        extra = [path for key, path in symvers_by_id.items() if key != item["id"]]
        command, group_env = _external_command(
            build_roots, kernel_out, item["source"], item["final_out"], item["group"],
            env, group_jobs, extra, False,
        )
        try:
            run(
                command, cwd=item["source"], env=group_env,
                log=logs / f"modules-final-{item['id']}.log",
                display=f"make module-final[{item['id']}] -j{group_jobs}",
            )
        except PipelineError as error:
            return [f"{item['id']}: {error}"]
        for module in item["group"]["modules"]:
            matches = list(item["final_out"].rglob(f"{_output_name(item['group'], module)}.ko"))
            if len(matches) != 1:
                failures.append(
                    f"{item['id']}: {module}: expected one "
                    f"{_output_name(item['group'], module)}.ko, found {len(matches)}"
                )
                continue
        return failures

    final_failures: list[str] = []
    with ThreadPoolExecutor(max_workers=parallelism) as executor:
        for failures in executor.map(build_final, active_external):
            final_failures.extend(failures)

    if final_failures:
        write_json(output / "module-failures.json", {
            "schema": 1,
            "stage": "final",
            "failed_groups": final_failures,
            "logs": sorted(
                str(path.relative_to(output))
                for path in logs.glob("modules-final-*.log")
            ),
        })
        raise PipelineError(
            f"module final pass failed for {len(final_failures)} group(s):\n  "
            + "\n  ".join(final_failures)
        )

    if selected_modules is None or any(plan["modules"][name]["root"] == "kernel"
                                      for name in selected_modules):
        _finalize_kernel_modules(
            roots["kernel"], kernel_out, env, jobs, list(symvers_by_id.values()),
            logs / "kernel-modules-final.log",
        )
    for item in active_external:
        for module in item["group"]["modules"]:
            source = next(item["final_out"].rglob(f"{_output_name(item['group'], module)}.ko"))
            shutil.copy2(source, modules_dir / f"{module}.ko")
    for group in plan["groups"]:
        if group["root"] != "kernel":
            continue
        for module in group["modules"]:
            if selected_modules is not None and module not in selected_modules:
                continue
            shutil.copy2(
                _kernel_module(kernel_out, group, module), modules_dir / f"{module}.ko"
            )

    expected = set(plan["modules"])
    actual = {path.stem for path in modules_dir.glob("*.ko")}
    if expected != actual:
        raise PipelineError(
            f"built module set differs from plan; missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )
    btf_report = audit_btf(kernel_out / "vmlinux", sorted(modules_dir.glob("*.ko")))
    write_json(output / "logs/modules-btf-audit.json", btf_report)
    if btf_report["failures"]:
        raise PipelineError("rebuilt module BTF validation failed: " + "; ".join(btf_report["failures"]))
    strip = find_tool("llvm-strip", str(Path(args.toolchain).expanduser().resolve()))
    modinfo = find_tool("modinfo", env.get("PATH"))
    readelf = find_tool("llvm-readelf", str(Path(args.toolchain).expanduser().resolve()))
    for module in sorted(modules_dir.glob("*.ko")):
        vermagic = module_vermagic(module, modinfo, readelf)
        if not vermagic.startswith(kernelrelease):
            raise PipelineError(f"{module.name} vermagic does not match {kernelrelease}: {vermagic}")
        destination = stripped_dir / module.name
        if (incremental and destination.is_file()
                and previous_receipt.get("module_sha256", {}).get(module.name) == sha256_file(module)):
            continue
        shutil.copy2(module, destination)
        run([str(strip), "--strip-debug", str(destination)])

    receipt = {
        "kernelrelease": kernelrelease,
        "module_count": len(actual),
        "vendor_boot_count": len(plan["vendor_boot"]),
        "vendor_dlkm_count": len(plan["vendor_dlkm"]),
        "external_groups": [item["id"] for item in external],
        "rebuilt_modules": sorted(
            {name for item in active_external for name in item["group"]["modules"]}
            | {name for name in selected_modules or [] if plan["modules"][name]["root"] == "kernel"}
        ),
        "incremental": incremental,
        "base_btf_sha256": btf_report["base_btf_sha256"],
        "btf_refreshed_modules": sorted(btf_refresh),
        "module_sha256": {path.name: sha256_file(path) for path in sorted(modules_dir.glob("*.ko"))},
        "reused_build_identity_sha256": previous_receipt.get("build_identity_sha256") if incremental else None,
    }
    return receipt
