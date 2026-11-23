from __future__ import annotations

import json
import os
import re
import tomllib
from collections import defaultdict
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from .bazel import index_bazel_modules
from .common import PipelineError


ROOT_NAMES = ("kernel", "msm", "vendor", "compat")
SKIP_DIRS = {
    ".git", ".tmp", "__pycache__", "build", "out", "Documentation",
    "debian", "include/config", "include/generated",
}
ASSIGNMENT = re.compile(
    r"^\s*obj-\$\(([A-Za-z0-9_]+)\)\s*(?:\+|:)?=\s*(.*?)\s*$"
)
UNCONDITIONAL = re.compile(r"^\s*obj-m\s*(?:\+|:)?=\s*(.*?)\s*$")
OBJECT = re.compile(r"(?<![A-Za-z0-9_.$])([A-Za-z0-9_./+-]+\.o)(?![A-Za-z0-9_.$])")
MODULE_NAME = re.compile(r"^[A-Za-z0-9_+-]+$")
MAKE_VARIABLE = re.compile(r"^[A-Za-z0-9_]+$")


@dataclass(frozen=True, order=True)
class Candidate:
    root: str
    path: str
    config: str
    makefile: str
    output: str
    kind: str = "kbuild"
    sources: tuple[str, ...] = ()
    includes: tuple[str, ...] = ()
    defines: tuple[str, ...] = ()
    undefines: tuple[str, ...] = ()
    deps: tuple[str, ...] = ()
    make_vars: tuple[tuple[str, str], ...] = ()
    kcflags: tuple[str, ...] = ()


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        return tomllib.load(stream)


def read_module_list(path: Path) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    duplicates: list[str] = []
    for number, raw in enumerate(path.read_text().splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        name = line[:-3] if line.endswith(".ko") else line
        if not MODULE_NAME.fullmatch(name):
            raise PipelineError(f"invalid module name at {path}:{number}: {line}")
        if name in seen:
            duplicates.append(f"{name} (line {number})")
            continue
        seen.add(name)
        names.append(name)
    if duplicates:
        raise PipelineError(f"duplicate module entries in {path}: {', '.join(duplicates)}")
    return names


def source_roots(args: Any) -> dict[str, Path]:
    roots = {
        "kernel": Path(args.kernel_src).expanduser().resolve(),
        "msm": Path(args.msm_src).expanduser().resolve(),
        "vendor": Path(args.vendor_src).expanduser().resolve(),
    }
    roots["compat"] = (Path(args.compat_src).expanduser().resolve() if args.compat_src
                       else (roots["msm"] / "oneplus-6.18-compat").resolve())
    for entry in getattr(args, "extra_src", []) or []:
        if "=" not in entry:
            raise PipelineError("--extra-src must use NAME=/path/to/source")
        name, raw_path = entry.split("=", 1)
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name) or name in roots:
            raise PipelineError(f"invalid or duplicate extra source name: {name}")
        roots[name] = Path(raw_path).expanduser().resolve()
    for name, path in roots.items():
        if not path.is_dir():
            raise PipelineError(f"source root {name} does not exist: {path}")
    if len({roots[name] for name in ("kernel", "msm", "vendor")}) != 3:
        raise PipelineError("kernel, MSM and vendor must use separate source roots")
    if not (roots["vendor"] / "vendor").is_dir():
        raise PipelineError(
            "vendor source root must be the OnePlus repository root containing vendor/: "
            f"{roots['vendor']}"
        )
    return roots


def _logical_lines(path: Path):
    pending = ""
    for raw in path.read_text(errors="ignore").splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line and not pending:
            continue
        pending += line[:-1] + " " if line.endswith("\\") else line
        if not line.endswith("\\"):
            yield pending
            pending = ""
    if pending:
        yield pending


def _walk_makefiles(root: Path):
    for directory, dirs, files in os.walk(root, followlinks=False):
        current = Path(directory)
        rel_parts = current.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            dirs[:] = []
            continue
        dirs[:] = sorted(
            name for name in dirs
            if name not in SKIP_DIRS and not (current / name).is_symlink()
        )
        for name in ("Kbuild", "Makefile"):
            if name in files:
                yield current / name


def index_sources(roots: dict[str, Path]) -> dict[str, list[Candidate]]:
    index: dict[str, set[Candidate]] = defaultdict(set)
    for root_name in roots:
        search_root = roots[root_name] / "vendor" if root_name == "vendor" else roots[root_name]
        for makefile in _walk_makefiles(search_root):
            directory = makefile.parent.relative_to(search_root).as_posix()
            if directory == ".":
                directory = ""
            for line in _logical_lines(makefile):
                match = ASSIGNMENT.match(line)
                if match:
                    config, rhs = match.groups()
                else:
                    match = UNCONDITIONAL.match(line)
                    if not match:
                        continue
                    config, rhs = "", match.group(1)
                for object_file in OBJECT.findall(rhs):
                    module = Path(object_file).name[:-2]
                    if module in {"built-in", "modules"} or module.endswith(("-y", "-objs")):
                        continue
                    index[module].add(Candidate(
                        root=root_name,
                        path=directory,
                        config=config,
                        makefile=makefile.name,
                        output=module,
                    ))
    vendor_root = roots["vendor"] / "vendor"
    for item in index_bazel_modules(vendor_root):
        index[item["name"]].add(Candidate(
            root="vendor",
            path=item["path"],
            config="",
            makefile=item["manifest"],
            output=item["name"],
            kind="bazel",
            sources=tuple(item["sources"]),
            includes=tuple(item["includes"]),
            defines=tuple(item["defines"]),
            deps=tuple(item["deps"]),
        ))
    return {name: sorted(candidates) for name, candidates in index.items()}


def kernel_config_path(
    target: Path, manifest: dict[str, Any], roots: dict[str, Path],
) -> Path:
    build = manifest["build"]
    if bool(build.get("kernel_config")) == bool(build.get("kernel_defconfig")):
        raise PipelineError("specify exactly one of kernel_config and kernel_defconfig")
    if build.get("kernel_defconfig"):
        directory = (roots["kernel"] / "arch" / manifest["target"]["arch"] / "configs").resolve()
        config = (directory / build["kernel_defconfig"]).resolve()
        if not config.is_relative_to(directory):
            raise PipelineError("kernel_defconfig must stay inside the architecture configs directory")
    else:
        config = (target.parent / build["kernel_config"]).resolve()
    if not config.is_file():
        raise PipelineError(f"kernel config does not exist: {config}")
    return config


def read_config(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(errors="replace").splitlines():
        match = re.match(r"^(CONFIG_[A-Za-z0-9_]+)=(.*)$", raw)
        if match:
            values[match.group(1)] = match.group(2).strip('"')
        else:
            match = re.match(r"^# (CONFIG_[A-Za-z0-9_]+) is not set$", raw)
            if match:
                values[match.group(1)] = "n"
    return values


def _candidate_path(candidate: Candidate, roots: dict[str, Path]) -> Path:
    search_root = roots[candidate.root] / "vendor" if candidate.root == "vendor" else roots[candidate.root]
    result = (search_root / candidate.path).resolve()
    try:
        result.relative_to(search_root.resolve())
    except ValueError as error:
        raise PipelineError(f"source path escapes its root: {candidate}") from error
    if not result.is_dir():
        raise PipelineError(f"module source directory is missing: {result}")
    return result


def _validate_candidate(candidate: Candidate, roots: dict[str, Path]) -> None:
    if candidate.root not in roots:
        raise PipelineError(f"unsupported source root: {candidate.root}")
    if candidate.config and not MAKE_VARIABLE.fullmatch(candidate.config):
        raise PipelineError(f"invalid Kbuild variable: {candidate}")
    if not MODULE_NAME.fullmatch(candidate.output):
        raise PipelineError(f"invalid Kbuild output name: {candidate.output}")
    for name, value in candidate.make_vars:
        if not MAKE_VARIABLE.fullmatch(name) or not isinstance(value, str):
            raise PipelineError(f"invalid Kbuild variable assignment: {name}={value!r}")
        if "\n" in value or "\r" in value or "\0" in value:
            raise PipelineError(f"invalid control character in Kbuild variable {name}")
    for value in candidate.kcflags:
        if not isinstance(value, str) or any(char in value for char in "\r\n\0"):
            raise PipelineError(f"invalid control character in KCFLAGS for {candidate.output}")
    _candidate_path(candidate, roots)


def resolve_modules(
    module_names: list[str],
    roots: dict[str, Path],
    manifest: dict[str, Any],
    config_values: dict[str, str],
) -> tuple[dict[str, Candidate], dict[str, list[Candidate]]]:
    index = index_sources(roots)
    resolver = manifest.get("resolve", {})
    priority = list(resolver.get("root_order", [root for root in ROOT_NAMES if root in roots]))
    priority.extend(root for root in roots if root not in priority)
    if len(priority) != len(set(priority)) or any(root not in roots for root in priority):
        raise PipelineError("resolve.root_order contains a duplicate or unknown source root")
    priority_index = {name: index for index, name in enumerate(priority)}
    aliases = resolver.get("aliases", {})
    overrides = resolver.get("overrides", {})
    selected: dict[str, Candidate] = {}
    ambiguous: dict[str, list[Candidate]] = {}

    for module in module_names:
        override = overrides.get(module)
        if override:
            make_vars = override.get("make_vars", {})
            if not isinstance(make_vars, dict):
                raise PipelineError(f"make_vars for {module} must be a table")
            kcflags = override.get("kcflags", [])
            if not isinstance(kcflags, list):
                raise PipelineError(f"kcflags for {module} must be a list")
            candidate = Candidate(
                root=override["root"],
                path=override["path"],
                config=override.get("config", ""),
                makefile=override.get("makefile", "Kbuild"),
                output=override.get("output", module),
                kind=override.get("kind", "kbuild"),
                sources=tuple(override.get("sources", [])),
                includes=tuple(override.get("includes", [])),
                defines=tuple(override.get("defines", [])),
                undefines=tuple(override.get("undefines", [])),
                deps=tuple(override.get("deps", [])),
                make_vars=tuple(sorted(make_vars.items())),
                kcflags=tuple(kcflags),
            )
            if candidate.root not in roots and candidate.root in resolver.get("optional_roots", []):
                continue
            _validate_candidate(candidate, roots)
            selected[module] = candidate
            continue

        alias = aliases.get(module, module)
        if isinstance(alias, dict):
            source_name = alias.get("source", module)
            output_name = alias.get("output", source_name)
        else:
            source_name = alias
            output_name = source_name
        if output_name.endswith(".ko"):
            output_name = output_name[:-3]
        if not isinstance(source_name, str) or not isinstance(output_name, str):
            raise PipelineError(f"invalid alias for module {module}: {alias!r}")
        candidates = index.get(source_name, [])
        if not candidates:
            continue
        active = [item for item in candidates
                  if item.config and config_values.get(item.config, "n") in {"m", "y"}]
        if active:
            candidates = active
        else:
            unconditional = [item for item in candidates if not item.config]
            if unconditional:
                candidates = unconditional

        grouped: dict[tuple[str, str, str], list[Candidate]] = defaultdict(list)
        for item in candidates:
            grouped[(item.root, item.path, item.config)].append(item)
        normalized = [
            min(items, key=lambda item: (item.makefile != "Kbuild", item.makefile))
            for items in grouped.values()
        ]
        by_root: dict[str, list[Candidate]] = defaultdict(list)
        for item in normalized:
            by_root[item.root].append(item)
        preferred_root = min(by_root, key=lambda root: priority_index[root])
        preferred = sorted(by_root[preferred_root])
        if len(preferred) != 1:
            ambiguous[module] = normalized
            continue
        chosen = preferred[0]
        candidate = Candidate(
            root=chosen.root,
            path=chosen.path,
            config=chosen.config,
            makefile=chosen.makefile,
            output=output_name,
            kind=chosen.kind,
            sources=chosen.sources,
            includes=chosen.includes,
            defines=chosen.defines,
            undefines=chosen.undefines,
            deps=chosen.deps,
            make_vars=chosen.make_vars,
        )
        _validate_candidate(candidate, roots)
        selected[module] = candidate
    return selected, ambiguous


def build_plan(
    manifest_path: Path,
    roots: dict[str, Path],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    target_dir = manifest_path.parent
    module_cfg = manifest["modules"]
    boot = read_module_list(target_dir / module_cfg["vendor_boot_list"])
    dlkm = read_module_list(target_dir / module_cfg["vendor_dlkm_list"])
    excluded = set(module_cfg.get("exclude", []))
    overlap = sorted((set(boot) & set(dlkm)) - excluded)
    if overlap:
        raise PipelineError("modules assigned to both partitions: " + ", ".join(overlap))
    config_path = kernel_config_path(manifest_path, manifest, roots)
    all_modules = sorted((set(boot) | set(dlkm)) - excluded)
    selected, ambiguous = resolve_modules(all_modules, roots, manifest, read_config(config_path))
    path_overrides = manifest.get("resolve", {}).get("path_overrides", {})
    if not isinstance(path_overrides, dict):
        raise PipelineError("resolve.path_overrides must be a table")
    known_paths = {f"{item.root}:{item.path}" for item in selected.values()}
    def override_matches(pattern: str, source_path: str) -> bool:
        if ":" not in pattern:
            return False
        root_pattern, path_pattern = pattern.split(":", 1)
        source_root, source_relative = source_path.split(":", 1)
        if root_pattern not in {"*", source_root}:
            return False
        if path_pattern.endswith("/**"):
            prefix = path_pattern[:-3].rstrip("/")
            return source_relative.startswith(prefix + "/")
        return path_pattern == source_relative

    unknown_paths = sorted(
        pattern for pattern in path_overrides
        if not any(override_matches(pattern, source_path) for source_path in known_paths)
    )
    if unknown_paths:
        raise PipelineError(
            "path overrides do not match selected module sources: " + ", ".join(unknown_paths)
        )
    for module, candidate in list(selected.items()):
        source_path = f"{candidate.root}:{candidate.path}"
        matching_overrides = [
            (pattern, override) for pattern, override in path_overrides.items()
            if override_matches(pattern, source_path)
        ]
        if not matching_overrides:
            continue
        flags: list[str] = []
        make_vars: dict[str, str] = {}
        undefines: set[str] = set()
        for pattern, override in sorted(matching_overrides, key=lambda item: len(item[0])):
            if not isinstance(override, dict) or set(override) - {
                "kcflags", "make_vars", "undefines"
            }:
                raise PipelineError(
                    f"path override for {pattern} supports only kcflags, make_vars, and undefines"
                )
            item_flags = override.get("kcflags", [])
            item_make_vars = override.get("make_vars", {})
            item_undefines = override.get("undefines", [])
            if (not isinstance(item_flags, list) or not isinstance(item_make_vars, dict)
                    or not isinstance(item_undefines, list)):
                raise PipelineError(f"invalid path override for {pattern}")
            flags.extend(item_flags)
            make_vars.update(item_make_vars)
            undefines.update(item_undefines)
        candidate = replace(
            candidate,
            kcflags=(*candidate.kcflags, *flags),
            undefines=tuple(sorted(set(candidate.undefines) | undefines)),
            make_vars=tuple(sorted({**dict(candidate.make_vars), **make_vars}.items())),
        )
        _validate_candidate(candidate, roots)
        selected[module] = candidate
    external_kcflags = manifest.get("build", {}).get("external_kcflags", [])
    if not isinstance(external_kcflags, list):
        raise PipelineError("build.external_kcflags must be a list")
    for module, candidate in list(selected.items()):
        candidate = replace(candidate, kcflags=(*candidate.kcflags, *external_kcflags))
        _validate_candidate(candidate, roots)
        selected[module] = candidate
    external_make_vars = manifest.get("build", {}).get("external_make_vars", {})
    if not isinstance(external_make_vars, dict):
        raise PipelineError("build.external_make_vars must be a table")
    for name, value in external_make_vars.items():
        if (not MAKE_VARIABLE.fullmatch(name) or not isinstance(value, str)
                or any(char in value for char in "\r\n\0")):
            raise PipelineError(f"invalid external make variable: {name}={value!r}")
    unresolved = sorted(module for module in all_modules if module not in selected)
    groups: dict[tuple[Any, ...], dict[str, Any]] = {}
    for module in all_modules:
        candidate = selected.get(module)
        if not candidate:
            continue
        make_vars = {**external_make_vars, **dict(candidate.make_vars)}
        make_vars_key = tuple(sorted(make_vars.items()))
        key = (
            candidate.root,
            candidate.path,
            candidate.kind,
            candidate.makefile,
            module if candidate.kind == "bazel" else "",
            candidate.config,
            make_vars_key,
            candidate.kcflags,
        )
        group = groups.setdefault(key, {
            "root": key[0],
            "path": key[1],
            "kind": key[2],
            "makefile": key[3],
            "modules": [],
            "configs": [],
            "make_vars": make_vars,
            "kcflags": list(candidate.kcflags),
        })
        group["modules"].append(module)
        group.setdefault("outputs", {})[module] = candidate.output
        group.setdefault("kinds", {})[module] = candidate.kind
        group.setdefault("specs", {})[module] = {
            "sources": list(candidate.sources),
            "includes": list(candidate.includes),
            "defines": list(candidate.defines),
            "undefines": list(candidate.undefines),
            "deps": list(candidate.deps),
            "make_vars": dict(candidate.make_vars),
            "kcflags": list(candidate.kcflags),
        }
        if candidate.config:
            group["configs"].append(candidate.config)
    for group in groups.values():
        group["modules"].sort()
        group["configs"] = sorted(set(group["configs"]))
    return {
        "schema": 2,
        "target": manifest["target"]["name"],
        "excluded": sorted(excluded),
        "vendor_boot": [name for name in boot if name not in excluded],
        "vendor_dlkm": [name for name in dlkm if name not in excluded],
        "modules": {name: asdict(candidate) for name, candidate in sorted(selected.items())},
        "groups": [groups[key] for key in sorted(groups)],
        "unresolved": unresolved,
        "ambiguous": {
            name: [asdict(candidate) for candidate in candidates]
            for name, candidates in sorted(ambiguous.items())
        },
    }


def write_plan(plan: dict[str, Any], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")
    temporary.replace(destination)
