from __future__ import annotations

import re
from pathlib import Path


STRING = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')


def _block(text: str, start: int) -> str:
    opening = text.find("(", start)
    if opening < 0:
        return ""
    depth = 0
    quote = False
    escaped = False
    for index in range(opening, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = False
            continue
        if char == '"':
            quote = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[opening + 1:index]
    return ""


def _strings(block: str) -> list[str]:
    return [match.group(1) for match in STRING.finditer(block)]


def _list_value(block: str, name: str) -> list[str]:
    match = re.search(
        rf"\b{name}\s*=\s*(?:native\.glob\s*\(\s*)?\[(.*?)\](?:\s*\))?",
        block,
        re.S,
    )
    return _strings(match.group(1)) if match else []


def _conditional_qcom_sources(block: str) -> list[str]:
    match = re.search(r"conditional_srcs\s*=\s*\{(.*?)\n\s*\}\s*,", block, re.S)
    if not match:
        return []
    false = re.search(r"\bFalse\s*:\s*\[(.*?)\]", match.group(1), re.S)
    return _strings(false.group(1)) if false else []


def _conditional_qcom_defines(block: str) -> list[str]:
    match = re.search(r"conditional_defines\s*=\s*\{(.*?)\n\s*\}\s*,", block, re.S)
    if not match:
        return []
    qcom = re.search(r'"qcom"\s*:\s*\[(.*?)\]', match.group(1), re.S)
    return _strings(qcom.group(1)) if qcom else []


def _expand_sources(directory: Path, patterns: list[str]) -> tuple[str, ...]:
    result: set[str] = set()
    for pattern in patterns:
        if any(char in pattern for char in "*?["):
            paths = directory.glob(pattern)
        else:
            paths = [directory / pattern]
        for path in paths:
            if path.is_file() and path.suffix in {".c", ".h", ".S", ".s"}:
                result.add(path.relative_to(directory).as_posix())
    return tuple(sorted(result))


def index_bazel_modules(vendor_root: Path) -> list[dict[str, object]]:
    """Extract the small, declarative subset needed from Oplus DDK manifests.

    The vendor manifests already describe source files and output names. This
    reader deliberately does not execute Starlark, so CI does not need Bazel.
    """
    result: list[dict[str, object]] = []
    for manifest in sorted(vendor_root.rglob("oplus_local_modules.bzl")):
        text = manifest.read_text(errors="ignore")
        cursor = 0
        while True:
            start = text.find("define_oplus_ddk_module(", cursor)
            if start < 0:
                break
            block = _block(text, start)
            cursor = start + len(block) + 1
            name = re.search(r'\bname\s*=\s*"([A-Za-z0-9_+-]+)"', block)
            if not name:
                continue
            patterns = _list_value(block, "srcs") + _conditional_qcom_sources(block)
            sources = _expand_sources(manifest.parent, patterns)
            if not sources:
                continue
            includes = tuple(_strings(re.search(
                r"\bincludes\s*=\s*\[(.*?)\]", block, re.S
            ).group(1)) if re.search(r"\bincludes\s*=\s*\[(.*?)\]", block, re.S) else [])
            defines = tuple(_list_value(block, "local_defines") + _conditional_qcom_defines(block))
            deps = tuple(re.findall(r"//[^:]+:([A-Za-z0-9_+-]+)", block))
            result.append({
                "name": name.group(1),
                "path": manifest.parent.relative_to(vendor_root).as_posix(),
                "sources": sources,
                "includes": includes,
                "defines": defines,
                "deps": deps,
                "manifest": manifest.name,
            })
    return result
