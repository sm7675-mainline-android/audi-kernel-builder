from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class PipelineError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_digest(root: Path, *, ignored_xattrs: frozenset[str] = frozenset()) -> str:
    root = root.resolve()
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode()
        info = path.lstat()
        digest.update(relative + b"\0")
        digest.update(f"{info.st_mode & 0o7777:o}\0".encode())
        if path.is_symlink():
            digest.update(b"L\0" + os.readlink(path).encode() + b"\0")
        elif path.is_file():
            digest.update(b"F\0" + str(info.st_size).encode() + b"\0")
            digest.update(bytes.fromhex(sha256_file(path)))
        elif path.is_dir():
            digest.update(b"D\0")
        else:
            raise PipelineError(f"unsupported file type in input tree: {path}")
        try:
            for name in sorted(os.listxattr(path, follow_symlinks=False)):
                if name in ignored_xattrs:
                    continue
                value = os.getxattr(path, name, follow_symlinks=False)
                digest.update(name.encode() + b"\0" + value + b"\0")
        except OSError:
            pass
    return digest.hexdigest()


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    log: Path | None = None,
    capture: bool = False,
    display: str | None = None,
) -> subprocess.CompletedProcess[str]:
    print(f"$ {display or shlex.join(command)}")
    if log:
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("w", encoding="utf-8") as stream:
            result = subprocess.run(
                command, cwd=cwd, env=env, stdout=stream,
                stderr=subprocess.STDOUT, text=True,
            )
        if result.returncode:
            raise PipelineError(f"command failed ({result.returncode}); see {log}")
        return subprocess.CompletedProcess(command, result.returncode, "", "")
    result = subprocess.run(
        command, cwd=cwd, env=env, text=True,
        capture_output=capture,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout or "").strip() if capture else ""
        raise PipelineError(
            f"command failed ({result.returncode}): {shlex.join(command)}"
            + (f"\n{detail}" if detail else "")
        )
    return result


def find_tool(name: str, search_path: str | None = None) -> Path:
    result = shutil.which(name, path=search_path)
    if not result:
        raise PipelineError(f"required tool is not available: {name}")
    path = Path(result)
    if name in ("depmod", "modinfo", "modprobe"):
        return path.absolute()
    return path.resolve()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def ensure_output_path(output: Path, path: Path) -> Path:
    output = output.resolve()
    path = path.resolve()
    try:
        path.relative_to(output)
    except ValueError as error:
        raise PipelineError(f"generated path must stay inside --out: {path}") from error
    if path == output:
        raise PipelineError("refusing to replace the output root")
    return path


def replace_tree(source: Path, destination: Path, output: Path) -> None:
    destination = ensure_output_path(output, destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        shutil.rmtree(destination)
    os.replace(source, destination)


@contextmanager
def output_lock(output: Path) -> Iterator[None]:
    output.mkdir(parents=True, exist_ok=True)
    lock_path = output / ".forge.lock"
    with lock_path.open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        yield


@contextmanager
def temporary_directory(parent: Path, prefix: str) -> Iterator[Path]:
    parent.mkdir(parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    try:
        yield path
    finally:
        if path.exists():
            shutil.rmtree(path)


def reject_whitespace(paths: list[Path]) -> None:
    for path in paths:
        if any(char.isspace() for char in str(path)):
            raise PipelineError(f"Kbuild paths containing whitespace are unsupported: {path}")
