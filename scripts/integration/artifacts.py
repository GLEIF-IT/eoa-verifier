"""Explicit JSON artifacts and isolated candidate source snapshots.

These helpers never copy Git internals, ignored operator data or live stores.
They record what was built so a local dirty candidate is distinguishable from a
published revision. They are tooling only, outside application wheels.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def load_json(path: Path) -> dict:
    """Read an explicit UTF-8 JSON artifact; malformed or missing input fails."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save_json(path: Path, value) -> None:
    """Atomically replace one run-owned JSON file with private file permissions."""
    path = Path(path)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}-",
        delete=False,
    ) as stream:
        temporary = Path(stream.name)
        json.dump(value, stream, indent=2)
        stream.write("\n")
    try:
        os.chmod(temporary, 0o600)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def source_revision(source: Path) -> str:
    """Return the exact base commit of an explicitly selected source checkout."""
    return subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()


def snapshot_source(source: Path, destination: Path) -> dict:
    """Copy tracked and unignored candidate inputs, including recorded submodules.

    The destination must be fresh. Git internals and ignored caches/stores are
    excluded by Git's own file inventory; symlinks are refused rather than followed
    into an operator directory. Return base revision and a content digest.
    """
    source = source.resolve()
    destination.mkdir(parents=True)
    inputs = (
        subprocess.check_output(
            [
                "git",
                "-C",
                str(source),
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ]
        )
        .decode()
        .split("\0")
    )
    digest = hashlib.sha256()
    submodules = {}
    for relative in sorted(set(filter(None, inputs))):
        original, copied = source / relative, destination / relative
        if original.is_symlink():
            raise ValueError(f"Symlink source input is not supported: {original}")
        if original.is_dir():
            provenance = snapshot_source(original, copied)
            submodules[relative] = provenance
            digest.update(b"directory\0" + relative.encode() + b"\0")
            digest.update(bytes.fromhex(provenance["sha256"]))
        elif original.is_file():
            copied.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(original, copied)
            digest.update(b"file\0" + relative.encode() + b"\0")
            digest.update(hashlib.sha256(original.read_bytes()).digest())
    return {
        "revision": source_revision(source),
        "sha256": digest.hexdigest(),
        "submodules": submodules,
    }


def copy_tool_inputs(source: Path, destination: Path) -> dict:
    """Copy an external qualification root alongside an explicitly supplied wheel.

    Such a root is deliberately outside Git and contains only owned tooling,
    tests and protocol fixtures copied by the caller. Application code is supplied
    by the wheel, never imported from this directory.
    """
    destination.mkdir(parents=True)
    for name in ("scripts", "tests", "protocol"):
        if (source / name).is_dir():
            shutil.copytree(
                source / name,
                destination / name,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
    for name in ("pytest.ini", "README.md"):
        if (source / name).is_file():
            shutil.copy2(source / name, destination / name)
    digest = hashlib.sha256()
    for path in sorted(destination.rglob("*")):
        if path.is_file():
            digest.update(str(path.relative_to(destination)).encode() + b"\0")
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return {"sha256": digest.hexdigest()}
