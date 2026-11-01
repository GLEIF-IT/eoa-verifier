"""Build a Verifier wheel and its isolated tooling environment from explicit inputs."""

import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

from .artifacts import copy_tool_inputs, snapshot_source


def prepare_installation(
    root: Path,
    source: Path,
    *,
    wheel: Path | None = None,
    tool_revision: str | None = None,
) -> dict:
    """Install a fresh wheel and return interpreter/tool paths plus provenance.

    source is an explicit candidate checkout, or the copied qualification root
    accompanying wheel. The latter requires tool_revision because it has no Git
    metadata. Build/install output is retained in root/logs/build.log.
    """
    snapshot = root / "tools/verifier"
    if wheel is None:
        provenance = snapshot_source(source, snapshot)
    else:
        if not tool_revision:
            raise ValueError("--verifier-wheel requires --tool-revision")
        provenance = (
            snapshot_source(source, snapshot)
            if (source / ".git").exists()
            else copy_tool_inputs(source, snapshot)
        )
        provenance["revision"] = tool_revision
    # Resolve launcher symlinks before venv records its base-interpreter home.
    # In particular, uv's ~/.local/bin shim is not the Python installation root.
    base_python = str(Path(sys._base_executable).resolve())
    subprocess.run(
        [base_python, "-m", "venv", "--symlinks", str(root / "venv")], check=True
    )
    python = str(root / "venv/bin/python")
    with (root / "logs/build.log").open("w") as log:
        if wheel is None:
            subprocess.run(
                [
                    python,
                    "-m",
                    "pip",
                    "wheel",
                    "--no-deps",
                    "--wheel-dir",
                    str(root / "wheels"),
                    str(snapshot),
                ],
                check=True,
                stdout=log,
                stderr=log,
            )
            wheel = next((root / "wheels").glob("eoa_verifier-*.whl"))
        else:
            copied = root / "wheels" / wheel.name
            shutil.copy2(wheel, copied)
            wheel = copied
        subprocess.run(
            [python, "-m", "pip", "install", str(wheel) + "[test]"],
            check=True,
            stdout=log,
            stderr=log,
        )
    return {
        "python": python,
        "tool": str(snapshot / "scripts/integration/env.py"),
        "sourceRevision": provenance["revision"],
        "sourceSha256": provenance["sha256"],
        "wheelSha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
    }
