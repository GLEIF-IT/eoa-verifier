"""The same standalone commands used by operators, against an installed wheel."""

import os
from pathlib import Path
import subprocess
import sys
import pytest

from scripts.integration.artifacts import source_revision


@pytest.mark.parametrize("local_only", [False, True])
def test_installed_verifier_qualifies_without_oracle_or_comply(tmp_path, local_only):
    root = Path(__file__).resolve().parents[2]
    wheel = os.environ.get("EOA_VERIFIER_WHEEL")
    assert wheel and Path(wheel).is_file(), (
        "Set EOA_VERIFIER_WHEEL to the fresh qualified wheel"
    )
    run = tmp_path / "standalone"
    base = [sys.executable, "-m", "scripts.integration.env"]
    prepare = [
        *base,
        "prepare",
        "--run-dir",
        str(run),
        "--witness-count",
        "1",
        "--verifier-wheel",
        wheel,
        "--tool-revision",
        os.getenv("GITHUB_SHA") or source_revision(root),
    ]
    subprocess.run(
        prepare, check=True, timeout=180, capture_output=True, text=True, cwd=root
    )
    try:
        subprocess.run(
            [
                str(run / "venv/bin/python"),
                "-c",
                "from importlib.util import find_spec; assert find_spec('vlei_oracle') is None",
            ],
            check=True,
        )
        completed = subprocess.run(
            [
                *base,
                "qualify",
                "--run-dir",
                str(run),
                *(["--local-only"] if local_only else []),
            ],
            check=False,
            timeout=180,
            capture_output=True,
            text=True,
            cwd=root,
        )
        assert completed.returncode == 0, (completed.stdout, completed.stderr, str(run))
        assert (run / "flow.json").is_file()
    finally:
        subprocess.run(
            [*base, "stop", "--run-dir", str(run)], check=True, timeout=30, cwd=root
        )
