"""Functional lifecycle failures must preserve foreign processes and data."""

import socket
import subprocess
import sys

import pytest

from scripts.integration.artifacts import load_json, save_json, snapshot_source
from scripts.integration.processes import (
    free_port,
    is_running,
    launch,
    process_records,
    stop,
    wait_ready,
)


def test_foreign_listener_survives_refused_launch(tmp_path):
    """A listening port never authorizes adopting or terminating its owner."""
    (tmp_path / "logs").mkdir()
    with socket.socket() as foreign:
        foreign.bind(("127.0.0.1", 0))
        foreign.listen()
        with pytest.raises(OSError):
            launch(
                tmp_path,
                "foreign",
                [sys.executable, "-c", "raise AssertionError"],
                port=foreign.getsockname()[1],
            )
        stop(tmp_path)
        with socket.create_connection(foreign.getsockname(), timeout=1):
            pass
    assert not process_records(tmp_path)


def test_owned_process_restart_and_stop_preserve_artifacts(tmp_path):
    """Use literal shell-sensitive paths; restart promptly and keep stopped state."""
    root = tmp_path / "a space's $literal; run"
    (root / "logs").mkdir(parents=True)
    artifact = root / "sentinel.json"
    save_json(artifact, {"preserve": True})
    port = free_port()
    command = [
        sys.executable,
        "-m",
        "http.server",
        str(port),
        "--bind",
        "127.0.0.1",
        "--directory",
        str(root),
    ]

    def ready():
        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
            return True

    try:
        launch(root, "server", command, port=port)
        wait_ready(root, "server", ready)
        first = process_records(root)["server"]
        launch(root, "server", command, port=port)
        assert process_records(root)["server"] == first
        stop(root)
        assert not is_running(first)
        launch(root, "server", command, port=port)
        wait_ready(root, "server", ready)
        assert process_records(root)["server"]["pid"] != first["pid"]
    finally:
        stop(root)
    assert load_json(artifact) == {"preserve": True}
    assert not process_records(root)


def test_candidate_snapshot_preserves_work_and_excludes_ignored_stores(tmp_path):
    """Build actual Git inputs while leaving operator state and stale builds alone."""
    source = tmp_path / "source"
    source.mkdir()
    subprocess.run(["git", "init", "--quiet", str(source)], check=True)

    def git(*args):
        subprocess.run(
            ["git", "-C", str(source), *args], check=True, capture_output=True
        )

    git("config", "user.name", "Disposable fixture")
    git("config", "user.email", "fixture@example.invalid")
    (source / ".gitignore").write_text("state/\nbuild/\n*.egg-info/\n")
    (source / "current.py").write_text("original = True\n")
    git("add", ".")
    git("commit", "--quiet", "-m", "Create disposable source")
    (source / "current.py").write_text("candidate = True\n")
    for directory in ("state", "build", "old.egg-info"):
        (source / directory).mkdir()
        (source / directory / "sentinel").write_bytes(b"operator data")
    destination = tmp_path / "build candidate"
    provenance = snapshot_source(source, destination)
    assert len(provenance["revision"]) == 40 and len(provenance["sha256"]) == 64
    assert sorted(p.name for p in destination.iterdir()) == [".gitignore", "current.py"]
    assert (destination / "current.py").read_text() == "candidate = True\n"
    assert (source / "state/sentinel").read_bytes() == b"operator data"
