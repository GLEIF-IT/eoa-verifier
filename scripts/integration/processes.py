"""Start, inspect and stop only processes owned by one local integration run.

All children start in their own session. A saved PID alone is insufficient:
shutdown checks the recorded start time, executable command and process group.
One controller operates a run at a time; separate runs use separate ports/state.
"""

import os
from pathlib import Path
import signal
import socket
import subprocess
import time
from typing import Callable

from .artifacts import load_json, save_json


def free_port() -> int:
    """Probe a free loopback port; launch still rejects a later foreign occupant."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def process_identity(pid: int) -> str:
    """Read the POSIX process generation and command, or an empty value if gone."""
    result = subprocess.run(
        ["ps", "-p", str(pid), "-o", "lstart=", "-o", "command="],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def is_running(record: dict | None) -> bool:
    """Return whether this PID still identifies the recorded owned child."""
    return bool(record) and process_identity(record["pid"]) == record["identity"]


def process_records(root: Path) -> dict:
    """Read a run's process inventory; a fresh run has no processes yet."""
    path = root / "processes.json"
    return load_json(path) if path.exists() else {}


def launch(
    root: Path,
    role: str,
    command: list[str],
    *,
    port: int,
    env=None,
    cwd: Path | None = None,
) -> None:
    """Start one concrete service and retain its generation and combined log.

    Reusing our identical running role is idempotent. A different command or a
    foreign listener fails. If process registration fails, stop the new child
    instead of leaving an untracked daemon behind. Readiness is checked separately.
    """
    records = process_records(root)
    existing = records.get(role)
    if is_running(existing):
        if existing["command"] != command:
            raise ValueError(f"{role} already runs with different arguments")
        return
    # Permit restart after our closed TCP connections enter TIME_WAIT. A live
    # listener still makes this exclusive bind fail.
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("127.0.0.1", port))
    log_path = root / "logs" / f"{role}.log"
    with log_path.open("ab") as log:
        child = subprocess.Popen(
            command,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=cwd,
            start_new_session=True,
        )
    try:
        identity = process_identity(child.pid)
        if not identity or child.poll() is not None:
            raise RuntimeError(f"{role} exited; inspect {log_path}")
        records[role] = {
            "pid": child.pid,
            "identity": identity,
            "command": command,
            "port": port,
        }
        save_json(root / "processes.json", records)
    except BaseException:
        if child.poll() is None:
            child.terminate()
        child.wait(timeout=10)
        raise


def stop(root: Path, role: str | None = None) -> None:
    """Stop selected owned sessions in reverse launch order, preserving all data.

    Check identity again before escalation. Do not signal a recycled PID or a
    process that is no longer its own group leader. A vanished child is harmless.
    """
    records = process_records(root)
    for name in reversed(list(records)):
        if role is not None and name != role:
            continue
        record = records[name]
        if is_running(record):
            _signal_owned(record, signal.SIGTERM)
            deadline = time.monotonic() + 12
            while is_running(record) and time.monotonic() < deadline:
                time.sleep(0.05)
            if is_running(record):
                _signal_owned(record, signal.SIGKILL)
                deadline = time.monotonic() + 3
                while is_running(record) and time.monotonic() < deadline:
                    time.sleep(0.05)
                if is_running(record):
                    raise RuntimeError(f"Could not stop owned service {name}")
        try:
            os.waitpid(record["pid"], os.WNOHANG)
        except ChildProcessError:
            pass  # A later controller is not the parent of the stopped child.
        records.pop(name)
        save_json(root / "processes.json", records)


def _signal_owned(record: dict, signum: int) -> None:
    """Signal a verified owned session; tolerate an exit during the check."""
    try:
        if is_running(record) and os.getpgid(record["pid"]) == record["pid"]:
            os.killpg(record["pid"], signum)
    except ProcessLookupError:
        pass


def wait_ready(root: Path, role: str, probe: Callable, timeout: float = 20):
    """Poll a bounded public readiness probe while checking the owned child's life.

    Network/decoding failures remain retryable until the deadline. Return the
    successful probe value; include the service log path on failure.
    """
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        if not is_running(process_records(root).get(role)):
            raise RuntimeError(f"{role} stopped; inspect {root}/logs/{role}.log")
        try:
            value = probe()
            if value is not None and value is not False:
                return value
        except (OSError, ValueError) as error:
            last_error = error
        time.sleep(0.05)
    raise TimeoutError(
        f"{role} readiness timed out ({last_error}); inspect {root}/logs/{role}.log"
    )
