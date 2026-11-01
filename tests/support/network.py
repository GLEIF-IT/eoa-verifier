"""Allocate local ephemeral probe ports for isolated test listeners."""

import socket


def free_port():
    """Return an available loopback port, releasing the probe socket; the caller must bind it promptly."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
