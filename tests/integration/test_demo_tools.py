"""Canonical wallet signatures and checksum-verified local tool installation."""

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from scripts.integration.foundry import install_archive
from scripts.integration.wallet import sign_challenge


@pytest.fixture
def challenge():
    """Load the owned canonical wallet-1 reference challenge; this is not issued credential evidence."""
    return json.loads(
        (
            Path(__file__).resolve().parents[2]
            / "protocol/external-association-v1/eoa-v1/challenge.json"
        ).read_text()
    )


def test_wallet_driver_signs_the_owned_profile(challenge):
    """Recover the expected wallet while rejecting a different wallet and altered signing domain."""
    from eth_account import Account
    from eth_account.messages import encode_typed_data

    signature = sign_challenge(challenge, 1)["signature"]
    assert (
        Account.recover_message(
            encode_typed_data(full_message=challenge), signature=signature
        ).lower()
        == challenge["message"]["extId"].split(":")[2]
    )
    with pytest.raises(ValueError, match="selected wallet"):
        sign_challenge(challenge, 2)
    challenge["domain"]["name"] = "different application"
    with pytest.raises(ValueError, match="association profile"):
        sign_challenge(challenge, 1)


def test_foundry_archive_is_verified_before_installation(tmp_path):
    """A bad digest installs nothing; a verified archive writes only named regular executables."""
    archive = tmp_path / "foundry.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        for name in ("anvil", "forge", "cast", "chisel"):
            raw = ("#!/bin/sh\necho " + name + "\n").encode()
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            bundle.addfile(info, io.BytesIO(raw))
    destination = tmp_path / "tools"
    with pytest.raises(ValueError, match="checksum"):
        install_archive(archive, destination, "0" * 64)
    assert not destination.exists()
    install_archive(
        archive, destination, hashlib.sha256(archive.read_bytes()).hexdigest()
    )
    assert sorted(p.name for p in destination.iterdir()) == [
        "anvil",
        "cast",
        "chisel",
        "forge",
    ]
    assert all(p.stat().st_mode & 0o111 for p in destination.iterdir())
