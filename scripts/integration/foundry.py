"""Install the demo's qualified Foundry tools without changing the host installation.

Official v1.5.1 archive digests were obtained from the foundry-rs/foundry release.
Only named regular executables are extracted; the archive is never unpacked into
an operator directory. A matching host installation is reused when available.
"""

import hashlib
import os
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from urllib.request import urlopen

# Qualified release and SHA-256 digests of its official platform archives.
VERSION = "1.5.1"
ARCHIVES = {
    "darwin_amd64": "a416e79c26d32cd37316232f790b3a1bdeae4dfae09d82627d7a1ace4c281848",
    "darwin_arm64": "b3bf1752be066e0877911721e0624058171c88fc5616e228937fe4620b41c40d",
    "linux_amd64": "73640b01bd9ed29fdb4965085099371f8cf0dbbec3e2086cf54564efc4dcfe88",
    "linux_arm64": "cccf28bdf202289e837a9e21ed213b2b80dc1e806e12f1717bc98a44315c331e",
}


def qualified(binary: Path) -> bool:
    """Return whether this executable reports the qualified Foundry release."""
    try:
        output = subprocess.check_output(
            [str(binary), "--version"], text=True, timeout=5
        )
        return (
            re.search(
                r"Version: " + re.escape(VERSION) + r"(?:-|$)", output.splitlines()[0]
            )
            is not None
        )
    except (OSError, subprocess.SubprocessError, IndexError):
        return False


def install_archive(archive: Path, destination: Path, digest: str) -> None:
    """Verify the complete archive before installing its four regular executables.

    destination is the demo-owned version/platform cache, not a host bin directory.
    No executable is replaced unless the archive digest and all members validate.
    """
    if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
        raise ValueError("Foundry archive checksum mismatch")
    with tarfile.open(archive) as bundle:
        members = [
            bundle.getmember(name) for name in ("anvil", "forge", "cast", "chisel")
        ]
        if not all(member.isfile() for member in members):
            raise ValueError("Foundry archive contains a non-regular executable")
        destination.mkdir(parents=True, exist_ok=True)
        for member in members:
            with bundle.extractfile(member) as source:
                with tempfile.NamedTemporaryFile(
                    dir=destination, prefix=f".{member.name}-", delete=False
                ) as target:
                    temporary = Path(target.name)
                    shutil.copyfileobj(source, target)
                try:
                    temporary.chmod(0o755)
                    temporary.replace(destination / member.name)
                finally:
                    temporary.unlink(missing_ok=True)


def ensure_foundry(cache: Path | None = None) -> Path:
    """Return qualified tools, downloading a checksum-pinned copy if needed.

    cache overrides the demo's user cache for tests or explicit local installs.
    macOS and Linux on Intel/ARM are supported. No shell installer or sudo is used.
    """
    anvil = shutil.which("anvil")
    if anvil and qualified(Path(anvil)) and qualified(Path(anvil).parent / "forge"):
        return Path(anvil).parent
    system = platform.system().lower()
    machine = {"x86_64": "amd64", "aarch64": "arm64"}.get(
        platform.machine(), platform.machine()
    )
    target = f"{system}_{machine}"
    if target not in ARCHIVES:
        raise ValueError(f"Demo Foundry installer does not support {target}")
    cache = (
        cache
        or Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
        / "eoa-verifier/foundry"
    )
    destination = cache / VERSION / target
    if qualified(destination / "anvil") and qualified(destination / "forge"):
        return destination
    url = f"https://github.com/foundry-rs/foundry/releases/download/v{VERSION}/foundry_v{VERSION}_{target}.tar.gz"
    print(f"Installing Foundry {VERSION} for {target} in {destination}", flush=True)
    with tempfile.TemporaryDirectory(prefix="eoa-foundry-") as temporary:
        archive = Path(temporary) / "foundry.tar.gz"
        with urlopen(url, timeout=60) as source, archive.open("wb") as output:
            shutil.copyfileobj(source, output)
        install_archive(archive, destination, ARCHIVES[target])
    if not qualified(destination / "anvil") or not qualified(destination / "forge"):
        raise ValueError("Installed Foundry tools report an unexpected version")
    return destination
