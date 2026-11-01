"""Validate service identity, storage and network configuration before startup."""

import math
from dataclasses import dataclass, field
from urllib.parse import quote, urlsplit

from hio.core.http import httping as hio_httping
from keri.core import coring


@dataclass(frozen=True)
class ServiceConfig:
    """Service identity, local storage and initial-verification network settings."""

    # Configured trust root for QVI issuance and delegation; required canonical AID.
    trusted_geda_aid: str
    # Trusted Ethereum endpoint for initial observations; never taken from a credential.
    rpc_url: str
    # Required positive network ID, checked against both association and RPC.
    chain_id: int
    # KERIpy store name; reuse to reopen existing state.
    name: str = "eoa-verifier"
    # Habitat name within the Habery; reuse to retain the service AID.
    alias: str = "verifier"
    # Optional KERIpy store namespace below each store root.
    base: str = ""
    # Root override for KERIpy storage; None uses each KERIpy store’s default/fallback.
    head_dir: str | None = None
    # HTTP bind address; loopback by default.
    host: str = "127.0.0.1"
    # HTTP listening port; zero asks the OS for an ephemeral port.
    http_port: int = 9724
    # Optional KERIpy keystore passcode; excluded from dataclass repr.
    passcode: str | None = field(default=None, repr=False)
    # Optional JSON KERIpy inception options; used only when creating the alias.
    incept_file: str | None = None
    # Use disposable KERIpy stores and remove them on close; intended for tests.
    temp: bool = False
    # Configure both to enable durable acceptance/outbox for one trusted destination.
    webhook_url: str | None = None
    webhook_aid: str | None = None
    # Operational seconds: one in-flight request; backoff range is [lower, 2 * lower].
    webhook_max_attempts: int = 3
    webhook_timeout: float = 10.0
    webhook_interval: float = 1.0
    webhook_backoff_base: float = 1.0
    webhook_backoff_cap: float = 150.0

    def __post_init__(self):
        """Reject invalid verification configuration before opening resources."""
        if type(self.webhook_max_attempts) is not int or self.webhook_max_attempts < 1:
            raise ValueError("webhook max attempts must be a positive integer")
        timings = (
            self.webhook_timeout,
            self.webhook_interval,
            self.webhook_backoff_base,
            self.webhook_backoff_cap,
        )
        if not all(math.isfinite(value) and value > 0 for value in timings):
            raise ValueError("webhook timing values must be finite positive seconds")
        if self.webhook_backoff_cap < self.webhook_backoff_base:
            raise ValueError("webhook backoff cap must be at least the base")
        if bool(self.webhook_url) != bool(self.webhook_aid):
            raise ValueError("webhook URL and AID must be configured together")
        if self.webhook_url:
            target = urlsplit(self.webhook_url)
            if (
                target.scheme not in ("http", "https")
                or not target.netloc
                or target.fragment
            ):
                raise ValueError(
                    "webhook must be an absolute HTTP URL without a fragment"
                )
            # Mirror the pinned HIO sender's path/query rendering before signing.
            _, query = hio_httping.updateQargsQuery({}, target.query)
            if (
                not target.path
                or target.path.startswith("//")
                or quote(target.path) != target.path
                or query != target.query
            ):
                raise ValueError("HIO would rewrite the webhook URL path/query")
            if coring.Prefixer(qb64=self.webhook_aid).qb64 != self.webhook_aid:
                raise ValueError("webhook peer must be a canonical AID")
        if not self.rpc_url or self.chain_id <= 0:
            raise ValueError("verification requires an RPC URL and positive chain ID")
        if coring.Prefixer(qb64=self.trusted_geda_aid).qb64 != self.trusted_geda_aid:
            raise ValueError("trusted GEDA must be a canonical AID")
