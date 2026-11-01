"""Persistent application record schemas; field names are part of the stored format."""

from dataclasses import dataclass, field


@dataclass
class VerificationRecord:
    """Verification retry metadata; table membership identifies its durable phase."""

    associationSaid: str
    grantSaid: str
    reason: str = ""
    attempts: int = 0
    nextAttemptAt: float = 0.0


@dataclass
class GrantReplayRecord:
    """Authenticated notice retained until replay succeeds or an operator intervenes."""

    noticeId: str
    attrs: dict
    attempts: int = 0
    nextAttemptAt: float = 0.0
    reason: str = ""


@dataclass
class VerificationResult:
    """Completed initial check, not application acceptance, ownership or endorsement."""

    associationSaid: str
    status: str  # Workflow-selected verified or rejected outcome.
    reason: str = ""
    eoaResult: dict = field(
        default_factory=dict
    )  # Wallet and initial account observation.


@dataclass
class VerificationScope:
    """Last observed trust/network settings, used only for startup warnings."""

    trustedGedaAid: str
    chainId: int


@dataclass
class AcceptedNonce:
    """Accepted credential recorded under its permanently consumed nonce key."""

    associationSaid: str


@dataclass
class AssociationStatus:
    """Stored application acceptance and immutable initially verified association.

    Acceptance is not oracle ownership selection or an Ethereum endorsement.
    There is no expiry; verified association revocation changes status explicitly.
    Policy rejections use status rejected, reason NONCE_REUSED and no event ID;
    the independent initial VerificationResult remains verified.
    """

    associationSaid: str
    status: str
    eventId: str
    association: dict
    accountObservation: dict
    reason: str = ""


@dataclass
class Delivery:
    """One immutable event body/target with separately mutable attempt progress."""

    eventId: str
    associationSaid: str
    destination: str
    body: str
    delivered: bool = False
    attempts: int = 0
    error: str = ""
    # Permanent failure; requires correction and explicit resumption.
    blocked: bool = False


@dataclass
class DestinationSchedule:
    """Persisted destination-wide cooldown and consecutive transient-failure count.

    nextAttemptAt is UTC Unix seconds, not an association-validity deadline.
    """

    failures: int = 0
    nextAttemptAt: float = 0.0


@dataclass
class DeliveryReference:
    """One event's membership in a delivery phase; bytes remain in the outbox."""

    eventId: str
