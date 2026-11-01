"""Persistent application record schemas; field names are part of the stored format."""

from dataclasses import dataclass, field


@dataclass
class VerificationRecord:
    """One credential's initial-verification work, with its phase supplied by the table.

    associationSaid identifies the candidate ACDC; grantSaid identifies its IPEX
    Grant EXN. attempts counts charged dispatches, including interrupted work.
    nextAttemptAt is a UTC Unix timestamp in seconds (zero means immediately due),
    not credential expiry. reason retains the latest retry/failure explanation.
    """

    associationSaid: str
    grantSaid: str
    reason: str = ""
    attempts: int = 0
    nextAttemptAt: float = 0.0


@dataclass
class GrantReplayRecord:
    """Copied KERIpy notification retained until replay settles or an operator intervenes.

    noticeId is the notification ID; attrs is its copied attribute dictionary,
    including the EXN reference. Referenced evidence can still be missing, so this
    record alone proves no credential validity. attempts counts replay attempts;
    nextAttemptAt is UTC Unix seconds and reason describes the latest deferral.
    """

    noticeId: str
    attrs: dict
    attempts: int = 0
    nextAttemptAt: float = 0.0
    reason: str = ""


@dataclass
class VerificationResult:
    """Completed initial check, distinct from acceptance, ownership and endorsement.

    associationSaid is the checked credential SAID. status is the service-selected
    verified/rejected outcome; reason explains rejection. On success eoaResult
    contains wallet and the initial accountObservation. Completion persists this
    result independently of any later acceptance-policy rejection or revocation.
    """

    associationSaid: str
    status: str  # Workflow-selected verified or rejected outcome.
    reason: str = ""
    eoaResult: dict = field(
        default_factory=dict
    )  # Wallet and initial account observation.


@dataclass
class VerificationScope:
    """Advisory baseline for the last startup's trust root and Ethereum network.

    trustedGedaAid is the configured GEDA AID; chainId is the integer network ID.
    A change produces a warning, never a storage gate or historical revalidation.
    The operator decides whether existing results and work may be reused.
    """

    trustedGedaAid: str
    chainId: int


@dataclass
class AcceptedNonce:
    """Diagnostic owner stored under an exact, permanently consumed nonce key.

    associationSaid names the accepted credential. The value is not needed to test
    reuse: existence of the key denies a different credential, regardless of issuer
    or value readability. Revocation and restart never release the nonce.
    """

    associationSaid: str


@dataclass
class AssociationStatus:
    """Local application outcome and the immutable facts checked at initial acceptance.

    associationSaid names the credential. status is accepted, rejected or revoked;
    reason explains a policy rejection or revocation. eventId is empty for a
    local-only outcome/rejection, otherwise credSaid:1 for acceptance or credSaid:2
    for revocation. association holds issuer, LE, wallet and issuance facts;
    accountObservation holds the initial RPC snapshot and wallet. Revocation keeps
    those original facts. There is no intrinsic expiry or continuing RPC refresh.

    Acceptance does not select Oracle ownership or publish an Ethereum endorsement.
    A NONCE_REUSED rejection leaves the separate verified initial result intact.
    """

    associationSaid: str
    status: str
    eventId: str
    association: dict
    accountObservation: dict
    reason: str = ""


@dataclass
class Delivery:
    """One immutable status-event body/target with mutable attempt progress.

    eventId identifies the revision of associationSaid. destination is its original
    URL; body is the exact UTF-8 JSON text to resend and sign. attempts is charged
    before I/O. delivered means a complete successful HTTP response, including
    verification of any supplied signature; no JSON acknowledgement is required.
    error retains the latest failure and blocked requires explicit operator recovery.
    Phase references, not a scan of these historical records, schedule work.
    """

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
    """Destination-wide pacing/backoff, keyed by the exact webhook URL.

    failures counts consecutive transient failures. nextAttemptAt is UTC Unix
    seconds and gates request starts, not association validity. Success resets
    failure backoff; manual retry does not erase an existing pacing deadline.
    """

    failures: int = 0
    nextAttemptAt: float = 0.0


@dataclass
class DeliveryReference:
    """Delivery-phase membership containing only the outbox eventId.

    Immutable body/target and attempt progress stay in Delivery. A reference moves
    between ready, the single active slot and dead-letter storage atomically with
    its corresponding outbox changes.
    """

    eventId: str
