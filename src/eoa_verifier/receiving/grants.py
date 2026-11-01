"""Turn accepted IPEX Grant notifications into durable association work."""

from __future__ import annotations

import time
from typing import Any

from hio.base import doing
from keri import kering
from keri.core import serdering
from keri.peer import exchanging

from eoa_verifier.persistence.basing import VerifierBaser
from eoa_verifier.persistence.records import PendingVerification


class GrantNotReadyError(Exception):
    """KERIpy Grant material is not yet readable; retain its notice for a later turn."""


class InvalidGrantError(ValueError):
    """Grant decoding or KERIpy validation failed; report and consume its notice."""


class GrantNotificationDoer(doing.Doer):
    """Turn authenticated IPEX notifications into durable verification work.

    Accepted Grant signatures authenticate delivery; they do not establish KERIpy
    ACDC acceptance. Embedded evidence is replayed through the shared parser,
    which may escrow it. The coordinator separately checks credential acceptance.
    Missing Grant material moves to durable waiting with a finite retry budget.
    """

    def __init__(
        self,
        *,
        baser: VerifierBaser,
        hby,
        notifier,
        parser,
        clock=time.time,
        retry_delay=5.0,
        max_attempts=3,
        **kwa,
    ):
        """Borrow a work store, Habery, KERIpy Notifier and shared inbound parser.

        The outer resource contexts own stores; the service schedules parser/escrows;
        this Doer only consumes notifications and creates work. kwa supplies HIO options.
        """
        self.baser = baser
        self.hby = hby
        self.notifier = notifier
        self.parser = parser
        self.clock, self.retry_delay, self.max_attempts = (
            clock,
            retry_delay,
            max_attempts,
        )
        super().__init__(**kwa)

    def recur(self, tyme):
        """Process notices synchronously on this HIO turn and return False to remain scheduled."""

        _ = tyme
        self.process_notes()
        return False

    def process_notes(self) -> None:
        """Handoff and replay at most one notice; missing material cannot block fresh notices.

        Active work is durable before the native notice is removed. Replay and
        enqueue are idempotent if interruption occurs before acknowledgement.
        Missing material waits on a persistent UTC deadline; three attempts exhaust
        the budget. Invalid material goes directly to a diagnostic dead letter.
        """
        noter = self.notifier.noter
        with noter.env.begin(db=noter.notes.sdb) as txn, txn.cursor() as cursor:
            notice = (
                noter.notes.klas(raw=bytes(cursor.value())) if cursor.first() else None
            )
        work = self.baser.begin_grant(
            notice, now=self.clock(), max_attempts=self.max_attempts
        )
        if work is None:
            # Recover interruption before acknowledging a notice whose final
            # replay attempt was already charged and subsequently dead-lettered.
            if notice is not None and self.baser.grant_dead.get(keys=(notice.rid,)):
                noter.rem(notice.rid)
            return
        noter.rem(work.noticeId)
        try:
            if work.attrs.get("r") == "/exn/ipex/grant":
                self.process_grant_notice(work.attrs)
        except GrantNotReadyError as exc:
            self.baser.settle_grant(
                work,
                reason=str(exc) or type(exc).__name__,
                next_attempt_at=self.clock() + self.retry_delay,
                max_attempts=self.max_attempts,
            )
        except InvalidGrantError as exc:
            self.baser.settle_grant(
                work, reason=str(exc) or type(exc).__name__, invalid=True
            )
        else:
            self.baser.settle_grant(work)

    def _replay_embed(self, ims):
        """Advance KERIpy parsing once for a complete, fixed embed frame.

        The KERIpy generator yields only for missing bytes. This private buffer
        cannot grow, so a yield is malformed input, not a reason to spin or wait.
        Keep KERIpy dispatch/escrow behavior and close even an incomplete generator.
        """
        parser = self.parser.onceParsator(ims=ims, framed=True)
        try:
            try:
                next(parser)
            except StopIteration:
                if ims:
                    raise InvalidGrantError("trailing material in Grant embed")
            else:
                raise InvalidGrantError("incomplete Grant embed attachments")
        finally:
            parser.close()

    def process_grant_notice(self, attrs: dict[str, Any]) -> None:
        """Replay a decoded Grant’s embeds and enqueue a candidate for verification.

        Only supplied embeds with attachments are replayed. KERIpy parsing may escrow
        evidence; creating work does not assert acceptance. Repeated matching Grants
        preserve pending work and completed results. Schema-policy outcomes belong
        to the coordinator. GrantNotReadyError retains incomplete material; InvalidGrantError
        identifies decoding/KERIpy-validation failure. Other errors propagate.
        """

        grant_said, creder, streams = self._read_grant(attrs)
        for ims in streams:
            try:
                self._replay_embed(ims)
            except kering.MissingEntryError as exc:
                raise GrantNotReadyError(str(exc)) from exc
            except kering.ValidationError as exc:
                raise InvalidGrantError(str(exc)) from exc

        self.baser.enqueue(PendingVerification(creder.said, grant_said))

    def _read_grant(self, attrs):
        """Return (Grant SAID, KERIpy ACDC, replay bytearrays) from notification attributes.

        Clone and verify the KERIpy EXN, then validate the embedded ACDC identity before
        any replay or work creation. Missing KERIpy material raises GrantNotReadyError;
        malformed serialized input raises InvalidGrantError. Broad decoding exceptions
        are confined here, outside parser execution and persistence.
        """
        grant_said = attrs.get("d")
        if not isinstance(grant_said, str) or not grant_said:
            raise InvalidGrantError("IPEX Grant notification has no message SAID")
        try:
            exn, pathed = exchanging.cloneMessage(self.hby, said=grant_said)
        except kering.MissingEntryError as exc:
            raise GrantNotReadyError(str(exc)) from exc
        except kering.ValidationError as exc:
            raise InvalidGrantError(str(exc)) from exc
        if exn is None:
            raise GrantNotReadyError(
                f"IPEX Grant {grant_said} not found in exchanger store"
            )

        # Only decoding errors are bad input. Programming or persistence errors
        # in replay/work creation must surface without consuming the notice.
        try:
            embeds = exn.ked.get("e")
            if not isinstance(embeds, dict) or "acdc" not in embeds:
                raise InvalidGrantError(f"IPEX Grant {grant_said} has no embedded ACDC")
            # IPEX authentication commits the envelope, not the ACDC's claimed SAID.
            creder = serdering.SerderACDC(sad=embeds["acdc"])
            streams = []
            for label in ("anc", "iss", "acdc"):
                if label not in embeds or label not in pathed:
                    continue
                sadder = (
                    creder
                    if label == "acdc"
                    else serdering.SerderKERI(sad=embeds[label])
                )
                streams.append(bytearray(sadder.raw) + pathed[label])
        except (
            ValueError,
            KeyError,
            TypeError,
            kering.ValidationError,
            kering.MaterialError,
            kering.ExtractionError,
            kering.SerializeError,
        ) as exc:
            raise InvalidGrantError(str(exc)) from exc
        return grant_said, creder, streams
