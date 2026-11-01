"""Turn accepted IPEX Grant notifications into durable association work."""

from __future__ import annotations

from typing import Any

from hio.base import doing
from keri import kering
from keri.core import serdering
from keri.peer import exchanging

from eoa_verifier.persistence.records import GrantReplayRecord, VerificationRecord


class GrantNotReadyError(Exception):
    """KERIpy Grant material is not yet readable; retain its notice for a later turn."""


class InvalidGrantError(ValueError):
    """Grant decoding or KERIpy validation failed; report and consume its notice."""


class GrantNotificationDoer(doing.Doer):
    """Schedule one application replay operation per HIO turn."""

    def __init__(self, service, **kwa):
        """Borrow the replay service; resource ownership remains with the runtime."""
        self.service = service
        super().__init__(**kwa)

    def recur(self, tyme):
        """Advance one item and remain scheduled."""
        self.service.process_one()
        return False


class IpexGrantAdapter:
    """Read KERIpy notices and replay authenticated EXN embeds through KERIpy."""

    def __init__(self, hby, notifier, parser):
        """Borrow KERIpy stores and parser without assuming their lifecycle."""
        self.hby, self.notifier, self.parser = hby, notifier, parser

    def next_notice(self):
        """Detach the oldest KERIpy notice into an application Grant record."""
        noter = self.notifier.noter
        with noter.env.begin(db=noter.notes.sdb) as txn, txn.cursor() as cursor:
            notice = (
                noter.notes.klas(raw=bytes(cursor.value())) if cursor.first() else None
            )
        return GrantReplayRecord(notice.rid, notice.attrs) if notice else None

    def remove_notice(self, notice_id):
        """Acknowledge a KERIpy notice only after application work is durable."""
        self.notifier.noter.rem(notice_id)

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

    def replay(self, attrs: dict[str, Any]) -> VerificationRecord:
        """Replay a decoded Grant’s embeds and return detached verification work.

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

        return VerificationRecord(creder.said, grant_said)

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
