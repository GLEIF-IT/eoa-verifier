"""Turn accepted IPEX Grant notifications into durable association work."""

from __future__ import annotations

import traceback
from itertools import islice
from typing import Any

from hio.base import doing
from keri import kering
from keri.core import serdering
from keri.peer import exchanging

from eoa_verifier.basing import PendingVerification, VerifierBaser


class GrantNotReadyError(Exception):
    """Native Grant material is not yet readable; retain its notice for a later turn."""


class InvalidGrantError(ValueError):
    """Grant decoding or native validation failed; report and consume its notice."""


class GrantNotificationDoer(doing.Doer):
    """Turn authenticated native IPEX notifications into durable verification work.

    Accepted Grant signatures authenticate delivery; they do not establish native
    ACDC acceptance. Embedded evidence is replayed through the shared parser,
    which may escrow it. The coordinator separately checks credential acceptance.
    Missing Grant material leaves its notice pending for a later HIO turn.
    """

    def __init__(
        self,
        *,
        baser: VerifierBaser,
        hby,
        notifier,
        parser,
        **kwa,
    ):
        """Borrow a work store, Habery, native Notifier and shared inbound parser.

        The outer resource contexts own stores; the service schedules parser/escrows;
        this Doer only consumes notifications and creates work. kwa supplies HIO options.
        """
        self.baser = baser
        self.hby = hby
        self.notifier = notifier
        self.parser = parser
        self.scan_after = b""  # Native notice key; scheduling hint only.
        super().__init__(**kwa)

    def recur(self, tyme):
        """Process notices synchronously on this HIO turn and return False to remain scheduled."""

        _ = tyme
        self.process_notes()
        return False

    def process_notes(self) -> None:
        """Consume native notices with attrs.r routing and attrs.d naming the Grant EXN.

        Remove unrelated, successfully processed and invalid notices through Noter so
        indexes/signatures are cleaned together. Report invalid input with a traceback;
        retain missing material and advance past it. Read at most 32 notices per turn.
        Unexpected parser/storage errors propagate and leave
        the failing notice intact. Return None; native notification storage is borrowed.
        """

        batch = self._notice_batch()
        if not batch:
            self.scan_after = b""
        for key, notice in batch:
            self.scan_after = key
            attrs = notice.attrs
            if attrs.get("r") != "/exn/ipex/grant":
                self.notifier.noter.rem(notice.rid)
                continue

            try:
                self.process_grant_notice(attrs)
            except GrantNotReadyError:
                continue
            except InvalidGrantError:
                traceback.print_exc()
                self.notifier.noter.rem(notice.rid)
            else:
                self.notifier.noter.rem(notice.rid)

    def _notice_batch(self):
        """Seek past the last native key and copy at most 32 notices before mutation.

        Use a key cursor, not offset pagination that rescans the retained backlog.
        No read transaction survives processing; an empty page wraps next turn.
        """
        noter = self.notifier.noter
        with noter.env.begin(db=noter.notes.sdb) as txn:
            with txn.cursor() as cursor:
                if not cursor.set_range(self.scan_after):
                    return []
                if self.scan_after and cursor.key() == self.scan_after:
                    if not cursor.next():
                        return []
                return [
                    (bytes(key), noter.notes.klas(raw=bytes(raw)))
                    for key, raw in islice(cursor.iternext(), 32)
                ]

    def _replay_embed(self, ims):
        """Advance native parsing once for a complete, fixed embed frame.

        The native generator yields only for missing bytes. This private buffer
        cannot grow, so a yield is malformed input, not a reason to spin or wait.
        Keep native dispatch/escrow behavior and close even an incomplete generator.
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

        Only supplied embeds with attachments are replayed. Native parsing may escrow
        evidence; creating work does not assert acceptance. Repeated matching Grants
        preserve pending work and completed results. Schema-policy outcomes belong
        to the coordinator. GrantNotReadyError retains incomplete material; InvalidGrantError
        identifies decoding/native-validation failure. Other errors propagate.
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
        """Return (Grant SAID, native ACDC, replay bytearrays) from notification attributes.

        Clone and verify the native EXN, then validate the embedded ACDC identity before
        any replay or work creation. Missing native material raises GrantNotReadyError;
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
