"""Turn accepted IPEX Grant notifications into durable association work."""

from __future__ import annotations

import traceback
from typing import Any

from hio.base import doing
from keri import kering
from keri.core import serdering
from keri.peer import exchanging

from eoa_verifier.basing import VerificationWork, VerifierBaser


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
        expected_association_schema: str,
        **kwa,
    ):
        """Borrow a work store, Habery, native Notifier and shared inbound parser.

        expected_association_schema is the only accepted association schema SAID.
        The service owns these resources and schedules parser/escrow processing;
        this Doer only consumes notifications and creates work. kwa supplies HIO options.
        """
        self.baser = baser
        self.hby = hby
        self.notifier = notifier
        self.parser = parser
        self.expected_association_schema = expected_association_schema
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
        retain missing material. Unexpected parser/storage errors propagate and leave
        the failing notice intact. Return None; native notification storage is borrowed.
        """

        for notice, _ in self.notifier.noter.getNotes(end=-1):
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

    def process_grant_notice(self, attrs: dict[str, Any]) -> VerificationWork | None:
        """Replay a decoded Grant's anc/iss/acdc streams and return durable work.

        Only supplied embeds with attachments are replayed. Native parsing may escrow
        evidence; creating work does not assert acceptance. Repeated matching Grants
        retain existing work, including terminal status. A different schema records
        failure. GrantNotReadyError retains incomplete material; InvalidGrantError
        identifies decoding/native-validation failure. Other errors propagate.
        """

        grant_said, creder, streams = self._read_grant(attrs)
        for ims in streams:
            try:
                self.parser.parseOne(ims=ims)
            except kering.MissingEntryError as exc:
                raise GrantNotReadyError(str(exc)) from exc
            except kering.ValidationError as exc:
                raise InvalidGrantError(str(exc)) from exc

        acdc = creder.sad
        association_said = acdc["d"]
        association_schema = acdc.get("s", "")
        if association_schema != self.expected_association_schema:
            op = self.baser.start_verification(
                association_said=association_said,
                grant_said=grant_said,
            )
            return self.baser.mark_failed(
                op,
                f"association schema {association_schema} does not match expected {self.expected_association_schema}",
            )

        op = self.baser.start_verification(
            association_said=association_said,
            grant_said=grant_said,
        )
        return op

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
        except (ValueError, KeyError, TypeError, kering.ValidationError) as exc:
            raise InvalidGrantError(str(exc)) from exc
        return grant_said, creder, streams
