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
    """Raised when a grant notification arrives before its EXN material is readable."""


class InvalidGrantError(ValueError):
    """A malformed or invalid Grant cannot create verification work."""


class GrantNotificationDoer(doing.Doer):
    """Convert accepted IPEX Grant notices into durable pending operations.

    KERIpy's grant sender streams attachments before the EXN notice can be
    processed. When the notice is visible before the exchanger can clone all
    material, the Doer leaves the notice in place and retries on a later recur.
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
        self.baser = baser
        self.hby = hby
        self.notifier = notifier
        self.parser = parser
        self.expected_association_schema = expected_association_schema
        super().__init__(**kwa)

    def recur(self, tyme):
        """Poll for new grant notices on each HIO scheduler turn."""

        _ = tyme
        self.process_notes()
        return False

    def process_notes(self) -> None:
        """Consume accepted association Grant notices."""

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
        """Parse one IPEX Grant notice and create or fail its operation.

        Embedded ``anc``, ``iss``, and ``acdc`` artifacts are replayed into the
        parser so the verifier store can materialize the association and
        recursive source chain. The association schema check happens early because
        the verifier accepts a pinned schema set, not whatever the sender provides.
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
        """Decode the native envelope before replay or durable work creation."""
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
