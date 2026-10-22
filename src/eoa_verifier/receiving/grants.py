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

        for keys, notice in list(self.notifier.noter.notes.getItemIter()):
            attrs = notice.attrs
            if attrs.get("r") != "/exn/ipex/grant":
                self.notifier.noter.notes.rem(keys=keys)
                continue

            try:
                self.process_grant_notice(attrs)
            except (GrantNotReadyError, kering.MissingEntryError):
                continue
            except (ValueError, KeyError, TypeError, kering.ValidationError):
                traceback.print_exc()
                self.notifier.noter.notes.rem(keys=keys)
            else:
                self.notifier.noter.notes.rem(keys=keys)

    def process_grant_notice(self, attrs: dict[str, Any]) -> VerificationWork | None:
        """Parse one IPEX Grant notice and create or fail its operation.

        Embedded ``anc``, ``iss``, and ``acdc`` artifacts are replayed into the
        parser so the verifier store can materialize the association and
        recursive source chain. The association schema check happens early because
        the verifier accepts a pinned schema set, not whatever the sender provides.
        """

        grant_said = attrs["d"]
        exn, pathed = exchanging.cloneMessage(self.hby, said=grant_said)
        if exn is None:
            raise GrantNotReadyError(
                f"IPEX Grant {grant_said} not found in exchanger store"
            )
        embeds = exn.ked.get("e")
        if not isinstance(embeds, dict) or "acdc" not in embeds:
            raise ValueError(f"IPEX Grant {grant_said} has no embedded ACDC")

        # Validate the immutable identity before replay or operation creation.
        # IPEX authentication commits the envelope, not the ACDC's claimed SAID.
        creder = serdering.SerderACDC(sad=embeds["acdc"])
        for label in ("anc", "iss", "acdc"):
            if label not in embeds or label not in pathed:
                continue
            sadder = (
                creder if label == "acdc" else serdering.SerderKERI(sad=embeds[label])
            )
            ims = bytearray(sadder.raw)
            ims.extend(pathed[label])
            self.parser.parseOne(ims=ims)

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
