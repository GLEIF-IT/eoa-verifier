"""Public stored-status reads; no authentication, verification or network refresh."""

from dataclasses import asdict

import falcon


class StatusEnd:
    """Borrow the application store; GET is an informational view, not a signed event."""

    def __init__(self, baser):
        self.baser = baser

    def on_get(self, req, rep, said):
        """Handle GET /v1/associations/{said}/status without request signatures.

        Return HTTP 200 JSON for known pending, completed, accepted or revoked candidates;
        return 404 for unknown SAIDs. Observation timestamps/block identifiers are
        informational. This method reads stored records only and never calls RPC.
        """
        accepted = self.baser.associations.get(keys=(said,))
        result = self.baser.results.get(keys=(said,))
        pending = self.baser.pending.get(keys=(said,))
        if accepted is not None:
            data = asdict(accepted)
            event = self.baser.outbox.get(keys=(accepted.eventId,))
            data["delivery"] = {
                "eventId": event.eventId,
                "delivered": event.delivered,
                "attempts": event.attempts,
                "error": event.error,
            }
        elif result is not None:
            data = {
                "associationSaid": said,
                "status": result.outcome,
                "reason": result.reason,
                "observation": (
                    dict(
                        result.verified["observation"], wallet=result.verified["wallet"]
                    )
                    if result.verified
                    else None
                ),
            }
        elif pending is not None:
            data = {
                "associationSaid": said,
                "status": "pending",
                "reason": pending.reason,
                "observation": None,
            }
        else:
            raise falcon.HTTPNotFound(title="Unknown association")
        rep.media = data
