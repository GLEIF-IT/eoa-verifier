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
        associationStatus = self.baser.associations.get(keys=(said,))
        verificationResult = self.baser.results.get(keys=(said,))
        phase, verification = self.baser.verification_progress(said)
        deadLetterResult = self.baser.acceptance_dead.get(keys=(said,))
        if associationStatus is not None:
            statusBody = asdict(associationStatus)
            delivery = (
                self.baser.outbox.get(keys=(associationStatus.eventId,))
                if associationStatus.eventId
                else None
            )
            statusBody["delivery"] = (
                {
                    "eventId": delivery.eventId,
                    "acknowledged": delivery.acknowledged,
                    "attempts": delivery.attempts,
                    "error": delivery.error,
                    "blocked": delivery.blocked,
                }
                if delivery is not None
                else None
            )
        elif deadLetterResult is not None:
            statusBody = {
                "associationSaid": said,
                "status": "dead-letter",
                "phase": "acceptance",
                "reason": deadLetterResult.reason,
                "accountObservation": None,
            }
        elif verificationResult is not None:
            statusBody = {
                "associationSaid": said,
                "status": verificationResult.status,
                "reason": verificationResult.reason,
                "accountObservation": (
                    dict(
                        verificationResult.eoaResult["accountObservation"],
                        wallet=verificationResult.eoaResult["wallet"],
                    )
                    if verificationResult.eoaResult
                    else None
                ),
            }
        elif verification is not None:
            statusBody = {
                "associationSaid": said,
                "status": phase,
                "reason": verification.reason,
                "attempts": verification.attempts,
                "nextAttemptAt": verification.nextAttemptAt,
                "accountObservation": None,
            }
        else:
            raise falcon.HTTPNotFound(title="Unknown association")
        rep.media = statusBody
