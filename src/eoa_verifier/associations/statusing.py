"""Detached status projection and its thin informational HTTP endpoint."""

from dataclasses import asdict

import falcon


class StatusQuery:
    """Build one stored association view without effects or work discovery."""

    def __init__(self, associations, verification, delivery):
        """Compose association, verification and delivery point reads explicitly."""
        self.associations, self.verification, self.delivery = (
            associations,
            verification,
            delivery,
        )

    def get(self, said):
        """Return a detached public view, or None for an unknown candidate."""
        associationStatus = self.associations.association(said)
        verificationResult = self.verification.verification_result(said)
        phase, verification = self.verification.verification_progress(said)
        deadLetterResult = self.associations.dead_acceptance(said)
        if associationStatus is not None:
            statusBody = asdict(associationStatus)
            delivery = (
                self.delivery.delivery(associationStatus.eventId)
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
            return None
        return statusBody


class StatusEnd:
    """Map the status query to GET /v1/associations/{said}/status."""

    def __init__(self, query):
        """Borrow the application status projection."""
        self.query = query

    def on_get(self, req, rep, said):
        """Return known status as JSON, or HTTP 404; never refresh chain state."""
        status = self.query.get(said)
        if status is None:
            raise falcon.HTTPNotFound(title="Unknown association")
        rep.media = status
