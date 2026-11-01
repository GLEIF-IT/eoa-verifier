"""One-item Grant replay policy over detached reads and short atomic saves."""

import time
from dataclasses import replace

from .grants import GrantNotReadyError, InvalidGrantError


class GrantReplayService:
    """Own retry budgets, phase priority and KERIpy/application sequencing."""

    def __init__(
        self,
        reader,
        writer,
        grant_adapter=None,
        *,
        clock=time.time,
        retry_delay=5.0,
        max_attempts=3,
    ):
        """Borrow adapters; grant_adapter is unnecessary for an offline manual retry."""
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        self.reader, self.writer, self.grant_adapter = reader, writer, grant_adapter
        self.clock, self.retry_delay, self.max_attempts = (
            clock,
            retry_delay,
            max_attempts,
        )

    def process_one(self):
        """Persist one attempt before acknowledging/replaying its KERIpy notice."""
        notice = self.grant_adapter.next_notice()
        if notice is not None and self.reader.dead_grant(notice.noticeId) is not None:
            self.grant_adapter.remove_notice(notice.noticeId)
            return
        record = self.reader.active_grant()
        if record is not None:
            if record.attempts >= self.max_attempts:
                dead = replace(
                    record,
                    reason=record.reason
                    or "Grant replay interrupted; attempt budget exhausted",
                )
                self.writer.dead_letter_grant(record, dead)
                self.grant_adapter.remove_notice(record.noticeId)
                return
            active = replace(record, attempts=record.attempts + 1)
            self.writer.resume_grant(record, active)
        else:
            record = self.reader.waiting_grant()
            if record is not None and record.nextAttemptAt <= self.clock():
                if record.attempts >= self.max_attempts:
                    dead = replace(
                        record,
                        reason=record.reason
                        or "Grant replay interrupted; attempt budget exhausted",
                    )
                    self.writer.dead_letter_waiting_grant(record, dead)
                    self.grant_adapter.remove_notice(record.noticeId)
                    return
                active = replace(record, attempts=record.attempts + 1)
                self.writer.activate_waiting_grant(record, active)
            elif notice is not None:
                active = replace(notice, attempts=1)
                self.writer.start_grant(active)
            else:
                return
        self.grant_adapter.remove_notice(active.noticeId)
        try:
            verification = (
                self.grant_adapter.replay(active.attrs)
                if active.attrs.get("r") == "/exn/ipex/grant"
                else None
            )
        except GrantNotReadyError as exc:
            failed = replace(
                active,
                reason=str(exc) or type(exc).__name__,
                nextAttemptAt=self.clock() + self.retry_delay,
            )
            if active.attempts >= self.max_attempts:
                self.writer.dead_letter_grant(active, failed)
            else:
                self.writer.defer_grant(active, failed)
        except InvalidGrantError as exc:
            failed = replace(active, reason=str(exc) or type(exc).__name__)
            self.writer.dead_letter_grant(active, failed)
        else:
            if verification is None:
                self.writer.discard_unrelated_notice(active)
            else:
                self.writer.complete_grant(active, verification)

    def retry(self, notice_id):
        """Resume a corrected dead letter with a fresh budget; service must be stopped."""
        record = self.reader.dead_grant(notice_id)
        if record is None:
            raise ValueError("unknown Grant dead letter")
        waiting = replace(record, attempts=0, nextAttemptAt=0, reason="")
        self.writer.retry_dead_grant(record, waiting)
