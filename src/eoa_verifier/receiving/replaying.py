"""One-item Grant replay policy over detached reads and short atomic saves."""

import time
from dataclasses import replace

from .grants import GrantNotReadyError, InvalidGrantError


class GrantReplayService:
    """Own retry budgets, phase priority and native/application sequencing."""

    def __init__(
        self,
        reader,
        writer,
        native=None,
        *,
        clock=time.time,
        retry_delay=5.0,
        max_attempts=3,
    ):
        """Borrow adapters; native is unnecessary for an offline manual retry."""
        self.reader, self.writer, self.native = reader, writer, native
        self.clock, self.retry_delay, self.max_attempts = (
            clock,
            retry_delay,
            max_attempts,
        )

    def process_one(self):
        """Persist one attempt before acknowledging/replaying its native notice."""
        notice = self.native.next_notice()
        if notice is not None and self.reader.dead_grant(notice.noticeId) is not None:
            self.native.remove_notice(notice.noticeId)
            return
        record = self.reader.active_grant()
        source = "active"
        if record is None:
            record = self.reader.waiting_grant()
            source = "waiting"
            if record is None or record.nextAttemptAt > self.clock():
                record, source = notice, None
        if record is None:
            return
        if record.attempts >= self.max_attempts:
            dead = replace(
                record,
                reason=record.reason
                or "Grant replay interrupted; attempt budget exhausted",
            )
            self.writer.move_grant(record, source, dead, "dead")
            self.native.remove_notice(record.noticeId)
            return
        active = replace(record, attempts=record.attempts + 1)
        self.writer.move_grant(record, source, active, "active")
        self.native.remove_notice(active.noticeId)
        try:
            verification = (
                self.native.replay(active.attrs)
                if active.attrs.get("r") == "/exn/ipex/grant"
                else None
            )
        except GrantNotReadyError as exc:
            target = "dead" if active.attempts >= self.max_attempts else "waiting"
            failed = replace(
                active,
                reason=str(exc) or type(exc).__name__,
                nextAttemptAt=self.clock() + self.retry_delay,
            )
            self.writer.move_grant(active, "active", failed, target)
        except InvalidGrantError as exc:
            failed = replace(active, reason=str(exc) or type(exc).__name__)
            self.writer.move_grant(active, "active", failed, "dead")
        else:
            self.writer.complete_grant(active, verification)

    def retry(self, notice_id):
        """Resume a corrected dead letter with a fresh budget; service must be stopped."""
        record = self.reader.dead_grant(notice_id)
        if record is None:
            raise ValueError("unknown Grant dead letter")
        waiting = replace(record, attempts=0, nextAttemptAt=0, reason="")
        self.writer.move_grant(record, "dead", waiting, "waiting")
