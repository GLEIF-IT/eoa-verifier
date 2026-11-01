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

    def next_active(self):
        """Read one interrupted Grant without changing its attempt count."""
        return self.reader.active()

    def next_waiting(self):
        """Read one due Grant retry without consuming its deadline index."""
        record = self.reader.waiting()
        return (
            record
            if record is not None and record.nextAttemptAt <= self.clock()
            else None
        )

    def next_notice(self):
        """Read one detached KERIpy notice without acknowledging it."""
        return self.grant_adapter.next_notice()

    def resume_active(self, record):
        """Charge interrupted Grant replay or stop its exhausted attempt budget."""
        if record.attempts >= self.max_attempts:
            dead = replace(
                record,
                reason=record.reason
                or "Grant replay interrupted; attempt budget exhausted",
            )
            self.writer.active_to_dead(record, dead)
            self.grant_adapter.remove_notice(record.noticeId)
            return None
        active = replace(record, attempts=record.attempts + 1)
        self.writer.resume(record, active)
        return active

    def retry_waiting(self, record):
        """Charge due Grant replay or move exhausted waiting work to dead letters."""
        if record.nextAttemptAt > self.clock():
            raise ValueError("Grant retry is not due")
        if record.attempts >= self.max_attempts:
            dead = replace(
                record,
                reason=record.reason
                or "Grant replay interrupted; attempt budget exhausted",
            )
            self.writer.waiting_to_dead(record, dead)
            self.grant_adapter.remove_notice(record.noticeId)
            return None
        active = replace(record, attempts=record.attempts + 1)
        self.writer.waiting_to_active(record, active)
        return active

    def start_notice(self, notice):
        """Persist one new KERIpy notice before acknowledging or replaying it."""
        active = replace(notice, attempts=1)
        self.writer.start(active)
        return active

    def process_one(self):
        """Schedule one interrupted, due or new Grant; never fall through after failure."""
        notice = self.next_notice()
        if notice is not None and self.reader.dead(notice.noticeId) is not None:
            self.grant_adapter.remove_notice(notice.noticeId)
            return
        if (record := self.next_active()) is not None:
            active = self.resume_active(record)
        elif (record := self.next_waiting()) is not None:
            active = self.retry_waiting(record)
        elif notice is not None:
            active = self.start_notice(notice)
        else:
            return
        if active is not None:
            self.replay(active)

    def replay(self, active):
        """Acknowledge durable work, then replay and commit its explicit outcome."""
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
                self.writer.active_to_dead(active, failed)
            else:
                self.writer.active_to_waiting(active, failed)
        except InvalidGrantError as exc:
            failed = replace(active, reason=str(exc) or type(exc).__name__)
            self.writer.active_to_dead(active, failed)
        else:
            if verification is None:
                self.writer.discard_notice(active)
            else:
                self.writer.complete(active, verification)

    def retry(self, notice_id):
        """Resume a corrected dead letter with a fresh budget; service must be stopped."""
        record = self.reader.dead(notice_id)
        if record is None:
            raise ValueError("unknown Grant dead letter")
        waiting = replace(record, attempts=0, nextAttemptAt=0, reason="")
        self.writer.dead_to_waiting(record, waiting)
