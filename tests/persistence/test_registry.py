"""Atomic KERIpy TEL revocation records and idempotent application revocation."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from keri import core
from keri.db import dbing
from keri.vdr import eventing

from eoa_verifier.associations.revoking import RevocationDoer, RevocationWorkDoer
from eoa_verifier.persistence.registry import VerifierReger
from tests.support.acceptance import (
    accept_chained,
    accept_verified_result,
    revocation_service,
)


def revocation_serder(*, backers=False):
    """Make a syntactic TEL event; integration tests separately establish KERIpy validation."""
    credSaid = core.Diger(ser=b"credential").qb64
    registryId = core.Diger(ser=b"registry").qb64
    issuanceTelSaid = core.Diger(ser=b"issuance").qb64
    if backers:
        return eventing.backerRevoke(
            credSaid, registryId, 0, registryId, issuanceTelSaid
        )
    return eventing.revoke(credSaid, registryId, issuanceTelSaid)


@pytest.mark.parametrize("backers", [False, True])
def test_accepted_tel_and_revocation_record_survive_reopen(tmp_path, backers):
    """Both KERIpy revocation variants commit one revocation record; KERIpy replay cannot recreate it."""
    with dbing.openLMDB(
        cls=VerifierReger,
        name="revocation_record",
        headDirPath=str(tmp_path),
        temp=False,
    ) as reger:
        telSerder = revocation_serder(backers=backers)
        key = dbing.snKey(telSerder.pre, telSerder.sn)
        reger.putTvt(dbing.dgKey(telSerder.pre, telSerder.said), telSerder.raw)
        assert reger.putTel(key, telSerder.saidb)
        reger.close()
        reger.reopen()
        assert bytes(reger.getTel(key)) == telSerder.saidb
        assert reger.next_revocation() == (telSerder.pre, telSerder.said)
        reger.revocations.rem(keys=(telSerder.pre,))
        assert not reger.putTel(key, telSerder.saidb)
        assert reger.next_revocation() is None


def test_failed_revocation_record_write_rolls_back_keripy_acceptance():
    """A fault after the TEL index write commits neither index nor revocation record."""
    with dbing.openLMDB(cls=VerifierReger) as reger:
        telSerder = revocation_serder()
        key = dbing.snKey(telSerder.pre, telSerder.sn)
        reger.putTvt(dbing.dgKey(telSerder.pre, telSerder.said), telSerder.raw)
        real = reger.env

        class Transaction:
            """Delegate TEL-index writes and refuse the associated revocation-record write."""
            def __enter__(self):
                """Open a real test-owned LMDB write transaction and return this wrapper."""
                self.txn = real.begin(write=True)
                return self

            def __exit__(self, kind, value, traceback):
                """Abort on an exception or commit on normal exit, preserving real LMDB atomicity."""
                self.txn.abort() if kind else self.txn.commit()

            def get(self, *args, **kwargs):
                """Read through the underlying transaction without emulating database state."""
                return self.txn.get(*args, **kwargs)

            def put(self, *args, **kwargs):
                """Refuse revocation-record storage while allowing the preceding TEL-index write to execute."""
                if kwargs["db"] == reger.revocations.sdb:
                    raise RuntimeError("revocation record unavailable")
                return self.txn.put(*args, **kwargs)

        with (
            patch.object(
                reger, "env", SimpleNamespace(begin=lambda **kwargs: Transaction())
            ),
            pytest.raises(RuntimeError, match="revocation record unavailable"),
        ):
            reger.putTel(key, telSerder.saidb)
        assert reger.getTel(key) is None
        assert reger.next_revocation() is None
        assert reger.putTel(key, telSerder.saidb)


def test_revocation_ack_gap_repeats_only_the_same_event(verified_store, tmp_path):
    """Reopening after application commit repeats its exact event before clearing the revocation record."""
    baser = verified_store
    associationStatus = accept_verified_result(baser)
    with dbing.openLMDB(
        cls=VerifierReger, name="revocation", headDirPath=str(tmp_path), temp=False
    ) as reger:
        reger.revocations.put(keys=("association",), val="revocation")
        revocationDoer = RevocationDoer(
            revocation_service(baser, SimpleNamespace(reger=reger))
        )
        with (
            patch.object(
                reger.revocations,
                "rem",
                side_effect=RuntimeError("interrupted acknowledgement"),
            ),
            pytest.raises(RuntimeError, match="interrupted acknowledgement"),
        ):
            revocationDoer.recur(0)
        revokedStatus = baser.associations.get(keys=("association",))
        assert (
            revokedStatus.status == "revoked"
            and revokedStatus.association == associationStatus.association
        )
        body = baser.outbox.get(keys=(revokedStatus.eventId,)).body
        baser.close()
        baser.reopen()
        reger.close()
        reger.reopen()
        revocationDoer.recur(0)
        assert reger.next_revocation() is None
        assert baser.outbox.get(keys=(revokedStatus.eventId,)).body == body
        assert baser.outbox.cntAll() == 2


def test_upstream_ack_gap_recreates_work_without_a_second_event(verified_store, tmp_path):
    """Crash after Stage A commit: replay finds finished work and rewrites no event."""
    baser = verified_store
    for said in ("first", "second"):
        accept_chained(baser, said)
    with dbing.openLMDB(
        cls=VerifierReger, name="upstream", headDirPath=str(tmp_path), temp=False
    ) as reger:
        reger.revocations.put(keys=("le",), val="revocation")
        service = revocation_service(baser, SimpleNamespace(reger=reger))
        doer, worker = RevocationDoer(service), RevocationWorkDoer(service)
        with (
            patch.object(
                reger.revocations,
                "rem",
                side_effect=RuntimeError("interrupted acknowledgement"),
            ),
            pytest.raises(RuntimeError, match="interrupted acknowledgement"),
        ):
            doer.recur(0)
        assert reger.next_revocation() == ("le", "revocation")
        assert baser.revocation_work.cntAll() == 2
        worker.recur(0)
        worker.recur(0)
        bodies = {said: baser.outbox.get(keys=(f"{said}:2",)).body for said in ("first", "second")}
        events = baser.outbox.cntAll()
        baser.close()
        baser.reopen()
        reger.close()
        reger.reopen()
        doer.recur(0)
        assert reger.next_revocation() is None
        assert baser.revocation_work.cntAll() == 2  # Recreated, then discarded unapplied.
        worker.recur(0)
        worker.recur(0)
        assert baser.revocation_work.cntAll() == 0
        assert baser.outbox.cntAll() == events
        assert {
            said: baser.outbox.get(keys=(f"{said}:2",)).body for said in ("first", "second")
        } == bodies
