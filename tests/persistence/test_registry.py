"""Atomic native TEL handoffs and idempotent application retirement."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from keri import core
from keri.db import dbing
from keri.vdr import eventing

from eoa_verifier.associations.retiring import RetirementDoer
from eoa_verifier.persistence.registry import VerifierReger
from tests.support.acceptance import accept_verified_result


def revocation(*, backers=False):
    """Make a syntactic TEL event; integration tests separately establish native validation."""
    said = core.Diger(ser=b"credential").qb64
    registry = core.Diger(ser=b"registry").qb64
    digest = core.Diger(ser=b"issuance").qb64
    if backers:
        return eventing.backerRevoke(said, registry, 0, registry, digest)
    return eventing.revoke(said, registry, digest)


@pytest.mark.parametrize("backers", [False, True])
def test_accepted_tel_and_handoff_survive_reopen(tmp_path, backers):
    """Both native revocation variants commit one handoff; native replay cannot recreate it."""
    with dbing.openLMDB(
        cls=VerifierReger, name="handoff", headDirPath=str(tmp_path), temp=False
    ) as reger:
        event = revocation(backers=backers)
        key = dbing.snKey(event.pre, event.sn)
        reger.putTvt(dbing.dgKey(event.pre, event.said), event.raw)
        assert reger.putTel(key, event.saidb)
        reger.close()
        reger.reopen()
        assert bytes(reger.getTel(key)) == event.saidb
        assert reger.next_revocation() == (event.pre, event.said)
        reger.revocations.rem(keys=(event.pre,))
        assert not reger.putTel(key, event.saidb)
        assert reger.next_revocation() is None


def test_failed_handoff_write_rolls_back_native_acceptance():
    """A fault after the TEL index write commits neither index nor handoff."""
    with dbing.openLMDB(cls=VerifierReger) as reger:
        event = revocation()
        key = dbing.snKey(event.pre, event.sn)
        reger.putTvt(dbing.dgKey(event.pre, event.said), event.raw)
        real = reger.env

        class Transaction:
            def __enter__(self):
                self.txn = real.begin(write=True)
                return self

            def __exit__(self, kind, value, traceback):
                self.txn.abort() if kind else self.txn.commit()

            def get(self, *args, **kwargs):
                return self.txn.get(*args, **kwargs)

            def put(self, *args, **kwargs):
                if kwargs["db"] == reger.revocations.sdb:
                    raise RuntimeError("handoff unavailable")
                return self.txn.put(*args, **kwargs)

        with (
            patch.object(
                reger, "env", SimpleNamespace(begin=lambda **kwargs: Transaction())
            ),
            pytest.raises(RuntimeError, match="handoff unavailable"),
        ):
            reger.putTel(key, event.saidb)
        assert reger.getTel(key) is None
        assert reger.next_revocation() is None
        assert reger.putTel(key, event.saidb)


def test_retirement_ack_gap_repeats_only_the_same_event(verified_store, tmp_path):
    """Reopening after application commit repeats its exact event before clearing the handoff."""
    baser = verified_store
    accepted = accept_verified_result(baser)
    with dbing.openLMDB(
        cls=VerifierReger, name="retirement", headDirPath=str(tmp_path), temp=False
    ) as reger:
        reger.revocations.put(keys=("association",), val="revocation")
        worker = RetirementDoer(baser=baser, rgy=SimpleNamespace(reger=reger))
        with (
            patch.object(
                reger.revocations,
                "rem",
                side_effect=RuntimeError("interrupted acknowledgement"),
            ),
            pytest.raises(RuntimeError, match="interrupted acknowledgement"),
        ):
            worker.recur(0)
        retired = baser.associations.get(keys=("association",))
        assert (
            retired.status == "revoked" and retired.association == accepted.association
        )
        body = baser.outbox.get(keys=(retired.eventId,)).body
        baser.close()
        baser.reopen()
        reger.close()
        reger.reopen()
        worker.recur(0)
        assert reger.next_revocation() is None
        assert baser.outbox.get(keys=(retired.eventId,)).body == body
        assert baser.outbox.cntAll() == 2
