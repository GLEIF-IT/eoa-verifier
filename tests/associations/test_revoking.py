"""Direct and upstream revocation policy, fan-out, replay and dead letters."""

import json
from types import SimpleNamespace

import pytest
from keri.db import dbing

from eoa_verifier.persistence.registry import VerifierReger
from tests.support.acceptance import (
    accept_chained,
    accept_verified_result,
    revocation_service,
)


def test_missing_original_delivery_cannot_silently_revoke_locally(verified_store):
    """Local-only acceptance is explicit; a lost delivery obligation is corruption."""
    baser = verified_store
    associationStatus = accept_verified_result(baser)
    baser.outbox.rem(keys=(associationStatus.eventId,))
    with pytest.raises(ValueError, match="delivery event is absent"):
        revocation_service(baser).apply_revocation("association")
    assert baser.associations.get(keys=("association",)) == associationStatus
    assert baser.accepted_nonces.cntAll() == 1


@pytest.fixture
def reger(tmp_path):
    """Yield the real persistent revocation queue, without any KERIpy TEL simulation."""
    with dbing.openLMDB(
        cls=VerifierReger, name="upstream", headDirPath=str(tmp_path), temp=False
    ) as store:
        yield store


def service_for(baser, reger):
    """Compose the production revocation stages over the fixture's two stores."""
    return revocation_service(baser, SimpleNamespace(reger=reger))


def queue(reger, cred_said, tel_said="tel"):
    """Seed one accepted-TEL revocation record as VerifierReger.putTel would."""
    reger.revocations.put(keys=(cred_said,), val=tel_said)


def run_work(baser, service):
    """Advance Stage B until its durable work phase is empty."""
    while baser.revocation_work.cntAll():
        service.process_work()


def events_of(baser, said):
    """Return every outbox event ID for one association."""
    return sorted(
        event.eventId
        for _, event in baser.outbox.getItemIter()
        if event.associationSaid == said
    )


def test_le_revocation_revokes_every_accepted_association(verified_store, reger):
    """Stage A only queues; Stage B preserves facts and each original destination."""
    baser = verified_store
    saids = ("first", "second", "third")
    destinations = {said: f"https://receiver.example/{said}" for said in saids}
    accepted = {
        said: accept_chained(baser, said, destination=destinations[said])
        for said in saids
    }
    service = service_for(baser, reger)
    queue(reger, "le")
    service.process_one()
    assert reger.next_revocation() is None
    assert baser.revocation_work.cntAll() == 3
    assert all(baser.associations.get(keys=(s,)).status == "accepted" for s in saids)
    run_work(baser, service)
    for said in saids:
        status = baser.associations.get(keys=(said,))
        assert status.status == "revoked" and status.reason == "REVOKED"
        assert status.eventId == f"{said}:2"
        assert status.association == accepted[said].association
        assert status.accountObservation == accepted[said].accountObservation
        event = baser.outbox.get(keys=(status.eventId,))
        assert event.destination == destinations[said]
        body = json.loads(event.body)
        assert (body["statusRevision"], body["status"]) == (2, "revoked")
        assert body["reasonCode"] == "REVOKED"
        assert "revocationSource" not in body
        assert baser.delivery_ready.get(keys=(status.eventId,)) is not None
        assert status.revocationSource == {
            "credentialSaid": "le",
            "role": "le",
            "telEventSaid": "tel",
        }
    assert baser.accepted_nonces.get(keys=("first-nonce",)) is not None


def test_qvi_revocation_fans_out_across_its_les_only(verified_store, reger):
    """Three LEs under one QVI revoke six associations; another QVI's LE is untouched."""
    baser = verified_store
    chained = [
        accept_chained(baser, f"{le}-{n}", le=le).associationSaid
        for le in ("le-a", "le-b", "le-c")
        for n in (1, 2)
    ]
    other = accept_chained(baser, "other", le="le-d", qvi="other-qvi")
    service = service_for(baser, reger)
    queue(reger, "qvi", "qvi-tel")
    service.process_one()
    run_work(baser, service)
    assert all(baser.associations.get(keys=(s,)).status == "revoked" for s in chained)
    assert all(
        baser.associations.get(keys=(s,)).revocationSource
        == {"credentialSaid": "qvi", "role": "qvi", "telEventSaid": "qvi-tel"}
        for s in chained
    )
    assert baser.associations.get(keys=("other",)) == other
    assert events_of(baser, "other") == ["other:1"]


def test_unrelated_credential_is_acknowledged_with_no_writes(verified_store, reger):
    """A credential with no association or link row changes no application table."""
    baser = verified_store
    accept_chained(baser, "first")
    service = service_for(baser, reger)
    queue(reger, "same-schema-other-credential")
    before = baser.env.info()["last_txnid"]
    service.process_one()
    assert baser.env.info()["last_txnid"] == before
    assert reger.next_revocation() is None
    assert baser.revocation_work.cntAll() == 0
    assert baser.associations.get(keys=("first",)).status == "accepted"


def test_replay_and_double_cause_produce_one_event_each(verified_store, reger):
    """Duplicate records, LE-then-QVI and a direct revocation never add a second event."""
    baser = verified_store
    for said in ("replayed", "both", "direct"):
        accept_chained(baser, said)
    service = service_for(baser, reger)

    # The same association record applied directly, then its LE fan-out replayed.
    queue(reger, "direct", "direct-tel")
    service.process_one()
    direct_body = baser.outbox.get(keys=("direct:2",)).body

    # Fan-out: LE first, QVI before the worker runs; the first cause wins.
    queue(reger, "le", "le-tel")
    service.process_one()
    assert baser.revocation_work.get(keys=("direct",)) is not None
    queue(reger, "qvi", "qvi-tel")
    service.process_one()
    assert baser.revocation_work.get(keys=("both",)).sourceRole == "le"
    run_work(baser, service)
    bodies = {s: baser.outbox.get(keys=(f"{s}:2",)).body for s in ("replayed", "both")}

    # Same record again after everything has completed.
    queue(reger, "le", "le-tel")
    service.process_one()
    assert baser.revocation_work.cntAll() == 3
    run_work(baser, service)
    for said, body in bodies.items():
        assert events_of(baser, said) == [f"{said}:1", f"{said}:2"]
        assert baser.outbox.get(keys=(f"{said}:2",)).body == body
        assert baser.associations.get(keys=(said,)).revocationSource["role"] == "le"
    assert events_of(baser, "direct") == ["direct:1", "direct:2"]
    assert baser.outbox.get(keys=("direct:2",)).body == direct_body
    assert baser.associations.get(keys=("direct",)).revocationSource == {}


def test_local_only_association_revokes_without_an_event(verified_store, reger):
    """No original delivery obligation means revoked status and cause with no outbox row."""
    baser = verified_store
    accept_chained(baser, "local", destination=None)
    service = service_for(baser, reger)
    queue(reger, "le")
    service.process_one()
    run_work(baser, service)
    status = baser.associations.get(keys=("local",))
    assert status.status == "revoked" and status.eventId == ""
    assert baser.outbox.cntAll() == 0 and baser.delivery_ready.cntAll() == 0
    assert status.revocationSource["credentialSaid"] == "le"


def test_bad_association_dead_letters_while_others_revoke(verified_store, reger):
    """A lost revision-1 event stops one association; retry completes it after correction."""
    baser = verified_store
    bad = accept_chained(baser, "bad")
    good = accept_chained(baser, "good")
    original = baser.outbox.get(keys=(bad.eventId,))
    baser.outbox.rem(keys=(bad.eventId,))
    service = service_for(baser, reger)
    queue(reger, "le")
    service.process_one()
    run_work(baser, service)
    dead = baser.revocation_dead.get(keys=("bad",))
    assert dead.sourceSaid == "le" and "delivery event is absent" in dead.reason
    assert baser.associations.get(keys=("bad",)) == bad
    assert baser.associations.get(keys=("good",)).status == "revoked"
    assert good.eventId == "good:1"

    # A replayed fan-out does not resurrect stopped work without an operator.
    queue(reger, "le")
    service.process_one()
    assert baser.revocation_work.get(keys=("bad",)) is None

    baser.outbox.put(keys=(bad.eventId,), val=original)
    service.retry("bad")
    assert baser.revocation_dead.cntAll() == 0
    assert baser.revocation_work.get(keys=("bad",)).reason == ""
    run_work(baser, service)
    revived = baser.associations.get(keys=("bad",))
    assert revived.status == "revoked" and revived.revocationSource["role"] == "le"
    with pytest.raises(ValueError, match="unknown revocation dead letter"):
        service.retry("bad")


def test_failed_direct_revocation_does_not_wedge_the_shared_queue(verified_store, reger):
    """A lost revision-1 event dead-letters one direct revocation; later records proceed."""
    baser = verified_store
    bad = accept_chained(baser, "bad")
    good = accept_chained(baser, "good")
    original = baser.outbox.get(keys=(bad.eventId,))
    baser.outbox.rem(keys=(bad.eventId,))
    service = service_for(baser, reger)
    queue(reger, "bad")
    service.process_one()
    assert baser.associations.get(keys=("bad",)) == bad
    assert reger.revocations.cntAll() == 0

    queue(reger, "good")
    service.process_one()
    run_work(baser, service)
    dead = baser.revocation_dead.get(keys=("bad",))
    assert dead.sourceRole == "association" and "delivery event is absent" in dead.reason
    assert baser.associations.get(keys=("good",)).status == "revoked"
    assert good.eventId == "good:1"

    baser.outbox.put(keys=(bad.eventId,), val=original)
    service.retry("bad")
    run_work(baser, service)
    revived = baser.associations.get(keys=("bad",))
    assert revived.status == "revoked" and not revived.revocationSource
    assert baser.outbox.get(keys=("bad:2",)) is not None
