"""persistence/test_accepted_nonces.py."""

import subprocess
import sys

import falcon
import pytest
from falcon.testing import TestClient
from keri.db import dbing

from eoa_verifier.associations.statusing import StatusEnd
from eoa_verifier.persistence.basing import VerifierBaser
from eoa_verifier.persistence.records import (
    AcceptedNonce,
    VerificationRecord,
    VerificationResult,
)
from tests.support.issuers import candidate

WORKER = """
import os, sys
from keri.db import dbing
from eoa_verifier.persistence.basing import VerifierBaser
root, said, mode = sys.argv[1:]
with dbing.openLMDB(cls=VerifierBaser, name="process", headDirPath=root, temp=False) as baser:
    if mode == "race":
        print("ready", flush=True)
        sys.stdin.readline()
    elif mode == "abort":
        baser.associations.serializer = lambda value: os._exit(23)
    status = baser.accept(said, associationFacts={"issuerAid":"issuer"}, nonce="process-nonce",
                          destination="https://receiver.example/hook", peer_aid="peer")
    if mode == "commit":
        os._exit(24)
    print(status.status, flush=True)
"""


def verify(baser, said):
    """Seed only initial verification for storage-boundary tests, not intake qualification."""
    baser.enqueue(VerificationRecord(said, "grant"))
    baser.next_verification(now=0)
    baser.finish(
        VerificationResult(
            said, "verified", eoaResult={"wallet": "wallet", "accountObservation": {}}
        )
    )


def accept(baser, said, *, issuer="issuer", nonce="nonce", delivery=True):
    return baser.accept(
        said,
        associationFacts={"issuerAid": issuer},
        nonce=nonce,
        destination="https://receiver.example/hook" if delivery else None,
        peer_aid="peer" if delivery else None,
    )


@pytest.mark.parametrize("delivery", [False, True])
def test_exact_pair_scope_terminal_rejection_and_revocation(tmp_path, delivery):
    with dbing.openLMDB(
        cls=VerifierBaser, name="nonces", headDirPath=str(tmp_path), temp=False
    ) as baser:
        for said in (
            "first",
            "second",
            "issuer2",
            "uppercase",
            "lowercase",
            "maximum",
            "after-revocation",
        ):
            verify(baser, said)
        original = accept(baser, "first", delivery=delivery)
        assert accept(baser, "first", delivery=delivery) == original
        if not delivery:
            # Later delivery configuration does not fabricate an old obligation.
            assert accept(baser, "first", delivery=True) == original
            assert original.eventId == "" and baser.outbox.cntAll() == 0
        rejectedStatus = accept(baser, "second", delivery=delivery)
        assert (
            rejectedStatus.status,
            rejectedStatus.reason,
            rejectedStatus.eventId,
        ) == (
            "rejected",
            "NONCE_REUSED",
            "",
        )
        assert baser.results.get(keys=("second",)).status == "verified"
        assert baser.outbox.get(keys=("second:1",)) is None
        app = falcon.App()
        app.add_route("/v1/associations/{said}/status", StatusEnd(baser))
        client = TestClient(app)
        response = client.simulate_get("/v1/associations/second/status")
        assert response.status_code == 200
        assert response.json["reason"] == "NONCE_REUSED"
        assert response.json["delivery"] is None
        first = client.simulate_get("/v1/associations/first/status")
        assert first.status_code == 200 and first.json["status"] == "accepted"
        assert (first.json["delivery"] is not None) == delivery
        assert (
            accept(baser, "issuer2", issuer="other", delivery=delivery).status
            == "accepted"
        )
        for said, nonce in (
            ("uppercase", "Nonce"),
            ("lowercase", "nonce_"),
            ("maximum", "N" * 128),
        ):
            assert (
                accept(baser, said, nonce=nonce, delivery=delivery).status == "accepted"
            )
        assert baser.accepted_nonces.cntAll() == 5
        assert (
            baser.accepted_nonces.get(keys=("issuer", "nonce")).associationSaid
            == "first"
        )
        with baser.env.begin() as txn:
            assert txn.get(b"issuer.nonce", db=baser.accepted_nonces.sdb) is not None
        baser.retire("first")
        baser.close()
        baser.reopen()
        baser.validate_nonce_history()
        assert accept(baser, "first", delivery=delivery).status == "revoked"
        assert (
            accept(baser, "after-revocation", delivery=delivery).reason
            == "NONCE_REUSED"
        )
        assert (
            accept(baser, "second", nonce="different", delivery=delivery)
            == rejectedStatus
        )
        assert baser.outbox.cntAll() == (6 if delivery else 0)


@pytest.mark.parametrize(
    "corruption", ["json", "wrong-pair", "missing-owner", "wrong-owner"]
)
def test_inconsistent_claims_abort_acceptance(corruption):
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        verify(baser, "first")
        verify(baser, "candidate")
        accept(baser, "first")
        key = baser.nonce_key("issuer", "nonce")
        raw = {
            "json": b"{bad",
            "wrong-pair": baser.accepted_nonces.serializer(
                AcceptedNonce("issuer", "different", "first")
            ),
            "missing-owner": baser.accepted_nonces.serializer(
                AcceptedNonce("issuer", "nonce", "absent")
            ),
            "wrong-owner": baser.accepted_nonces.serializer(
                AcceptedNonce("other", "nonce", "first")
            ),
        }[corruption]
        with baser.env.begin(write=True) as txn:
            txn.put(key, raw, db=baser.accepted_nonces.sdb)
        with pytest.raises(ValueError, match="inconsistent"):
            accept(baser, "candidate")
        assert baser.associations.get(keys=("candidate",)) is None
        assert baser.outbox.get(keys=("candidate:1",)) is None
        with pytest.raises(ValueError, match="inconsistent"):
            baser.validate_nonce_history()


def test_populated_store_without_nonce_history_is_rejected():
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        baser.bind_verification_scope(trusted_geda_aid="geda", chain_id=1)
        verify(baser, "first")
        accept(baser, "first")
        baser.accepted_nonces.trim()
        with pytest.raises(ValueError, match="lack nonce history"):
            baser.bind_verification_scope(trusted_geda_aid="geda", chain_id=1)
        assert baser.associations.get(keys=("first",)).status == "accepted"


def test_old_scope_is_rejected_without_reading_or_migrating_acceptance():
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        with baser.env.begin(write=True) as txn:
            txn.put(
                b"verification",
                b'{"trustedGedaAid":"geda","chainId":1}',
                db=baser.scope.sdb,
            )
        with pytest.raises(ValueError, match="fresh store"):
            baser.bind_verification_scope(trusted_geda_aid="geda", chain_id=1)


@pytest.mark.parametrize("same_said", [False, True])
def test_independent_process_race_has_one_owner(tmp_path, same_said):
    options = dict(
        cls=VerifierBaser, name="process", headDirPath=str(tmp_path), temp=False
    )
    with dbing.openLMDB(**options) as baser:
        for i in range(4):
            verify(baser, str(i))
    processes = []
    try:
        for i in range(4):
            processes.append(
                subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        WORKER,
                        str(tmp_path),
                        "0" if same_said else str(i),
                        "race",
                    ],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            )
        for p in processes:
            assert p.stdout.readline().strip() == "ready"
        for p in processes:
            p.stdin.write("go\n")
            p.stdin.flush()
        outcomes = []
        for p in processes:
            out, err = p.communicate(timeout=15)
            assert p.returncode == 0, err
            outcomes.append(out.strip())
        assert sorted(outcomes) == (
            ["accepted"] * 4
            if same_said
            else ["accepted", "rejected", "rejected", "rejected"]
        )
    finally:
        for p in processes:
            if p.poll() is None:
                p.kill()
            p.wait(timeout=5)
    with dbing.openLMDB(**options) as baser:
        baser.validate_nonce_history()
        assert baser.accepted_nonces.cntAll() == baser.outbox.cntAll() == 1
        assert (
            sum(row.status == "accepted" for _, row in baser.associations.getItemIter())
            == 1
        )


def test_process_death_before_and_after_commit(tmp_path):
    options = dict(
        cls=VerifierBaser, name="process", headDirPath=str(tmp_path), temp=False
    )
    with dbing.openLMDB(**options) as baser:
        verify(baser, "first")
    for mode, exitcode in (("abort", 23), ("commit", 24)):
        result = subprocess.run(
            [sys.executable, "-c", WORKER, str(tmp_path), "first", mode],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == exitcode, result.stderr
        with dbing.openLMDB(**options) as baser:
            baser.validate_nonce_history()
            expected = int(mode == "commit")
            assert (
                baser.accepted_nonces.cntAll()
                == baser.associations.cntAll()
                == baser.outbox.cntAll()
                == expected
            )
            assert baser.results.get(keys=("first",)).status == "verified"
            if expected:
                original = baser.outbox.get(keys=("first:1",))
                assert not original.acknowledged
                assert accept(baser, "first").status == "accepted"
                assert baser.outbox.get(keys=("first:1",)) == original


@pytest.mark.parametrize(
    "nonce", ["x", "N" * 128, "aZ09_-", "25C89E61-21F8-4CCF-948D-46D1FBB7BAE8"]
)
def test_ascii_boundaries_are_preserved_in_lmdb(nonce):
    credential = candidate()
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        issuer = credential["i"]
        key = baser.nonce_key(issuer, nonce)
        assert key == f"{issuer}.{nonce}".encode("ascii")
        assert len(key) <= 173 < baser.env.max_key_size()


@pytest.mark.parametrize(
    "nonce",
    [
        "",
        "N" * 129,
        "é",
        "e\u0301",
        "😀",
        " nonce",
        "nonce ",
        "nonce.nonce",
        "nonce\n",
        "nonce\r",
        "nonce\x00",
        "nonce/",
        "nonce+",
        "nonce=",
        None,
        7,
    ],
)
def test_invalid_nonce_is_rejected_without_consumption(nonce):
    credential = candidate()
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        baser.enqueue(VerificationRecord("candidate", "grant"))
        baser.next_verification(now=0)
        baser.finish(
            VerificationResult(
                "candidate",
                "verified",
                eoaResult={"wallet": "wallet", "accountObservation": {}},
            )
        )
        with pytest.raises(ValueError, match="nonce"):
            baser.accept(
                "candidate",
                associationFacts={"issuerAid": credential["i"]},
                nonce=nonce,
            )
        assert (
            baser.accepted_nonces.cntAll()
            == baser.associations.cntAll()
            == baser.outbox.cntAll()
            == 0
        )
