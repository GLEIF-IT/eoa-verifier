"""persistence/test_accepted_nonces.py."""

import subprocess
import sys

import falcon
import pytest
from falcon.testing import TestClient
from keri.db import dbing

from eoa_verifier.associations.statusing import StatusEnd, StatusQuery
from eoa_verifier.persistence.basing import VerifierBaser
from eoa_verifier.persistence.keys import nonce_key
from eoa_verifier.persistence.reading import ApplicationReader
from eoa_verifier.persistence.records import (
    VerificationRecord,
    VerificationResult,
)
from eoa_verifier.persistence.writing import ApplicationWriter
from tests.support.acceptance import (
    acceptance_service,
    retirement_service,
)
from tests.support.issuers import candidate
from tests.support.services import verification_service

WORKER = """
import os, sys
from keri.db import dbing
from eoa_verifier.persistence.basing import VerifierBaser
from eoa_verifier.associations.accepting import AcceptanceService
from eoa_verifier.persistence.reading import ApplicationReader
from eoa_verifier.persistence.writing import ApplicationWriter
root, said, mode = sys.argv[1:]
with dbing.openLMDB(cls=VerifierBaser, name="process", headDirPath=root, temp=False) as baser:
    if mode == "race":
        print("ready", flush=True)
        sys.stdin.readline()
    elif mode == "abort":
        from types import SimpleNamespace
        env = baser.env
        class InterruptedTransaction:
            def __enter__(self):
                self.txn = env.begin(write=True)
                return self
            def __exit__(self, kind, value, traceback):
                self.txn.abort() if kind else self.txn.commit()
            def __getattr__(self, name):
                return getattr(self.txn, name)
            def put(self, *args, **kwargs):
                result = self.txn.put(*args, **kwargs)
                if kwargs.get("db") == baser.accepted_nonces.sdb:
                    os._exit(23)
                return result
        baser.env = SimpleNamespace(begin=lambda **kwargs: InterruptedTransaction()
                                    if kwargs.get("write") else env.begin(**kwargs))
    status = AcceptanceService(ApplicationReader(baser), ApplicationWriter(baser)).accept(said, associationFacts={"issuerAid":"issuer"}, nonce="process-nonce",
                          destination="https://receiver.example/hook", peer_aid="peer")
    if mode == "commit":
        os._exit(24)
    print(status.status, flush=True)
"""


def verify(baser, said):
    """Seed only initial verification for storage-boundary tests, not intake qualification."""
    ApplicationWriter(baser).enqueue_verification(VerificationRecord(said, "grant"))
    verificationService = verification_service(baser)
    verificationService.start_pending(verificationService.next_pending())
    verification_service(baser).finish(
        VerificationResult(
            said, "verified", eoaResult={"wallet": "wallet", "accountObservation": {}}
        )
    )


def accept(baser, said, *, issuer="issuer", nonce="nonce", delivery=True):
    return acceptance_service(baser).accept(
        said,
        associationFacts={"issuerAid": issuer},
        nonce=nonce,
        destination="https://receiver.example/hook" if delivery else None,
        peer_aid="peer" if delivery else None,
    )


@pytest.mark.parametrize("delivery", [False, True])
def test_global_nonce_rejection_survives_revocation_and_reopen(tmp_path, delivery):
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
        app.add_route(
            "/v1/associations/{said}/status",
            StatusEnd(StatusQuery(ApplicationReader(baser))),
        )
        client = TestClient(app)
        response = client.simulate_get("/v1/associations/second/status")
        assert response.status_code == 200
        assert response.json["reason"] == "NONCE_REUSED"
        assert response.json["delivery"] is None
        first = client.simulate_get("/v1/associations/first/status")
        assert first.status_code == 200 and first.json["status"] == "accepted"
        assert (first.json["delivery"] is not None) == delivery
        assert (
            accept(baser, "issuer2", issuer="other", delivery=delivery).reason
            == "NONCE_REUSED"
        )
        for said, nonce in (
            ("uppercase", "Nonce"),
            ("lowercase", "nonce_"),
            ("maximum", "N" * 128),
        ):
            assert (
                accept(baser, said, nonce=nonce, delivery=delivery).status == "accepted"
            )
        assert baser.accepted_nonces.cntAll() == 4
        assert baser.accepted_nonces.get(keys=("nonce",)).associationSaid == "first"
        with baser.env.begin() as txn:
            assert txn.get(b"nonce", db=baser.accepted_nonces.sdb) is not None
        retirement_service(baser).retire("first")
        baser.close()
        baser.reopen()
        assert accept(baser, "first", delivery=delivery).status == "revoked"
        assert (
            accept(baser, "after-revocation", delivery=delivery).reason
            == "NONCE_REUSED"
        )
        assert (
            accept(baser, "second", nonce="different", delivery=delivery)
            == rejectedStatus
        )
        assert baser.outbox.cntAll() == (5 if delivery else 0)


@pytest.mark.parametrize("raw", [b"{bad", b"{}", b'{"associationSaid":"absent"}'])
def test_existing_nonce_key_rejects_without_decoding_its_value(raw):
    """Any stored value means consumed, even if its diagnostic owner is unreadable."""
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        verify(baser, "candidate")
        with baser.env.begin(write=True) as txn:
            txn.put(b"nonce", raw, db=baser.accepted_nonces.sdb)
        rejected = accept(baser, "candidate", issuer="another-issuer")
        assert rejected.status == "rejected" and rejected.reason == "NONCE_REUSED"
        assert baser.outbox.get(keys=("candidate:1",)) is None
        with baser.env.begin() as txn:
            assert txn.get(b"nonce", db=baser.accepted_nonces.sdb) == raw


def test_scope_reopen_does_not_audit_nonce_or_association_values():
    """Startup checks its policy record, not the growing accepted-history dataset."""
    from eoa_verifier.runtime.bootstrap import bind_verification_scope

    with dbing.openLMDB(cls=VerifierBaser) as baser:
        reader, writer = ApplicationReader(baser), ApplicationWriter(baser)
        bind_verification_scope(reader, writer, trusted_geda_aid="geda", chain_id=1)
        with baser.env.begin(write=True) as txn:
            txn.put(b"nonce", b"opaque consumed value", db=baser.accepted_nonces.sdb)
            txn.put(
                b"credential", b"opaque historical value", db=baser.associations.sdb
            )
        bind_verification_scope(reader, writer, trusted_geda_aid="geda", chain_id=1)


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
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        key = nonce_key(nonce)
        assert key == nonce.encode("ascii")
        assert len(key) <= 128 < baser.env.max_key_size()


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
        ApplicationWriter(baser).enqueue_verification(
            VerificationRecord("candidate", "grant")
        )
        verificationService = verification_service(baser)
        verificationService.start_pending(verificationService.next_pending())
        verification_service(baser).finish(
            VerificationResult(
                "candidate",
                "verified",
                eoaResult={"wallet": "wallet", "accountObservation": {}},
            )
        )
        with pytest.raises(ValueError, match="nonce"):
            acceptance_service(baser).accept(
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
