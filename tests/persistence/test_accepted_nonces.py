"""Exact nonce-key consumption, atomic acceptance and independent-process durability.

Use real LMDB transactions and subprocess death to distinguish aborted writes
from committed consumption. Verification is seeded at this storage boundary;
the witnessed integration tests separately establish credential validity.
"""

import subprocess
import sys

import falcon
import pytest
from falcon.testing import TestClient
from keri.db import dbing

from eoa_verifier.associations.statusing import StatusEnd, StatusQuery
from eoa_verifier.persistence.associations import AssociationReader
from eoa_verifier.persistence.basing import VerifierBaser
from eoa_verifier.persistence.delivery import DeliveryReader
from eoa_verifier.persistence.keys import nonce_key
from eoa_verifier.persistence.records import (
    VerificationRecord,
    VerificationResult,
)
from eoa_verifier.persistence.scope import ScopeStore
from eoa_verifier.persistence.verification import VerificationReader
from tests.support.acceptance import (
    acceptance_service,
    revocation_service,
)
from tests.support.issuers import candidate
from tests.support.persistence import enqueue_verification
from tests.support.services import verification_service

# Child program: root/SAID/mode arguments; stdin releases the race barrier.
WORKER = """
'''Accept one seeded credential in a real child process, optionally dying at a commit boundary.'''
import os, sys
from keri.db import dbing
from eoa_verifier.persistence.basing import VerifierBaser
from eoa_verifier.associations.accepting import AcceptanceService
from eoa_verifier.persistence.associations import AssociationReader, AssociationWriter
from eoa_verifier.persistence.verification import VerificationReader

root, said, mode = sys.argv[1:]
with dbing.openLMDB(cls=VerifierBaser, name="process", headDirPath=root, temp=False) as baser:
    if mode == "race":
        print("ready", flush=True)
        sys.stdin.readline()
    elif mode == "abort":
        from types import SimpleNamespace
        env = baser.env
        class InterruptedTransaction:
            '''Delegate a real write transaction and exit after the nonce write, before commit.'''
            def __enter__(self):
                '''Open the real transaction and return the fault wrapper.'''
                self.txn = env.begin(write=True)
                return self
            def __exit__(self, kind, value, traceback):
                '''Preserve normal commit/abort semantics when the process is not killed.'''
                self.txn.abort() if kind else self.txn.commit()
            def __getattr__(self, name):
                '''Delegate all unaffected operations to the real transaction.'''
                return getattr(self.txn, name)
            def put(self, *args, **kwargs):
                '''Perform the actual put, then exit without cleanup at the consumed-nonce boundary.'''
                result = self.txn.put(*args, **kwargs)
                if kwargs.get("db") == baser.accepted_nonces.sdb:
                    os._exit(23)
                return result
        baser.env = SimpleNamespace(begin=lambda **kwargs: InterruptedTransaction()
                                    if kwargs.get("write") else env.begin(**kwargs))
    status = AcceptanceService(AssociationReader(baser), AssociationWriter(baser), verification_reader=VerificationReader(baser)).accept(said, associationFacts={"issuerAid":"issuer"}, nonce="process-nonce",
                          destination="https://receiver.example/hook")
    if mode == "commit":
        os._exit(24)
    print(status.status, flush=True)
"""


def verify(baser, said):
    """Seed only initial verification for storage-boundary tests, not intake qualification."""
    enqueue_verification(baser, VerificationRecord(said, "grant"))
    verificationService = verification_service(baser)
    verificationService.start_pending(verificationService.next_pending())
    verification_service(baser).finish(
        VerificationResult(
            said, "verified", eoaResult={"wallet": "wallet", "accountObservation": {}}
        )
    )


def accept(baser, said, *, issuer="issuer", nonce="nonce", delivery=True):
    """Accept a pre-verified fixture candidate with chosen issuer/nonce and optional delivery.

    Use the real acceptance service and atomic writers. The caller seeds initial
    verification separately; this helper does not establish credential validity.
    """
    return acceptance_service(baser).accept(
        said,
        associationFacts={"issuerAid": issuer},
        nonce=nonce,
        destination="https://receiver.example/hook" if delivery else None,
    )


@pytest.mark.parametrize("delivery", [False, True])
def test_global_nonce_rejection_survives_revocation_and_reopen(tmp_path, delivery):
    """A consumed nonce rejects every different credential, across issuers and restart.

    Same-credential replay stays idempotent. Exercise delivery-enabled and local-only
    acceptance, preserve distinct valid nonce bytes, and prove revocation never
    releases the consumed key or fabricates an old delivery obligation.
    """
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
            StatusEnd(
                StatusQuery(
                    AssociationReader(baser),
                    VerificationReader(baser),
                    DeliveryReader(baser),
                )
            ),
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
        revocation_service(baser).apply_revocation("first")
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
    """Startup only records settings, even with no baseline and opaque history."""
    from eoa_verifier.runtime.bootstrap import note_config

    with dbing.openLMDB(cls=VerifierBaser) as baser:
        scope_store = ScopeStore(baser)
        note_config(scope_store, trusted_geda_aid="geda", chain_id=1)
        with baser.env.begin(write=True) as txn:
            txn.put(b"nonce", b"opaque consumed value", db=baser.accepted_nonces.sdb)
            txn.put(
                b"credential", b"opaque historical value", db=baser.associations.sdb
            )
        baser.scope.rem(keys=("verification",))
        note_config(scope_store, trusted_geda_aid="other-geda", chain_id=2)


@pytest.mark.parametrize("same_said", [False, True])
def test_independent_process_race_has_one_owner(tmp_path, same_said):
    """Race four real LMDB processes at one nonce without an application lock.

    Different credentials yield one acceptance; same-credential contenders observe
    the same committed acceptance. Reopen and require one nonce, status and event.
    """
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
    """Terminate a child without Python cleanup on either side of the atomic acceptance commit.

    Reopen the real store after each exit: pre-commit mutation leaves no partial
    nonce/status/event; post-commit death retains all three and idempotent replay.
    """
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
                assert not original.delivered
                assert accept(baser, "first").status == "accepted"
                assert baser.outbox.get(keys=("first:1",)) == original


@pytest.mark.parametrize(
    "nonce", ["x", "N" * 128, "aZ09_-", "25C89E61-21F8-4CCF-948D-46D1FBB7BAE8"]
)
def test_ascii_boundaries_are_preserved_in_lmdb(nonce):
    """Keep accepted nonce keys equal to their exact ASCII bytes and below the LMDB key limit."""
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
    """Reject malformed nonce values before any nonce, association status or delivery is written."""
    credential = candidate()
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        enqueue_verification(baser, VerificationRecord("candidate", "grant"))
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
