"""integration/test_ipex_verification.py."""

import shutil
import subprocess
import time
from contextlib import ExitStack, closing
from importlib.resources import files
from uuid import uuid4

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from hio.base import doing
from hio.core import http
from keri.app import habbing, httping, indirecting, oobiing, signing
from keri.core import coring, scheming
from keri.db import basing, dbing
from keri.help import helping

from eoa_verifier.associations.retiring import RetirementDoer
from eoa_verifier.persistence.keys import nonce_key
from eoa_verifier.persistence.reading import ApplicationReader
from eoa_verifier.receiving.grants import GrantNotificationDoer
from eoa_verifier.runtime.config import ServiceConfig
from eoa_verifier.verification.constants import LE_SCHEMA, QVI_SCHEMA
from eoa_verifier.verification.coordinating import VerificationCoordinator
from eoa_verifier.verification.eoa import build_challenge
from scripts.integration.issuers import (
    KEY,
    IssuerEscrows,
    anchor,
    approve_qvi,
    association_from_challenge,
    grant,
    issue_credential,
    open_issuers,
    receive,
    replay,
    revoke_credential,
    rules,
)
from tests.support.network import free_port
from tests.support.services import verifier_service


@pytest.mark.parametrize("method", ["POST", "PUT"])
@pytest.mark.parametrize("delivery", [True, False])
def test_grant_verification_and_restart(tmp_path, method, delivery):
    """Exercise real witnessed GEDA/QVI/LE issuance, IPEX HTTP delivery and local Anvil.

    Own isolated KERIpy stores/processes with ExitStack and all network tasks with
    HIO. Missing Anvil fails rather than skips. Test delayed evidence across restart,
    acceptance with verified issuance facts, delayed-anchor retirement across restart,
    duplicate delivery, incomplete HTTP input before evidence/revocation, revocation
    during initial RPC, and invalid proof/relationships.
    """
    anvil_path = shutil.which("anvil")
    assert anvil_path, "Anvil is required for KERI/IPEX integration; install Foundry"
    schemas = [
        scheming.Schemer(raw=p.read_bytes())
        for p in files("eoa_verifier.verification").joinpath("schema_data").iterdir()
    ]
    by_said = {s.said: s for s in schemas}
    with ExitStack() as stack:
        witness_hby = stack.enter_context(habbing.openHby(name="witness", temp=True))
        witness_port = free_port()
        witness_doers = indirecting.setupWitness(
            hby=witness_hby, alias="witness", tcpPort=None, httpPort=witness_port
        )
        witness = witness_hby.habByName("witness")
        witness_url = f"http://127.0.0.1:{witness_port}"
        witness_hby.psr.parse(ims=witness.makeEndRole(eid=witness.pre))
        witness_hby.psr.parse(ims=witness.makeLocScheme(url=witness_url))
        actors, issuers = open_issuers(
            stack, schemas, base="", temp=True, witness=witness
        )
        oobi = f"{witness_url}/oobi/{witness.pre}/controller"
        resolvers = []
        for hby, _, _ in actors.values():
            hby.db.oobis.pin(
                keys=(oobi,), val=basing.OobiRecord(date=helping.nowIso8601())
            )
            resolvers.append(oobiing.Oobiery(hby=hby, clienter=httping.Clienter()))
        _, geda, _ = actors["geda"]
        _, qvi, _ = actors["qvi"]
        _, le, le_rgy = actors["le"]
        rpc_port, port = free_port(), free_port()
        anvil = subprocess.Popen(
            [anvil_path, "--host", "127.0.0.1", "--port", str(rpc_port), "--silent"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        stack.callback(anvil.wait, timeout=5)
        stack.callback(anvil.terminate)
        config = ServiceConfig(
            trusted_geda_aid=geda.pre,
            chain_id=31337,
            rpc_url=f"http://127.0.0.1:{rpc_port}",
            head_dir=str(tmp_path),
            http_port=port,
            webhook_url="http://127.0.0.1:1/hook" if delivery else None,
            webhook_aid=geda.pre if delivery else None,
        )
        service_stores = stack.enter_context(ExitStack())
        epoch = time.time()

        def open_service():
            """Keep persistent retry deadlines on the test's HIO timeline across restart.

            Real Doist catches up after blocking setup/store work. Its virtual
            deadlines can otherwise run ahead of a recently started UTC cooldown.
            Use one epoch for every reopened worker; keep all retry budgets and
            ten-second progress assertions unchanged.
            """
            service = service_stores.enter_context(verifier_service(config))
            for doer in service.doers:
                if isinstance(doer, (GrantNotificationDoer, VerificationCoordinator)):
                    doer.clock = lambda: epoch + workflow.tyme
            return service

        runtime = open_service()
        client = http.Client(hostname="127.0.0.1", port=port)
        client_doer = http.ClientDoer(client=client)
        doers = [
            *witness_doers,
            *(d for r in resolvers for d in r.doers),
            *(d for i in issuers.values() for d in (i.registrar, i)),
            IssuerEscrows(list(issuers.values())),
            runtime,
            client_doer,
        ]
        finished = []

        def send(stream):
            """Yield while sending CESR bytes through the owned HTTP client; assert each transport ACK, return None."""
            if method == "POST":
                count = httping.streamCESRRequests(
                    client, bytearray(stream), runtime.hab.pre
                )
            else:
                client.request(method="PUT", path="/", body=stream)
                count = 1
            for _ in range(count):
                while not client.responses:
                    yield 0.01
                assert client.responses.popleft()["status"] in (200, 202, 204)

        def send_incomplete():
            """Submit a truncated CESR frame; later independent requests must progress."""
            if method == "POST":
                client.request(
                    method="POST",
                    path="/",
                    body=runtime.hab.kever.serder.raw,
                    headers={
                        "Content-Type": httping.CESR_CONTENT_TYPE,
                        "CESR-ATTACHMENT": "-AAB",
                    },
                )
            else:
                client.request(
                    method="PUT",
                    path="/",
                    body=b'{"v":"KERI10JSONffffff_","t":"ixn"}',
                )
            while not client.responses:
                yield 0.01
            assert client.responses.popleft()["status"] == 204

        def deliver(stream, said, expected):
            """Yield through HTTP delivery and wait up to ten HIO seconds for the expected durable row; return it."""
            yield from send(stream)
            deadline = workflow.tyme + 10
            while True:
                verification = (
                    ApplicationReader(runtime.baser).verification_progress(said)[1]
                    if expected == "pending"
                    else runtime.baser.results.get(keys=(said,))
                )
                if verification is not None and (
                    expected == "pending" or verification.status == expected
                ):
                    return verification
                assert workflow.tyme < deadline, (
                    expected,
                    verification,
                    ApplicationReader(runtime.baser).verification_progress(said),
                )
                yield 0.01

        def wait_status(said, expected):
            """Yield until the application stores the expected status, with a bounded deadline."""
            deadline = workflow.tyme + 5
            while True:
                status = runtime.baser.associations.get(keys=(said,))
                if status is not None and status.status == expected:
                    return status
                assert workflow.tyme < deadline, (expected, status)
                yield 0.01

        def issue_association(
            *, signer=KEY, chain=31337, holder=None, nonce=None, wallet_key=KEY
        ):
            """Yield through witnessed issuance and return (ACDC, KERI evidence/Grant bytes).

            signer, chain and holder select intentional invalid cases. The normal
            issuer is the LE holder. Signatures and anchors remain genuine even
            when testing a mismatched holder relationship.
            """
            hab = holder or le
            registry = registries["qvi" if holder else "le"]
            challenge = build_challenge(
                issuer_aid=hab.pre,
                le_vlei_said=credentials["qvi"].said,
                ext_id=f"eip155:{chain}:{Account.from_key(wallet_key).address.lower()}",
                nonce=nonce if nonce is not None else str(uuid4()),
            )
            sig = Account.sign_message(
                encode_typed_data(full_message=challenge), signer
            ).signature
            creder = association_from_challenge(
                challenge, "0x" + sig.hex(), registry.regk
            )
            issuer = issuers["qvi" if holder else "le"]
            if holder:
                # Intentionally invalid I2I relation, but genuine signed/witnessed issuance.
                issuance = registry.issue(said=creder.said)
                issuer.registrar.issue(creder, issuance, anchor(hab, issuance))
                while not issuer.registrar.complete(creder.said):
                    yield 0.01
                acdc = signing.serialize(
                    creder,
                    coring.Prefixer(qb64=issuance.pre),
                    coring.Seqner(sn=issuance.sn),
                    coring.Saider(qb64=issuance.said),
                )
            else:
                yield from issue_credential(issuer, registry, creder)
                acdc = None
            rgy = actors["qvi" if holder else "le"][2]
            presentationCesr = b"".join(hab.db.clonePreIter(pre=hab.pre))
            presentationCesr += b"".join(rgy.reger.clonePreIter(pre=registry.regk))
            presentationCesr += grant(hab, rgy, creder, runtime.hab.pre, acdc=acdc)
            return creder, presentationCesr

        def run(tymth, tock=0.0, **kwa):
            """Yield through issuance, restart, replay and the held-result revocation scenario.

            Share runtime/client references so delivery uses reopened stores. On success
            mark finished, unschedule the other tasks before stack cleanup, and return True.
            """
            nonlocal runtime, client, client_doer
            yield tock
            for hby, _, _ in actors.values():
                while hby.db.roobi.get(keys=(oobi,)) is None:
                    yield 0.01
                assert hby.db.roobi.get(keys=(oobi,)).state == oobiing.Result.resolved
            yield from approve_qvi(actors, issuers)
            for name, (_, hab, rgy) in actors.items():
                registry = rgy.makeRegistry(name=name, prefix=hab.pre, noBackers=True)
                issuers[name].registrar.incept(registry.vcp, anchor(hab, registry.vcp))
                while not issuers[name].registrar.complete(registry.regk):
                    yield 0.01
                registries[name] = registry
            # Issue the real GEDA -> QVI -> LE chain before association creation.
            for name, recipient, schema_said in [
                ("geda", qvi, QVI_SCHEMA),
                ("qvi", le, LE_SCHEMA),
            ]:
                source = (
                    None
                    if name == "geda"
                    else coring.Saider.saidify(
                        sad={
                            "d": "",
                            "qvi": {"n": credentials["geda"].said, "s": QVI_SCHEMA},
                        }
                    )[1]
                )
                creder = issuers[name].create(
                    regname=name,
                    recp=recipient.pre,
                    schema=schema_said,
                    source=source,
                    rules=rules(by_said[schema_said]),
                    data={"LEI": "5493001KJTIIGC8Y1R12"},
                )
                yield from issue_credential(issuers[name], registries[name], creder)
                credentials[name] = creder
                streams[name] = replay(
                    registries[name].hab, issuers[name].rgy, registries[name], creder
                )
                hby, _, rgy = actors["qvi" if name == "geda" else "le"]
                receive(
                    hby,
                    rgy,
                    streams["geda"] + (streams["qvi"] if name == "qvi" else b""),
                )
                assert rgy.reger.saved.get(keys=(creder.said,))

            # Deliver the association first, then reopen with its sources still absent.
            creder, presentationCesr = yield from issue_association()
            yield from send_incomplete()
            yield from deliver(presentationCesr, creder.said, "pending")
            assert runtime.baser.accepted_nonces.cntAll() == 0
            aid = runtime.hab.pre
            workflow.remove([runtime, client_doer])
            service_stores.close()
            runtime = open_service()
            client = http.Client(hostname="127.0.0.1", port=port)
            client_doer = http.ClientDoer(client=client)
            workflow.extend([runtime, client_doer])
            assert runtime.hab.pre == aid
            assert (
                ApplicationReader(runtime.baser).verification_progress(creder.said)[1]
                is not None
            )
            # Supporting evidence alone resumes persisted work; no new Grant required.
            yield from deliver(
                streams["geda"] + streams["qvi"], creder.said, "verified"
            )
            assert runtime.rgy.reger.saved.get(keys=(creder.said,))
            # Capture verified issuance facts after verification, without another RPC pass.
            associationStatus = yield from wait_status(creder.said, "accepted")
            assert associationStatus.association["issuerAid"] == le.pre
            assert associationStatus.association["leSaid"] == credentials["qvi"].said
            assert associationStatus.association["issuanceAnchor"] == {
                "sequenceNumber": le.kever.sn,
                "said": le.kever.serder.said,
            }
            assert associationStatus.accountObservation["chainId"] == 31337
            assert bool(associationStatus.eventId) == delivery
            if delivery:
                assert (
                    runtime.baser.outbox.get(keys=(associationStatus.eventId,))
                    is not None
                )
            # Replaying the same Grant must retain the completed work record.
            original = runtime.baser.results.get(keys=(creder.said,))
            # EXN deduplication may suppress a new notice entirely. Test application
            # replay explicitly after the HTTP redelivery, rather than observing the
            # already-existing result before the duplicate has been processed.
            yield from send(presentationCesr)

            with closing(runtime.hby.db.exns.getItemIter()) as exnRecords:
                for _, exn in exnRecords:
                    if exn.ked.get("e", {}).get("acdc", {}).get("d") == creder.said:
                        grantSaid = exn.said
                        break
                else:
                    raise AssertionError("accepted Grant not found")
            runtime.notifier.add({"r": "/exn/ipex/grant", "d": grantSaid})
            runtime.grant_replay.process_one()
            assert runtime.baser.results.get(keys=(creder.said,)) == original
            assert (
                runtime.baser.associations.get(keys=(creder.said,)) == associationStatus
            )

            # Two otherwise valid signed credentials sharing issuer/u: only the first accepts.
            other_key = "0x" + "0" * 63 + "2"
            reused, reused_stream = yield from issue_association(
                signer=other_key, wallet_key=other_key, nonce=creder.sad["u"]
            )
            assert reused.said != creder.said
            result = yield from deliver(reused_stream, reused.said, "verified")
            rejectedStatus = yield from wait_status(reused.said, "rejected")
            assert (
                result.status == "verified" and rejectedStatus.reason == "NONCE_REUSED"
            )
            assert runtime.baser.outbox.get(keys=(f"{reused.said}:1",)) is None
            assert runtime.baser.accepted_nonces.cntAll() == 1

            # A newer same-LE/address association has independent application status.
            successor, successor_stream = yield from issue_association()
            yield from deliver(successor_stream, successor.said, "verified")
            newer = yield from wait_status(successor.said, "accepted")
            assert (
                newer.association["issuanceAnchor"]["sequenceNumber"]
                > associationStatus.association["issuanceAnchor"]["sequenceNumber"]
            )
            initial_event = (
                runtime.baser.outbox.get(keys=(associationStatus.eventId,))
                if delivery
                else None
            )

            # A fresh Grant still embeds issuance. Neither it nor unanchored TEL
            # evidence can retire an association; wait for actual KERIpy escrow.
            yield from revoke_credential(issuers["le"], registries["le"], creder)
            yield from send(grant(le, le_rgy, creder, runtime.hab.pre))
            revocation = le_rgy.reger.cloneTvtAt(creder.said, sn=1)
            yield from send_incomplete()
            yield from send(revocation)
            deadline = workflow.tyme + 5
            while runtime.rgy.reger.getTae(dbing.snKey(creder.said, 1)) is None:
                assert workflow.tyme < deadline, (
                    "revocation did not enter KERIpy anchor escrow"
                )
                yield 0.01
            retirement = next(d for d in runtime.doers if isinstance(d, RetirementDoer))
            retirement.recur(workflow.tyme)
            assert (
                runtime.rgy.reger.tevers[creder.regi].vcState(creder.said).et == "iss"
            )
            assert (
                runtime.baser.associations.get(keys=(creder.said,)) == associationStatus
            )

            # Model loss between accepted KERIpy TEL and application commit. Only
            # the missing KEL arrives now: no further Grant notification is needed.
            runtime.remove([retirement])
            yield from send(b"".join(le.db.clonePreIter(pre=le.pre)))
            deadline = workflow.tyme + 5
            while (
                runtime.rgy.reger.tevers[creder.regi].vcState(creder.said).et != "rev"
            ):
                assert workflow.tyme < deadline, (
                    "verified revocation escrow did not resolve"
                )
                yield 0.01
            assert (
                runtime.baser.associations.get(keys=(creder.said,)) == associationStatus
            )
            workflow.remove([runtime, client_doer])
            service_stores.close()
            runtime = open_service()
            client = http.Client(hostname="127.0.0.1", port=port)
            client_doer = http.ClientDoer(client=client)
            workflow.extend([runtime, client_doer])
            revokedStatus = yield from wait_status(creder.said, "revoked")
            assert (
                revokedStatus.association == associationStatus.association
            )  # Keep issuance, not revocation anchor.
            assert (
                revokedStatus.accountObservation == associationStatus.accountObservation
            )
            assert revokedStatus.eventId == (f"{creder.said}:2" if delivery else "")
            retained = (
                runtime.baser.outbox.get(keys=(associationStatus.eventId,))
                if delivery
                else None
            )
            if delivery:
                # Retry progress may advance; immutable accepted-event bytes must not.
                assert retained.body == initial_event.body
            else:
                assert retained is None
            assert runtime.baser.associations.get(keys=(successor.said,)) == newer
            # Replay both the original Grant and the now-revoked KERI artifacts.
            yield from send(
                presentationCesr + replay(le, le_rgy, registries["le"], creder)
            )

            # Hold completion after a real RPC observation, then deliver KERIpy
            # revocation before applying the result. The final KERIpy recheck
            # must prevent initial success without asking RPC a second time.

            coordinator = next(
                d for d in runtime.doers if isinstance(d, VerificationCoordinator)
            )
            verifier_loop = next(
                d for d in coordinator.doers if d is not coordinator.eoa_verifier
            )
            coordinator.remove([verifier_loop])
            raced, stream = yield from issue_association()
            yield from send(stream)
            while runtime.baser.pending.get(keys=(raced.said,)) is None:
                yield 0.01
            while coordinator.activeCredSaid != raced.said:
                coordinator.process_ready()
                yield 0.01
            while not coordinator.eoa_verifier.cues:
                yield 0.01
            assert coordinator.eoa_verifier.cues[0]["kin"] == "verified"
            yield from revoke_credential(issuers["le"], registries["le"], raced)
            yield from send(replay(le, le_rgy, registries["le"], raced))
            while runtime.rgy.reger.tevers[raced.regi].vcState(raced.said).et != "rev":
                yield 0.01
            coordinator.process_results()
            rejectedResult = runtime.baser.results.get(keys=(raced.said,))
            assert (
                rejectedResult.status == "rejected"
                and "revoked" in rejectedResult.reason
            )
            assert (
                runtime.baser.accepted_nonces.get(
                    keys=(nonce_key(raced.sad["u"]),)
                )
                is None
            )
            coordinator.extend([verifier_loop])

            for label, options, reason in [
                ("proof", {"signer": "0x" + "0" * 63 + "2"}, "signer"),
                ("chain", {"chain": 31338}, "chain"),
                ("issuer", {"holder": qvi}, "issuer does not match"),
            ]:
                candidate, stream = yield from issue_association(**options)
                verification = yield from deliver(stream, candidate.said, "rejected")
                assert reason in verification.reason, (label, verification)
                assert (
                    runtime.baser.accepted_nonces.get(
                        keys=(nonce_key(candidate.sad["u"]),)
                    )
                    is None
                )
            assert runtime.baser.associations.get(keys=(creder.said,)) == revokedStatus
            assert len(
                [
                    event
                    for _, event in runtime.baser.outbox.getItemIter()
                    if event.associationSaid == creder.said
                ]
            ) == (2 if delivery else 0)
            assert runtime.baser.associations.get(keys=(successor.said,)) == newer
            finished.append(True)
            workflow.remove([d for d in workflow.doers if d is not task])
            return True

        registries, credentials, streams = {}, {}, {}
        task = doing.doify(run)
        workflow = doing.DoDoer(doers=[*doers, task])
        doing.Doist(real=True, tock=0.01, limit=60).do(doers=[workflow])
        assert finished, "IPEX workflow timed out"
