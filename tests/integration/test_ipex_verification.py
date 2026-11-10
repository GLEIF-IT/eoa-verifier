"""Witnessed issuer-chain and IPEX integration through the real Verifier runtime.

Retain the independent habitats, source credentials, witness evidence, HTTP
transport and Anvil observation. Restart and hostile ordering exercise durable
phase boundaries rather than a second verification simulator.
"""

import json
import shutil
import subprocess
import time
from contextlib import ExitStack, closing
from importlib.resources import files
from uuid import uuid4

import falcon
import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from falcon.testing import TestClient
from hio.base import doing
from hio.core import http
from keri.app import habbing, httping, indirecting, oobiing, signing
from keri.core import coring, scheming
from keri.db import basing, dbing
from keri.help import helping

from eoa_verifier.associations.revoking import RevocationDoer, RevocationWorkDoer
from eoa_verifier.persistence.associations import AssociationReader
from eoa_verifier.persistence.keys import nonce_key
from eoa_verifier.persistence.verification import VerificationReader
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
    acceptance with verified issuance facts, delayed-anchor revocationDoer across restart,
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
                    doer.service.clock = lambda: epoch + workflow.tyme
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
                    VerificationReader(runtime.baser).progress(said)[1]
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
                    VerificationReader(runtime.baser).progress(said),
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
                VerificationReader(runtime.baser).progress(creder.said)[1] is not None
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
            # evidence can revoke an association; wait for actual KERIpy escrow.
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
            revocationDoer = next(
                d for d in runtime.doers if isinstance(d, RevocationDoer)
            )
            revocationDoer.recur(workflow.tyme)
            assert (
                runtime.rgy.reger.tevers[creder.regi].vcState(creder.said).et == "iss"
            )
            assert (
                runtime.baser.associations.get(keys=(creder.said,)) == associationStatus
            )

            # Model loss between accepted KERIpy TEL and application commit. Only
            # the missing KEL arrives now: no further Grant notification is needed.
            runtime.remove([revocationDoer])
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
                d for d in coordinator.doers if d is not coordinator.wallet_doer
            )
            coordinator.remove([verifier_loop])
            raced, stream = yield from issue_association()
            yield from send(stream)
            while runtime.baser.pending.get(keys=(raced.said,)) is None:
                yield 0.01
            while coordinator.activeCredSaid != raced.said:
                coordinator.process_ready()
                yield 0.01
            while not coordinator.wallet_doer.cues:
                yield 0.01
            assert coordinator.wallet_doer.cues[0]["kin"] == "verified"
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
                runtime.baser.accepted_nonces.get(keys=(nonce_key(raced.sad["u"]),))
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


def test_upstream_revocation_from_witnessed_evidence(tmp_path):
    """Revoke witnessed LE and QVI credentials and observe every accepted association.

    The QVI issues two LE credentials to one holder, so only the credential SAID
    can distinguish their associations. LE 1 is revoked by raw PUT with its TEL
    before its KEL anchor while another association waits on missing evidence. A
    third LE is revoked by evidence in the same PUT body as a Grant presentation.
    GEDA then revokes the QVI across restarts on both sides of Stage A. Webhooks
    reach a real receiver.
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
        _, geda, geda_rgy = actors["geda"]
        _, qvi, qvi_rgy = actors["qvi"]
        le_hby, le, le_rgy = actors["le"]
        rpc_port, port, hook_port = free_port(), free_port(), free_port()
        anvil = subprocess.Popen(
            [anvil_path, "--host", "127.0.0.1", "--port", str(rpc_port), "--silent"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        stack.callback(anvil.wait, timeout=5)
        stack.callback(anvil.terminate)
        webhooks = []

        class Hook:
            """Retain every status event body received over real HTTP."""

            def on_post(self, req, rep):
                """Record the delivered JSON event and return an unsigned success."""
                webhooks.append(json.loads(req.bounded_stream.read()))
                rep.status = falcon.HTTP_200

        hook_app = falcon.App()
        hook_app.add_route("/hook", Hook())
        config = ServiceConfig(
            trusted_geda_aid=geda.pre,
            chain_id=31337,
            rpc_url=f"http://127.0.0.1:{rpc_port}",
            head_dir=str(tmp_path),
            http_port=port,
            webhook_url=f"http://127.0.0.1:{hook_port}/hook",
        )
        service_stores = stack.enter_context(ExitStack())
        epoch = time.time()

        def open_service(*omitted):
            """Reopen the persistent Verifier on one test timeline, leaving out named workers."""
            service = service_stores.enter_context(verifier_service(config))
            for doer in service.doers:
                if isinstance(doer, (GrantNotificationDoer, VerificationCoordinator)):
                    doer.service.clock = lambda: epoch + workflow.tyme
            service.doers = [d for d in service.doers if not isinstance(d, omitted)]
            return service

        runtime = open_service()
        finished = []

        def restart(*omitted):
            """Stop and reopen the Verifier without presenting any evidence."""
            nonlocal runtime
            workflow.remove([runtime])
            service_stores.close()
            runtime = open_service(*omitted)
            workflow.extend([runtime])

        def send(stream):
            """Yield while PUTting CESR on a new connection; idle ones close during issuance."""
            client = http.Client(hostname="127.0.0.1", port=port)
            client_doer = http.ClientDoer(client=client)
            workflow.extend([client_doer])
            client.request(method="PUT", path="/", body=stream)
            while not client.responses:
                yield 0.01
            assert client.responses.popleft()["status"] in (200, 202, 204)
            workflow.remove([client_doer])

        def until(condition, reason):
            """Yield until condition holds, failing after a bounded HIO deadline."""
            deadline = workflow.tyme + 10
            while not condition():
                assert workflow.tyme < deadline, reason
                yield 0.01

        def stored(said):
            """Read one association's current application status."""
            return runtime.baser.associations.get(keys=(said,))

        def has_status(said, expected):
            """Return a predicate for one association reaching one status."""
            return lambda: (s := stored(said)) is not None and s.status == expected

        def tel_state(creder):
            """Read a credential's current accepted TEL state in the Verifier."""
            return runtime.rgy.reger.tevers[creder.regi].vcState(creder.said)

        def status_view(said):
            """Return the public status response through the service's own routes."""
            return TestClient(runtime.app).simulate_get(
                f"/v1/associations/{said}/status"
            ).json

        def issue_association(source):
            """Yield through witnessed issuance on one LE credential; return (ACDC, evidence)."""
            challenge = build_challenge(
                issuer_aid=le.pre,
                le_vlei_said=source.said,
                ext_id=f"eip155:31337:{Account.from_key(KEY).address.lower()}",
                nonce=str(uuid4()),
            )
            sig = Account.sign_message(
                encode_typed_data(full_message=challenge), KEY
            ).signature
            creder = association_from_challenge(
                challenge, "0x" + sig.hex(), registries["le"].regk
            )
            yield from issue_credential(issuers["le"], registries["le"], creder)
            evidence = b"".join(le.db.clonePreIter(pre=le.pre))
            evidence += b"".join(le_rgy.reger.clonePreIter(pre=registries["le"].regk))
            evidence += grant(le, le_rgy, creder, runtime.hab.pre)
            return creder, evidence

        def issue_source(name, recipient, schema_said, data, source=None):
            """Yield through one witnessed source credential and return (ACDC, evidence)."""
            creder = issuers[name].create(
                regname=name,
                recp=recipient.pre,
                schema=schema_said,
                source=source,
                rules=rules(by_said[schema_said]),
                data=data,
            )
            yield from issue_credential(issuers[name], registries[name], creder)
            stream = replay(registries[name].hab, issuers[name].rgy, registries[name], creder)
            return creder, stream

        def accept(source):
            """Yield until one new association on the LE credential is accepted; return it."""
            creder, evidence = yield from issue_association(source)
            yield from send(evidence)
            yield from until(has_status(creder.said, "accepted"), creder.said)
            return creder

        def run(tymth, tock=0.0, **kwa):
            """Yield through the upstream revocation scenario; mark success and unschedule."""
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

            qvi_credential, qvi_stream = yield from issue_source(
                "geda", qvi, QVI_SCHEMA, {"LEI": "5493001KJTIIGC8Y1R12"}
            )
            receive(actors["qvi"][0], qvi_rgy, qvi_stream)
            edge = coring.Saider.saidify(
                sad={"d": "", "qvi": {"n": qvi_credential.said, "s": QVI_SCHEMA}}
            )[1]
            le_one, le_one_stream = yield from issue_source(
                "qvi", le, LE_SCHEMA, {"LEI": "5493001KJTIIGC8Y1R12"}, source=edge
            )
            le_two, le_two_stream = yield from issue_source(
                "qvi", le, LE_SCHEMA, {"LEI": "254900OPPU84GM83MG36"}, source=edge
            )
            le_three, le_three_stream = yield from issue_source(
                "qvi", le, LE_SCHEMA, {"LEI": "529900T8BM49AURSDO55"}, source=edge
            )
            sources = (qvi_stream, le_one_stream, le_two_stream, le_three_stream)
            receive(le_hby, le_rgy, b"".join(sources))
            assert le_one.said != le_two.said
            assert le_rgy.reger.saved.get(keys=(le_one.said,))
            assert le_rgy.reger.saved.get(keys=(le_two.said,))
            for stream in sources:
                yield from send(stream)

            first = yield from accept(le_one)
            second = yield from accept(le_one)
            third = yield from accept(le_two)
            fourth = yield from accept(le_two)
            fifth = yield from accept(le_three)
            accepted = {
                c.said: stored(c.said) for c in (first, second, third, fourth, fifth)
            }
            yield from until(
                lambda: len(webhooks) >= 5, "accepted webhooks were not delivered"
            )

            # Withhold one KEL event: the embedded anchor escrows and verification waits.
            yield from issue_association(le_one)
            waiting, _ = yield from issue_association(le_one)
            yield from send(grant(le, le_rgy, waiting, runtime.hab.pre))
            verification = VerificationReader(runtime.baser)
            yield from until(
                lambda: verification.progress(waiting.said)[0] == "waiting",
                "association did not reach waiting",
            )

            # LE 1: TEL first escrows without effect; the witnessed anchor resolves it.
            yield from revoke_credential(issuers["qvi"], registries["qvi"], le_one)
            assert len(qvi.kever.serder.ked["a"]) == 1
            yield from send(qvi_rgy.reger.cloneTvtAt(le_one.said, sn=1))
            yield from until(
                lambda: runtime.rgy.reger.getTae(dbing.snKey(le_one.said, 1)),
                "LE revocation did not enter KERIpy anchor escrow",
            )
            assert tel_state(le_one).et == "iss" and stored(first.said).status == "accepted"
            yield from send(b"".join(qvi.db.clonePreIter(pre=qvi.pre)))
            for creder in (first, second):
                yield from until(has_status(creder.said, "revoked"), creder.said)
            leRevocation = tel_state(le_one).d
            for creder in (first, second):
                status = stored(creder.said)
                assert status.eventId == f"{creder.said}:2"
                assert status.association == accepted[creder.said].association
                assert status_view(creder.said)["revocationSource"] == {
                    "credentialSaid": le_one.said,
                    "role": "le",
                    "telEventSaid": leRevocation,
                }
            for creder in (third, fourth):
                assert stored(creder.said) == accepted[creder.said]
                assert "revocationSource" not in status_view(creder.said)
            yield from until(
                lambda: len(webhooks) >= 7, "LE revocation webhooks were not delivered"
            )
            assert {e["eventId"] for e in webhooks if e["status"] == "revoked"} == {
                f"{first.said}:2",
                f"{second.said}:2",
            }

            # The waiting association names the now-revoked LE and cannot be accepted.
            yield from until(
                lambda: runtime.baser.results.get(keys=(waiting.said,)) is not None,
                "waiting association did not settle",
            )
            rejected = runtime.baser.results.get(keys=(waiting.said,))
            assert rejected.status == "rejected" and "revoked" in rejected.reason
            assert stored(waiting.said) is None
            assert AssociationReader(runtime.baser).source_links(le_one.said) == sorted(
                [(first.said, "le"), (second.said, "le")]
            )
            assert (
                runtime.baser.accepted_nonces.get(keys=(nonce_key(waiting.sad["u"]),))
                is None
            )

            # A presenter may place the evidence in the same CESR body as a Grant. The
            # Grant's own embeds carry only the presented association's issuance.
            presented, presentation = yield from issue_association(le_three)
            yield from revoke_credential(issuers["qvi"], registries["qvi"], le_three)
            yield from send(
                replay(qvi, qvi_rgy, registries["qvi"], le_three) + presentation
            )
            yield from until(has_status(fifth.said, "revoked"), fifth.said)
            assert status_view(fifth.said)["revocationSource"] == {
                "credentialSaid": le_three.said,
                "role": "le",
                "telEventSaid": tel_state(le_three).d,
            }
            yield from until(
                lambda: runtime.baser.results.get(keys=(presented.said,)) is not None,
                "presented association did not settle",
            )
            refused = runtime.baser.results.get(keys=(presented.said,))
            assert refused.status == "rejected" and le_three.said in refused.reason
            assert stored(presented.said) is None

            # QVI: hold both stages so the TEL commit is the only durable progress.
            runtime.remove(
                [
                    d
                    for d in runtime.doers
                    if isinstance(d, (RevocationDoer, RevocationWorkDoer))
                ]
            )
            yield from revoke_credential(
                issuers["geda"], registries["geda"], qvi_credential
            )
            assert len(geda.kever.serder.ked["a"]) == 1
            yield from send(replay(geda, geda_rgy, registries["geda"], qvi_credential))
            yield from until(
                lambda: tel_state(qvi_credential).et == "rev",
                "QVI revocation was not accepted",
            )
            qviRevocation = tel_state(qvi_credential).d
            assert runtime.rgy.reger.next_revocation() == (
                qvi_credential.said,
                qviRevocation,
            )
            assert stored(third.said) == accepted[third.said]
            assert runtime.baser.revocation_work.cntAll() == 0

            # Restart with the registry record only: Stage A alone may run next.
            restart(RevocationWorkDoer)
            yield from until(
                lambda: runtime.rgy.reger.next_revocation() is None,
                "restarted Stage A did not acknowledge the QVI revocation",
            )
            assert runtime.baser.revocation_work.cntAll() == 5  # Three already revoked.
            assert stored(third.said) == accepted[third.said]

            # Restart with durable work only: no evidence is presented again.
            restart()
            for creder in (third, fourth):
                yield from until(has_status(creder.said, "revoked"), creder.said)
                assert status_view(creder.said)["revocationSource"] == {
                    "credentialSaid": qvi_credential.said,
                    "role": "qvi",
                    "telEventSaid": qviRevocation,
                }
            yield from until(
                lambda: runtime.baser.revocation_work.cntAll() == 0,
                "finished work was not dropped",
            )
            yield from until(
                lambda: len(webhooks) >= 10, "QVI revocation webhooks were not delivered"
            )
            assert status_view(first.said)["revocationSource"]["role"] == "le"
            assert runtime.baser.outbox.cntAll() == 10
            revoked = [e for e in webhooks if e["status"] == "revoked"]
            assert {e["eventId"] for e in revoked} == {
                f"{c.said}:2" for c in (first, second, third, fourth, fifth)
            }
            for event in revoked:
                assert event["statusRevision"] == 2 and event["reasonCode"] == "REVOKED"
                assert set(event) == {
                    "version",
                    "eventId",
                    "associationSaid",
                    "statusRevision",
                    "status",
                    "reasonCode",
                    "association",
                    "accountObservation",
                }
            finished.append(True)
            workflow.remove([d for d in workflow.doers if d is not task])
            return True

        registries = {}
        task = doing.doify(run)
        workflow = doing.DoDoer(
            doers=[
                *witness_doers,
                *(d for r in resolvers for d in r.doers),
                *(d for i in issuers.values() for d in (i.registrar, i)),
                IssuerEscrows(list(issuers.values())),
                http.ServerDoer(
                    server=http.Server(
                        host="127.0.0.1", port=hook_port, app=hook_app
                    )
                ),
                runtime,
                task,
            ]
        )
        doing.Doist(real=True, tock=0.01, limit=90).do(doers=[workflow])
        assert finished, "upstream revocation workflow timed out"
