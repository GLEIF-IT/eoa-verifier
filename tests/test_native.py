"""Real witnessed KERI/IPEX verification with isolated stores and local Anvil."""

import shutil
import subprocess
from contextlib import ExitStack
from importlib.resources import files
from uuid import uuid4

from eth_account import Account
from eth_account.messages import encode_typed_data
from hio.base import doing
from hio.core import http
from keri.app import habbing, httping, indirecting, oobiing, signing
from keri.core import coring, scheming
from keri.db import basing
from keri.help import helping
from native_helpers import (
    KEY,
    free_port,
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

from eoa_verifier.serving import ServiceConfig, setup_service
from eoa_verifier.verification.constants import LE_SCHEMA, QVI_SCHEMA
from eoa_verifier.verification.eoa import build_challenge


def test_native_grant_verification_and_restart(tmp_path):
    """Exercise real witnessed GEDA/QVI/LE issuance, IPEX HTTP delivery and local Anvil.

    Own isolated native stores/processes with ExitStack and all network tasks with
    HIO. Missing Anvil fails rather than skips. Test delayed evidence across restart,
    duplicate delivery, revocation during initial RPC, and invalid proof/relationships.
    """
    anvil_path = shutil.which("anvil")
    assert anvil_path, "Anvil is required for native integration; install Foundry"
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
        )
        runtime = setup_service(config)
        stack.callback(runtime.close)
        client = http.Client(hostname="127.0.0.1", port=port)
        client_doer = http.ClientDoer(client=client)
        doers = [
            *witness_doers,
            *(d for r in resolvers for d in r.doers),
            *(d for i in issuers.values() for d in (i.registrar, i)),
            IssuerEscrows(list(issuers.values())),
            *runtime.doers,
            client_doer,
        ]
        finished = []

        def send(stream):
            """Yield while sending CESR bytes through the owned HTTP client; assert each transport ACK, return None."""
            count = httping.streamCESRRequests(
                client, bytearray(stream), runtime.hab.pre
            )
            for _ in range(count):
                while not client.responses:
                    yield 0.01
                assert client.responses.popleft()["status"] in (200, 202, 204)

        def deliver(stream, said, expected):
            """Yield through HTTP delivery and wait up to ten HIO seconds for the expected durable row; return it."""
            yield from send(stream)
            deadline = workflow.tyme + 10
            while True:
                store = (
                    runtime.baser.pending
                    if expected == "awaiting_artifacts"
                    else runtime.baser.results
                )
                work = store.get(keys=(said,))
                if work is not None and (
                    expected == "awaiting_artifacts" or work.outcome == expected
                ):
                    return work
                assert workflow.tyme < deadline, (expected, work)
                yield 0.01

        def issue_association(label, *, signer=KEY, chain=31337, holder=None):
            """Yield through witnessed issuance and return (ACDC, native evidence/Grant bytes).

            label names the scenario; signer, chain and holder select intentional invalid
            cases. The normal issuer is the LE holder. This constructs genuine signatures
            and anchors even when testing a mismatched holder relationship.
            """
            hab = holder or le
            registry = registries["qvi" if holder else "le"]
            challenge = build_challenge(
                issuer_aid=hab.pre,
                le_vlei_said=credentials["qvi"].said,
                ext_id=f"eip155:{chain}:{Account.from_key(KEY).address.lower()}",
                nonce=str(uuid4()),
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
            evidence = b"".join(hab.db.clonePreIter(pre=hab.pre))
            evidence += b"".join(rgy.reger.clonePreIter(pre=registry.regk))
            evidence += grant(hab, rgy, creder, runtime.hab.pre, acdc=acdc)
            return creder, evidence

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
            creder, evidence = yield from issue_association("delayed")
            yield from deliver(evidence, creder.said, "awaiting_artifacts")
            aid = runtime.hab.pre
            workflow.remove([*runtime.doers, client_doer])
            runtime.close()
            runtime = setup_service(config)
            stack.callback(runtime.close)
            assert runtime.hab.pre == aid
            assert runtime.baser.pending.get(keys=(creder.said,)) is not None
            client = http.Client(hostname="127.0.0.1", port=port)
            client_doer = http.ClientDoer(client=client)
            workflow.extend([*runtime.doers, client_doer])
            # Supporting evidence alone resumes persisted work; no new Grant required.
            yield from deliver(
                streams["geda"] + streams["qvi"], creder.said, "verified"
            )
            assert runtime.rgy.reger.saved.get(keys=(creder.said,))
            # Replaying the same Grant must retain the completed work record.
            original = runtime.baser.results.get(keys=(creder.said,))
            yield from deliver(evidence, creder.said, "verified")
            assert runtime.baser.results.get(keys=(creder.said,)) == original

            # Hold completion after a real RPC observation, then deliver native
            # revocation before applying the result. The final native recheck
            # must prevent initial success without asking RPC a second time.
            from eoa_verifier.verification.coordinating import PresentationVerifierDoer

            coordinator = next(
                d for d in runtime.doers if isinstance(d, PresentationVerifierDoer)
            )
            verifier_loop = next(
                d for d in coordinator.doers if d is not coordinator.eoa_verifier
            )
            coordinator.remove([verifier_loop])
            raced, stream = yield from issue_association("revoked-during-rpc")
            yield from send(stream)
            while runtime.baser.pending.get(keys=(raced.said,)) is None:
                yield 0.01
            while coordinator.inflight != raced.said:
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
            rejected = runtime.baser.results.get(keys=(raced.said,))
            assert rejected.outcome == "rejected" and "revoked" in rejected.reason
            coordinator.extend([verifier_loop])

            for label, options, reason in [
                ("proof", {"signer": "0x" + "0" * 63 + "2"}, "signer"),
                ("chain", {"chain": 31338}, "chain"),
                ("issuer", {"holder": qvi}, "issuer does not match"),
            ]:
                candidate, stream = yield from issue_association(label, **options)
                work = yield from deliver(stream, candidate.said, "rejected")
                assert reason in work.reason, work
            finished.append(True)
            workflow.remove([d for d in workflow.doers if d is not task])
            return True

        registries, credentials, streams = {}, {}, {}
        task = doing.doify(run)
        workflow = doing.DoDoer(doers=[*doers, task])
        doing.Doist(real=True, tock=0.01, limit=60).do(doers=[workflow])
        assert finished, "native workflow timed out"
