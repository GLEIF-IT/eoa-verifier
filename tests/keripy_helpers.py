"""Test-side issuer setup and KERIpy KLI artifact workflows.

The verifier library receives and verifies; these helpers own test controllers,
credential issuance setup, and supporting evidence transport.
"""

from contextlib import contextmanager
import socket

from eth_account import Account
from eth_account.messages import encode_typed_data
from keri import core
from hio.base import doing
from keri.app import habbing, signing
from keri.core import coring, eventing, parsing, serdering
from keri.db import dbing
from keri.kering import Protocols, versify
from keri.vc import protocoling
from keri.vdr import credentialing, verifying

from eoa_verifier.verification.constants import ASSOCIATION_SCHEMA, LE_SCHEMA
from eoa_verifier.verification.eoa import DOMAIN_TAG, PROOF_ALGORITHM, build_challenge


# Public deterministic test signing key; never a production secret.
KEY = "0x" + "0" * 63 + "1"


def free_port():
    """Return an available loopback port, releasing the probe socket; the caller must bind it promptly."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def candidate():
    """Return a signed, SAID-valid test ACDC dict without KERIpy issuance or acceptance evidence."""
    said = coring.Diger(ser=b"test").qb64
    challenge = build_challenge(
        issuer_aid=core.Signer().verfer.qb64,
        le_vlei_said=said,
        ext_id=f"eip155:31337:{Account.from_key(KEY).address.lower()}",
        nonce="test-account",
    )
    sig = Account.sign_message(encode_typed_data(full_message=challenge), KEY).signature
    return association_from_challenge(challenge, "0x" + sig.hex(), said).sad


def anchor(hab, event) -> serdering.SerderKERI:
    """Append a signed TEL seal to hab’s KEL and return its KERIpy interaction Serder."""
    message = hab.interact(
        data=[eventing.SealEvent(event.pre, event.snh, event.said)._asdict()]
    )
    return serdering.SerderKERI(raw=message)


def replay(hab, rgy, registry, creder) -> bytes:
    """Return issuer KEL, registry/credential TEL and accepted ACDC bytes from KERIpy stores.

    The caller supplies an issued credential and its registry. Prepend upstream
    streams when the receiver also needs LE/QVI evidence; this helper does no network I/O.
    """
    return b"".join(
        [
            *hab.db.clonePreIter(pre=hab.pre),
            *rgy.reger.clonePreIter(pre=registry.regk),
            *rgy.reger.clonePreIter(pre=creder.said),
            signing.serialize(*rgy.reger.cloneCred(creder.said)),
        ]
    )


def issue_credential(issuer, registry, creder):
    """Schedule KERIpy TEL/KEL issuance for creder in registry using the supplied Credentialer.

    Yield 0.01 HIO seconds until completion, then return None. The caller must run
    Registrar, Credentialer and escrow Doers and own their stores.
    """
    issuance = registry.issue(said=creder.said, dt=creder.attrib.get("dt"))
    anc = anchor(registry.hab, issuance)
    issuer.issue(creder, issuance)
    issuer.registrar.issue(creder, issuance, anc)
    while not issuer.complete(creder.said):
        yield 0.01


def revoke_credential(issuer, registry, creder):
    """Anchor verified revocation and schedule it on the supplied issuer's Registrar.

    Yield 0.01 HIO seconds until witnessed completion, then return None. The caller
    owns scheduling and later transports the resulting TEL/KEL evidence.
    """
    revocation = registry.revoke(said=creder.said)
    issuer.registrar.revoke(creder, revocation, anchor(registry.hab, revocation))
    while not issuer.registrar.complete(creder.said, sn=revocation.sn):
        yield 0.01


def receive(hby, rgy, stream) -> None:
    """Give an issuer supporting KERI evidence through the standard parser.

    QVI and LE use this local delivery before issuing their own credentials.
    Verifier delivery is tested separately through HTTP. Acceptance is established
    by KERIpy's verifier, including its normal escrow processing.
    """
    verifier = verifying.Verifier(hby=hby, reger=rgy.reger)
    parsing.Parser().parse(
        ims=bytearray(stream),
        kvy=eventing.Kevery(db=hby.db, lax=False, local=False),
        tvy=verifier.tvy,
        vry=verifier,
    )
    verifier.processEscrows()


def rules(schema) -> dict:
    """Return a SAID-bearing rules dict with the exact disclaimers required by the supplied credential schema."""
    fields = schema.sed["properties"]["r"]["oneOf"][1]["properties"]
    return coring.Saider.saidify(
        sad={
            "d": "",
            **{
                name: {"l": fields[name]["properties"]["l"]["const"]}
                for name in ("usageDisclaimer", "issuanceDisclaimer")
            },
        }
    )[1]


def grant(
    hab,
    rgy,
    creder,
    recipient,
    *,
    acdc=None,
) -> bytes:
    """Return IPEX Grant bytes addressed to recipient from the supplied issuer stores.

    Use the issued creder plus KERIpy issuance/anchor embeds; acdc can override
    serialized credential bytes. Source
    credentials travel separately so tests can withhold them. This builds, not sends.
    """
    acdc = (
        signing.serialize(*rgy.reger.cloneCred(creder.said)) if acdc is None else acdc
    )
    iss = rgy.reger.cloneTvtAt(creder.said)
    issuance = serdering.SerderKERI(raw=iss)
    sealing_event = hab.db.fetchLastSealingEventByEventSeal(
        hab.pre,
        seal={"i": issuance.pre, "s": issuance.snh, "d": issuance.said},
    )
    anc = hab.db.cloneEvtMsg(pre=hab.pre, fn=0, dig=sealing_event.said)
    exn, attachments = protocoling.ipexGrantExn(
        hab=hab,
        recp=recipient,
        message="External association",
        acdc=acdc,
        iss=iss,
        anc=anc,
    )
    return exn.raw + attachments


class IssuerEscrows(doing.Doer):
    """Process each issuer's registry and credential escrows on the HIO clock.

    The KLI normally performs this alongside its mailbox processing. Local
    issuer-to-holder delivery here has no mailbox; Registrar and Credentialer
    still run as their own HIO doers.
    """

    def __init__(self, issuers):
        """Borrow issuer runtimes in issuers and recur every 0.03125 HIO seconds; do not own their stores."""
        self.issuers = issuers
        super().__init__(tock=0.03125)

    def recur(self, tyme):
        """Process borrowed registry/verifier escrows once and return False to remain scheduled."""
        for issuer in self.issuers:
            issuer.rgy.processEscrows()
            issuer.verifier.processEscrows()
        return False


def issuer_for(hby, rgy):
    """Return a KERIpy Credentialer with Registrar and Verifier borrowing the supplied Habery/Regery."""
    registrar = credentialing.Registrar(hby=hby, rgy=rgy, counselor=None)
    return credentialing.Credentialer(
        hby=hby,
        rgy=rgy,
        registrar=registrar,
        verifier=verifying.Verifier(hby=hby, reger=rgy.reger),
    )


def open_issuers(stack, schemas, *, base, temp, witness):
    """Return actor and issuer dictionaries for isolated witnessed GEDA/QVI/LE controllers.

    Pin supplied credential schemas and configure QVI delegation to GEDA. stack owns store closure;
    temp selects disposable stores, base selects their namespace, witness supplies
    the witness AID. The caller must schedule the returned KERIpy issuance tasks.
    """
    actors, issuers = {}, {}
    for name in ("geda", "qvi", "le"):
        hby = stack.enter_context(habbing.openHby(name=name, base=base, temp=temp))
        for schema in schemas:
            hby.db.schema.pin(keys=(schema.said,), val=schema)
        hab = hby.makeHab(
            name=name,
            icount=1,
            isith="1",
            ncount=1,
            nsith="1",
            wits=[witness.pre],
            toad=1,
            **({"delpre": actors["geda"][1].pre} if name == "qvi" else {}),
        )
        rgy = credentialing.Regery(hby=hby, name=name, base=base, temp=temp)
        stack.callback(rgy.reger.close, clear=temp)
        actors[name] = (hby, hab, rgy)
        # Single-sig needs no multisig Counselor; retain the KLI lifecycle doers.
        issuers[name] = issuer_for(hby, rgy)
    return actors, issuers


def collect_receipts(issuer, hab, sn):
    """Queue hab/sn on the issuer’s KERIpy receipt worker; yield until its completion cue, then return None."""
    receiptor = issuer.registrar.receiptor
    receiptor.msgs.append({"pre": hab.pre, "sn": sn})
    while not any(cue["pre"] == hab.pre and cue["sn"] == sn for cue in receiptor.cues):
        yield 0.01


def approve_qvi(actors, issuers):
    """Yield through real witnessed QVI delegation approval among the supplied actors.

    Use the KLI authorizer seal and replay accepted evidence to issuer stores.
    Return None after GEDA accepts the delegation; the caller owns actor scheduling.
    """
    geda_hby, geda, _geda_rgy = actors["geda"]
    qvi_hby, qvi, qvi_rgy = actors["qvi"]
    _le_hby, le, _le_rgy = actors["le"]
    # Introduce the non-delegated inception events before GEDA's approval.
    yield from collect_receipts(issuers["geda"], geda, 0)
    yield from collect_receipts(issuers["le"], le, 0)
    inception = serdering.SerderKERI(raw=qvi.makeOwnEvent(sn=0))
    geda.interact(data=[eventing.SealEvent(qvi.pre, "0", inception.said)._asdict()])
    couple = coring.Seqner(sn=geda.kever.sn).qb64b + geda.kever.serder.saidb
    for hby in (geda_hby, qvi_hby):
        hby.db.setAes(dbing.dgKey(qvi.pre, inception.said), couple)
    yield from collect_receipts(issuers["geda"], geda, geda.kever.sn)
    receive(qvi_hby, qvi_rgy, b"".join(geda.db.clonePreIter(pre=geda.pre)))
    # The receipt worker sends cloneDelegation context before the delegated event.
    yield from collect_receipts(issuers["qvi"], qvi, 0)
    geda_hby.psr.parse(ims=bytearray(b"".join(qvi.db.clonePreIter(pre=qvi.pre))))
    geda_hby.kvy.processEscrowDelegables()
    receive(qvi_hby, qvi_rgy, b"".join(le.db.clonePreIter(pre=le.pre)))
    assert qvi.pre in geda_hby.kevers, "GEDA has not accepted QVI delegation"


def association_from_challenge(challenge, signature, registry):
    """Return a SAID-bearing association ACDC for typed challenge, signature and registry.

    Require the exact EOA challenge shape and canonical registry SAID, raising
    ValueError on mismatch. Build nested proof/attribute/LE-edge SAIDs but do not
    verify the wallet signature, issue the credential or establish KERIpy credential acceptance.
    """
    fields = challenge["message"]
    expected = build_challenge(
        issuer_aid=fields["issuerAid"],
        le_vlei_said=fields["leVleiSaid"],
        ext_id=fields["extId"],
        nonce=fields["nonce"],
    )
    if challenge != expected:
        raise ValueError("challenge does not match the EOA profile")
    if coring.Saider(qb64=registry).qb64 != registry:
        raise ValueError("registry must be a canonical KERI SAID")
    proof = coring.Saider.saidify(
        sad={
            "d": "",
            "alg": PROOF_ALGORITHM,
            "tag": DOMAIN_TAG,
            "sig": signature,
        }
    )[1]
    attributes = coring.Saider.saidify(
        sad={
            "d": "",
            "extId": fields["extId"],
            "proof": proof,
        }
    )[1]
    edge = coring.Saider.saidify(
        sad={
            "d": "",
            "le": {"n": fields["leVleiSaid"], "s": LE_SCHEMA, "o": "I2I"},
        }
    )[1]
    return serdering.SerderACDC(
        sad={
            "v": versify(protocol=Protocols.acdc, size=0),
            "d": "",
            "u": fields["nonce"],
            "i": fields["issuerAid"],
            "ri": registry,
            "s": ASSOCIATION_SCHEMA,
            "a": attributes,
            "e": edge,
        },
        makify=True,
    )


@contextmanager
def verifier_service(config):
    """Yield a service borrowing KERIpy stores owned by this fixture.

    The caller must stop its HIO scheduler before leaving this context. Use
    entered_service to enter and exit HIO tasks without advancing scheduler turns. Persistent
    configs retain files for reopening assertions; temporary configs remove them.
    """
    from keri.app import keeping, configing, notifying
    from keri.db import basing, dbing
    from keri.vdr import viring, credentialing
    from eoa_verifier.basing import VerifierBaser
    from eoa_verifier.serving import VerifierService

    options = dict(name=config.name, base=config.base, headDirPath=config.head_dir)
    with (
        keeping.openKS(temp=config.temp, **options) as ks,
        basing.openDB(temp=config.temp, **options) as db,
        configing.openCF(temp=config.temp, **options) as cf,
        viring.openReger(temp=config.temp, db=db, **options) as reger,
        dbing.openLMDB(cls=VerifierBaser, temp=config.temp, **options) as baser,
        dbing.openLMDB(cls=notifying.Noter, temp=config.temp, **options) as noter,
    ):
        hby = habbing.Habery(
            name=config.name,
            base=config.base,
            temp=config.temp,
            ks=ks,
            db=db,
            cf=cf,
            bran=config.passcode,
            free=False,
        )
        rgy = credentialing.Regery(
            hby=hby, name=config.name, base=config.base, temp=config.temp, reger=reger
        )
        service = VerifierService(config, hby=hby, rgy=rgy, baser=baser, noter=noter)
        yield service


@contextmanager
def entered_service(config):
    """Yield an entered service, then stop its tasks before closing borrowed stores.

    This fixture does not advance the scheduler. Tests call the relevant boundary
    directly or supply their own scheduling loop when they need task progress.
    """
    with verifier_service(config) as runtime:
        scheduler = doing.Doist(doers=[runtime])
        try:
            scheduler.enter()
            yield runtime
        finally:
            scheduler.exit()
