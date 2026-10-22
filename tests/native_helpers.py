"""Test-side issuer setup and native KLI artifact workflows.

The verifier library receives and verifies; these helpers own test controllers,
credential issuance setup, and supporting evidence transport.
"""

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


KEY = "0x" + "0" * 63 + "1"  # Public Anvil test account only.


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def candidate():
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
    """Seal a TEL event in a signed interaction, as the single-sig KLI does."""
    message = hab.interact(
        data=[eventing.SealEvent(event.pre, event.snh, event.said)._asdict()]
    )
    return serdering.SerderKERI(raw=message)


def replay(hab, rgy, registry, creder) -> bytes:
    """Export issuer KEL, registry TEL, credential TEL, and accepted ACDC bytes.

    Uses the same replay and serialization APIs as KLI artifact delivery.
    Callers prepend upstream streams when the receiver needs the source chain.
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
    """Schedule native TEL/KEL issuance and wait for Credentialer completion."""
    issuance = registry.issue(said=creder.said, dt=creder.attrib.get("dt"))
    anc = anchor(registry.hab, issuance)
    issuer.issue(creder, issuance)
    issuer.registrar.issue(creder, issuance, anc)
    while not issuer.complete(creder.said):
        yield 0.01


def revoke_credential(issuer, registry, creder):
    """Anchor native revocation and wait for witnessed Registrar completion."""
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
    """SAIDify the exact disclaimer text required by the published vLEI schema."""
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
    include_issuance=True,
    include_anchor=True,
    acdc=None,
) -> bytes:
    """Create the ACDC, issuance, and anchor embeds used by ``kli ipex grant``.

    Source credentials travel separately, allowing a complete Grant to arrive
    before the evidence needed to verify its LE edge.
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
        iss=iss if include_issuance else None,
        anc=anc if include_anchor else None,
    )
    return exn.raw + attachments


class IssuerEscrows(doing.Doer):
    """Process each issuer's registry and credential escrows on the HIO clock.

    The KLI normally performs this alongside its mailbox processing. Local
    issuer-to-holder delivery here has no mailbox; Registrar and Credentialer
    still run as their own native HIO doers.
    """

    def __init__(self, issuers):
        self.issuers = issuers
        super().__init__(tock=0.03125)

    def recur(self, tyme):
        """Advance evidence acceptance without blocking another actor's doers."""
        for issuer in self.issuers:
            issuer.rgy.processEscrows()
            issuer.verifier.processEscrows()
        return False


def issuer_for(hby, rgy):
    """Compose the native single-sig issuance runtime for one controller store."""
    registrar = credentialing.Registrar(hby=hby, rgy=rgy, counselor=None)
    return credentialing.Credentialer(
        hby=hby,
        rgy=rgy,
        registrar=registrar,
        verifier=verifying.Verifier(hby=hby, reger=rgy.reger),
    )


def open_issuers(stack, schemas, *, base, temp, witness):
    """Open isolated, witnessed GEDA/QVI/LE stores and native issuance doers."""
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
    """Yield while the native Registrar's receipt worker contacts the witness."""
    receiptor = issuer.registrar.receiptor
    receiptor.msgs.append({"pre": hab.pre, "sn": sn})
    while not any(cue["pre"] == hab.pre and cue["sn"] == sn for cue in receiptor.cues):
        yield 0.01


def approve_qvi(actors, issuers):
    """Schedule witnessed delegation approval using the KLI authorizer seal."""
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
    """Assemble schema-specific blocks with native KERIpy SAID/ACDC APIs."""
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
