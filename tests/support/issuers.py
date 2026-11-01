"""support/issuers.py."""

from eth_account import Account
from eth_account.messages import encode_typed_data
from keri import core
from keri.core import coring

from eoa_verifier.verification.eoa import build_challenge
from scripts.integration.issuers import association_from_challenge

KEY = "0x" + "0" * 63 + "1"


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


def signed_notice(runtime, sender, embedded, attachments=b""):
    """Deliver an actual signed opening Grant through KERIpy EXN authentication."""
    from keri.core import coring, parsing, serdering
    from keri.peer import exchanging
    from keri.vc import protocoling

    exn, _ = exchanging.exchange(
        route="/ipex/grant",
        sender=sender.pre,
        recipient=runtime.hab.pre,
        payload={"m": "intake regression"},
    )
    sad = dict(exn.sad)
    sad["e"] = coring.Saider.saidify(sad={"d": "", "acdc": embedded})[1]
    exn = serdering.SerderKERI(sad=sad, makify=True)
    stream = sender.endorse(exn, last=False, pipelined=False)
    if attachments:
        from keri import core, kering

        pathed = coring.Pather(path=["e", "acdc"]).qb64b + attachments
        stream += (
            core.Counter(
                core.Codens.PathedMaterialGroup,
                count=len(pathed) // 4,
                gvrsn=kering.Vrsn_1_0,
            ).qb64b
            + pathed
        )
    exc = exchanging.Exchanger(hby=runtime.hby, handlers=[])
    protocoling.loadHandlers(hby=runtime.hby, exc=exc, notifier=runtime.notifier)
    runtime.hby.psr.parse(ims=bytearray(sender.makeOwnEvent(sn=0)))
    parsing.Parser(kvy=runtime.hby.kvy, exc=exc).parse(ims=bytearray(stream))
    assert any(n.attrs["d"] == exn.said for n, _ in runtime.notifier.noter.getNotes())
    return exn.said
