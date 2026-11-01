"""Persistent witnessed issuer ceremonies used by the Verifier fixture CLI.

One command borrows GEDA, delegated QVI and LE stores, advances one native
ceremony, exports public evidence, then closes those stores. Witnesses and the
Verifier are separate processes. No application acceptance records are written.
"""

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Generator

from eth_account import Account
from eth_account.messages import encode_typed_data
from hio.base import doing
from keri.app import httping, oobiing
from keri.core import coring, scheming, serdering
from keri.db import basing
from keri.help import helping

from eoa_verifier.verification.constants import LE_SCHEMA, QVI_SCHEMA
from eoa_verifier.verification.eoa import build_challenge, verify_eoa_proof

from .artifacts import load_json, save_json
from .issuers import (
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


@dataclass
class IssuerCeremony:
    """Borrow native actors and scheduler tasks for one sequential ceremony.

    root owns only fixture artifacts. actors/issuers own native KERI state through
    the surrounding context, and schemas are the installed Verifier resources.
    """

    root: Path
    configuration: dict
    actors: dict
    issuers: dict
    schemas: dict
    resolvers: list
    witness_oobi: str

    @property
    def tasks(self) -> list:
        """Return the native tasks required while advancing an issuer operation."""
        return [
            *(task for resolver in self.resolvers for task in resolver.doers),
            *(
                task
                for issuer in self.issuers.values()
                for task in (issuer.registrar, issuer)
            ),
            IssuerEscrows(list(self.issuers.values())),
        ]

    def bootstrap_sources(self) -> Generator:
        """Issue and retain the witnessed GEDA -> QVI -> LE credential chain.

        This operation requires fresh actor registries. Return public chain facts
        only after delegation, registry anchors and both credentials are accepted.
        """
        yield from self._resolve_witness()
        yield from approve_qvi(self.actors, self.issuers)
        registries = yield from self._create_registries()
        credentials, streams = {}, {}
        for issuer_name, holder_name, schema_said in (
            ("geda", "qvi", QVI_SCHEMA),
            ("qvi", "le", LE_SCHEMA),
        ):
            source = (
                self._qvi_edge(credentials["geda"].said)
                if issuer_name == "qvi"
                else None
            )
            holder_hby, holder, holder_rgy = self.actors[holder_name]
            issuer = self.issuers[issuer_name]
            credential = issuer.create(
                regname=issuer_name,
                recp=holder.pre,
                schema=schema_said,
                source=source,
                rules=rules(self.schemas[schema_said]),
                data={"LEI": "5493001KJTIIGC8Y1R12"},
            )
            yield from issue_credential(issuer, registries[issuer_name], credential)
            credentials[issuer_name] = credential
            registry = registries[issuer_name]
            streams[issuer_name] = replay(
                registry.hab, issuer.rgy, registry, credential
            )
            sourceCesr = streams["geda"] + (
                streams["qvi"] if issuer_name == "qvi" else b""
            )
            receive(holder_hby, holder_rgy, sourceCesr)
            if not holder_rgy.reger.saved.get(keys=(credential.said,)):
                raise RuntimeError(
                    f"{holder_name} did not accept its source credential"
                )

        chain = {
            "gedaAid": self.actors["geda"][1].pre,
            "issuerAid": self.actors["le"][1].pre,
            "leSaid": credentials["qvi"].said,
            "registry": registries["le"].regk,
        }
        (self.root / "chain.cesr").write_bytes(streams["geda"] + streams["qvi"])
        save_json(self.root / "chain.json", chain)
        return chain

    def issue_association(self, wallet_key: str, nonce: str) -> Generator:
        """Sign and issue one association, returning its public descriptor.

        wallet_key is a local fixture key; nonce is passed unchanged to the owned
        proof implementation. A valid reused nonce is allowed at issuance so the
        Verifier can exercise its own acceptance policy.
        """
        chain, _registry = self._association_context()
        challenge = build_challenge(
            issuer_aid=chain["issuerAid"],
            le_vlei_said=chain["leSaid"],
            ext_id=f"eip155:{self.configuration['chainId']}:{Account.from_key(wallet_key).address.lower()}",
            nonce=nonce,
        )
        signature = Account.sign_message(
            encode_typed_data(full_message=challenge), wallet_key
        ).signature
        return (
            yield from self.issue_signed_association(challenge, "0x" + signature.hex())
        )

    def issue_signed_association(self, challenge: dict, signature: str) -> Generator:
        """Verify an externally signed challenge, then issue/anchor/export its association.

        The issuer and LE source must match this run's real holder; the wallet
        proof and configured chain must match before any TEL issuance is started.
        Nonce reuse remains Verifier acceptance policy, not an issuer ledger.
        """
        chain, registry = self._association_context()
        message = challenge["message"]
        if (
            message["issuerAid"] != chain["issuerAid"]
            or message["leVleiSaid"] != chain["leSaid"]
            or challenge["domain"]["chainId"] != str(self.configuration["chainId"])
        ):
            raise ValueError(
                "Challenge does not belong to this LE holder and local chain"
            )
        credential = association_from_challenge(challenge, signature, registry.regk)
        verify_eoa_proof(credential.sad)
        yield from issue_credential(self.issuers["le"], registry, credential)
        (self.root / "credentials" / f"{credential.said}.json").write_bytes(
            credential.raw
        )
        return self._export_association(credential, registry)

    def revoke_association(self, said: str) -> Generator:
        """Witness revocation of a previously exported SAID and refresh its evidence."""
        _, registry = self._association_context()
        credential = serdering.SerderACDC(
            raw=(self.root / "credentials" / f"{said}.json").read_bytes()
        )
        yield from revoke_credential(self.issuers["le"], registry, credential)
        return self._export_association(credential, registry)

    def _association_context(self):
        """Read the completed chain and its native LE registry without creating one."""
        chain = load_json(self.root / "chain.json")
        return chain, self.actors["le"][2].regs[chain["registry"]]

    def _export_association(self, credential, registry) -> dict:
        """Export exact KEL/TEL/Grant bytes addressed to the prepared Verifier AID."""
        _, le, rgy = self.actors["le"]
        presentationCesr = replay(le, rgy, registry, credential) + grant(
            le, rgy, credential, self.configuration["verifierAid"]
        )
        (self.root / "credentials" / f"{credential.said}.cesr").write_bytes(
            presentationCesr
        )
        return {
            "said": credential.said,
            "issuerAid": le.pre,
            "wallet": credential.sad["a"]["extId"].split(":")[2],
            "nonce": credential.sad["u"],
        }

    def _resolve_witness(self) -> Generator:
        """Wait for each actor's actual native OOBI acceptance before issuing."""
        for hby, _, _ in self.actors.values():
            while hby.db.roobi.get(keys=(self.witness_oobi,)) is None:
                yield 0.01
            if (
                hby.db.roobi.get(keys=(self.witness_oobi,)).state
                != oobiing.Result.resolved
            ):
                raise RuntimeError("Witness OOBI did not resolve")

    def _create_registries(self) -> Generator:
        """Create each actor's no-backer registry and wait for witnessed anchors."""
        registries = {}
        for name, (_, hab, rgy) in self.actors.items():
            registry = rgy.makeRegistry(name=name, prefix=hab.pre, noBackers=True)
            self.issuers[name].registrar.incept(registry.vcp, anchor(hab, registry.vcp))
            while not self.issuers[name].registrar.complete(registry.regk):
                yield 0.01
            registries[name] = registry
        return registries

    @staticmethod
    def _qvi_edge(qvi_said: str) -> dict:
        """Build the source edge for the LE credential using the owned QVI schema."""
        return coring.Saider.saidify(
            sad={"d": "", "qvi": {"n": qvi_said, "s": QVI_SCHEMA}}
        )[1]


@contextmanager
def open_ceremony(root: Path):
    """Own native actor stores; yield a ceremony borrowing their HIO tasks.

    root must be a prepared fixture run with a running witness. All stores close
    before returning to the caller, including when a native operation fails.
    """
    configuration = load_json(root / "run.json")
    schemas = [
        scheming.Schemer(raw=p.read_bytes())
        for p in files("eoa_verifier.verification").joinpath("schema_data").iterdir()
    ]
    witness = configuration["witnesses"][0]
    oobi = f"{witness['url']}/oobi/{witness['aid']}/controller"
    with ExitStack() as stack:
        from types import SimpleNamespace

        actors, issuers = open_issuers(
            stack,
            schemas,
            base="",
            temp=False,
            witness=SimpleNamespace(pre=witness["aid"]),
            head_dir=str(root / "issuers"),
        )
        resolvers = []
        for hby, _, _ in actors.values():
            if hby.db.roobi.get(keys=(oobi,)) is None:
                hby.db.oobis.pin(
                    keys=(oobi,), val=basing.OobiRecord(date=helping.nowIso8601())
                )
            resolvers.append(oobiing.Oobiery(hby=hby, clienter=httping.Clienter()))
        yield IssuerCeremony(
            root,
            configuration,
            actors,
            issuers,
            {schema.said: schema for schema in schemas},
            resolvers,
            oobi,
        )


def complete_ceremony(ceremony: IssuerCeremony, ceremonyGen: Generator) -> dict:
    """Drive one borrowed ceremony generator for at most 90 seconds and return its result.

    Scheduler shutdown precedes the caller closing the ceremony's native stores.
    No domain branching or state mutation is hidden inside this scheduler adapter.
    """
    results = []

    def advance(tymth, tock=0.0, **kwargs):
        """Bridge a native generator result to the owning HIO scheduler."""
        yield tock
        try:
            results.append((yield from ceremonyGen))
        finally:
            scheduler.remove(list(scheduler.doers[:-1]))

    scheduler = doing.DoDoer(doers=[*ceremony.tasks, doing.doify(advance)])
    doing.Doist(real=True, tock=0.01, limit=90).do(doers=[scheduler])
    if not results:
        raise TimeoutError(
            "Witnessed issuer ceremony did not complete within 90 seconds"
        )
    return results[0]
